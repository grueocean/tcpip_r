use crate::l2_l3::ethernet::get_interface_mac;
use crate::l2_l3::arp::{L2Stack, is_netmask_range, generate_network_addr, generate_broadcast_addr};
use crate::l2_l3::defs::{Ipv4Type, L2Error, L3Error};
use anyhow::{Context, Result};
use log;
use eui48::MacAddress;
use pnet::packet;
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const IPV4_HEADER_LENGTH_BASIC: usize = 20;
const IPV4_MAX_SIZE: usize = 65535;
const IPV4_MIN_MTU: usize = 68;    // rfc791
const IPV4_MIN_MTU_2: usize = 576; // rfc1122, rfc8900
const IPV4_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

// https://datatracker.ietf.org/doc/html/rfc791
//
//Bit 0: reserved, must be zero
//Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
//Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
//
//    0   1   2
//  +---+---+---+
//  |   | D | M |
//  | 0 | F | F |
//  +---+---+---+
//

const IPV4_FLAG_DF: u8 = 0b010;
const IPV4_FLAG_MF: u8 = 0b001;
const IPV4_FLAG_ZERO: u8 = 0b000;

static L3STACK_GLOBAL: OnceLock<Arc<L3Stack>> = OnceLock::new();

pub fn get_global_l3stack(config: NetworkConfiguration) -> Result<&'static Arc<L3Stack>> {
    Ok(L3STACK_GLOBAL.get_or_init(|| L3Stack::new(config).unwrap()))
}

// https://datatracker.ietf.org/doc/html/rfc791
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug)]
pub struct Ipv4Packet {
    pub version: u8,           // 4 bit
    pub ihl: u8,               // 4 bit
    pub type_of_service: u8,
    pub length: u16,
    pub identification: u16,
    pub flags: u8,             // 3 bit
    pub frag_offset: u16,      // 13 bit
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub options: Option<u32>,
    pub payload: Vec<u8>,
    pub valid: bool
}

impl Ipv4Packet {
    pub fn new() -> Self {
        Self {
            version: 0,
            ihl: 0,
            type_of_service: 0,
            length: 0,
            identification: 0,
            flags: 0,
            frag_offset: 0,
            ttl: 0,
            protocol: 0,
            header_checksum: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            options: None,
            payload: Vec::new(),
            valid: false
        }
    }

    pub fn read(&mut self, packet: &Vec<u8>) -> Result<bool> {
        if packet.len() < IPV4_HEADER_LENGTH_BASIC {
            return Err(anyhow::anyhow!("Insufficient packet length for IPv4 Header. packet.len()={}", packet.len()));
        }
        self.version = u8::from_be_bytes(packet[0..1].try_into()?) >> 4;  // top 4 bit
        self.ihl = u8::from_be_bytes(packet[0..1].try_into()?) & 0xf;     // bottom 4 bit
        self.type_of_service = u8::from_be_bytes(packet[1..2].try_into()?);
        self.length = u16::from_be_bytes(packet[2..4].try_into()?);
        self.identification = u16::from_be_bytes(packet[4..6].try_into()?);
        self.flags = (u16::from_be_bytes(packet[6..8].try_into()?) >> 13) as u8;  // top 3 bit
        self.frag_offset = u16::from_be_bytes(packet[6..8].try_into()?) & 0x1fff; // bottom 13 bit
        self.ttl = u8::from_be_bytes(packet[8..9].try_into()?);
        self.protocol = u8::from_be_bytes(packet[9..10].try_into()?);
        self.header_checksum = u16::from_be_bytes(packet[10..12].try_into()?);
        self.src_addr = packet[12..16].try_into()?;
        self.dst_addr = packet[16..20].try_into()?;
        if self.ihl == 5 {  // 20 bytes header w/o option
            self.options = None;
            self.payload = packet[20..].to_vec();
        } else if self.ihl == 6 {  // 24 byte header w/ option
            self.options = Some(u32::from_be_bytes(packet[20..24].try_into()?));
            self.payload = packet[24..].to_vec();
        } else {
            return Err(anyhow::anyhow!("Unsupported Ipv4 Header length. length={}", self.ihl));
        }
        self.validate()?;

        Ok(self.valid)
    }

    fn calc_header_checksum(&self) -> u16 {
        let header = self.create_header();
        let mut checksum_tmp: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            if i + 1 < header.len() {
                let word = u16::from_be_bytes([header[i], header[i+1]]);
                checksum_tmp += u32::from(word);
            }
        }
        checksum_tmp -= self.header_checksum as u32;
        checksum_tmp = (checksum_tmp & 0xffff) + (checksum_tmp >> 16);
        while (checksum_tmp >> 16) > 0 {
            checksum_tmp = (checksum_tmp & 0xffff) + (checksum_tmp >> 16);
        }
        let checksum = !(checksum_tmp as u16);

        checksum
    }

    pub fn calc_header_checksum_and_set(&mut self) {
        self.header_checksum = self.calc_header_checksum();
    }

    pub fn validate(&mut self) -> Result<bool> {
        self.valid = true;
        if self.version != 4 {
            log::debug!("Unexpected ip header. version is {}, but is expected 4.", self.version);
            self.valid = false;
        }
        if self.ihl != 5 && self.ihl != 6 {
            log::debug!("Unexpected ip header. ihl is {}, but is expected 5 or 6.", self.ihl);
            self.valid = false;
        }
        if Ipv4Type::from(self.protocol) == Ipv4Type::Unknown {
            log::debug!("Unexpected ip header. Unknown protocol {}.", self.protocol);
            self.valid = false;
        }
        let expected_checksum = self.calc_header_checksum();
        if self.header_checksum != expected_checksum && self.header_checksum != 0x0 {
            log::debug!("Unexpected ip header. Header checksum is 0x{:x} but is expected 0x{:x}.", self.header_checksum, expected_checksum);
            self.valid = false;
            return Err(anyhow::anyhow!("IP Header has bad checksum 0x{:x}, expected 0x{:x}.", self.header_checksum, expected_checksum));
        }

        Ok(self.valid)
    }

    fn create_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&(self.version << 4 | self.ihl).to_be_bytes());
        header.extend_from_slice(&self.type_of_service.to_be_bytes());
        header.extend_from_slice(&self.length.to_be_bytes());
        header.extend_from_slice(&self.identification.to_be_bytes());
        header.extend_from_slice(&(((self.flags as u16) << 13 | self.frag_offset) as u16).to_be_bytes());
        header.extend_from_slice(&self.ttl.to_be_bytes());
        header.extend_from_slice(&self.protocol.to_be_bytes());
        header.extend_from_slice(&self.header_checksum.to_be_bytes());
        header.extend_from_slice(&self.src_addr);
        header.extend_from_slice(&self.dst_addr);
        if let Some(options) = self.options {
            header.extend_from_slice(&options.to_be_bytes());
        }

        header
    }

    pub fn create_packet(&mut self) -> Result<Vec<u8>> {
        // We don't generate header_cheksum in this method, so caller should have set it.
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        Ok(packet)
    }

    pub fn create_fragment_packets(&self, mtu: usize) -> Result<VecDeque<Self>> {
        anyhow::ensure!((self.flags & IPV4_FLAG_DF) == 0, "Cannot split packet with DF (Don't Fragment) enabled.");
        let mut packets = VecDeque::new();
        let base_packet = self.clone();
        let header_length = (self.ihl * 4) as usize;
        // fragment must be 8-byte alligned
        let max_payload = (
            std::cmp::min(
                mtu - header_length,
                IPV4_MAX_SIZE - header_length
            )
        ) &!0b111;
        let num_fragments = (self.payload.len() - 1) / max_payload + 1;
        if num_fragments == 1 {
            let mut packet_fragment = base_packet.clone();
            packet_fragment.flags = IPV4_FLAG_ZERO;
            packet_fragment.frag_offset = 0;
            packet_fragment.calc_header_checksum_and_set();
            packets.push_back(packet_fragment);
        } else {
            for i in 0..num_fragments {
                let mut packet_fragment = base_packet.clone();
                packet_fragment.frag_offset = (i * max_payload / 8) as u16;
                // not a last fragment
                if i + 1 != num_fragments {
                    packet_fragment.flags = IPV4_FLAG_MF;   // DF=0 MF=1
                    packet_fragment.payload = packet_fragment.payload[i*max_payload..(i+1)*max_payload].to_vec();
                // last fragment
                } else {
                    packet_fragment.flags = IPV4_FLAG_ZERO; // DF=0 MF=0
                    packet_fragment.payload = packet_fragment.payload[i*max_payload..].to_vec();
                }
                packet_fragment.length = (packet_fragment.payload.len() + header_length) as u16;
                packet_fragment.calc_header_checksum_and_set();
                packets.push_back(packet_fragment);
            }
        }

        Ok(packets)
    }
}

trait MatchFragmentHeader {
    fn match_fragment_header(&self, other: &Self) -> bool;
}

impl MatchFragmentHeader for Ipv4Packet {
    fn match_fragment_header(&self, other: &Self) -> bool {
        self.version == other.version &&
        self.ihl == other.ihl &&
        self.type_of_service == other.type_of_service &&
        self.identification == other.identification &&
        self.ttl == other.ttl &&
        self.protocol == other.protocol &&
        self.src_addr == other.src_addr &&
        self.dst_addr == other.dst_addr &&
        self.options == other.options
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4FragmentHole {
    pub start: usize,
    pub end: usize
}

#[derive(Clone, Debug)]
pub struct Ipv4FragmentPiece {
    pub is_hole: bool,
    pub hole: Option<Ipv4FragmentHole>,
    pub packet: Option<Ipv4Packet>
}

#[derive(Debug)]
pub struct Ipv4FragmentQueue {
    timestamp: Instant,
    has_hole: bool,
    queue: VecDeque<Ipv4FragmentPiece>
}

impl Ipv4FragmentQueue {
    pub fn new() -> Self {
        let init_hole = Ipv4FragmentPiece {
            is_hole: true,
            hole: Some(Ipv4FragmentHole { start: 0, end: IPV4_MAX_SIZE }),
            packet: None
        };
        let mut init_queue = VecDeque::new();
        init_queue.push_back(init_hole);
        Self {
            timestamp: Instant::now(),
            has_hole: true,
            queue: init_queue
        }
    }

    pub fn check_is_expired(&self, timeout: Duration) -> bool {
        if self.timestamp.elapsed() >= timeout {
            true
        } else {
            false
        }
    }

    pub fn check_has_hole(&mut self) -> bool {
        let has_hole = self.queue.iter().any(|p| p.is_hole);
        self.has_hole = has_hole;
        return has_hole;
    }

    // based on rfc815, rfc6864
    pub fn push_packet(&mut self, packet: Ipv4Packet) -> bool {
        let mut new_queue = VecDeque::new();
        let frag_start = (packet.frag_offset * 8) as usize;
        let frag_end = (packet.frag_offset * 8) as usize + packet.payload.len() - 1;

        for piece in &self.queue {
            // current piece is hole
            if let Some(hole) = &piece.hole {
                // packet is in the hole
                if hole.start <= frag_start && frag_end <= hole.end {
                    // if a last fragment, insert packet and truncate tail
                    // before:
                    // <--------------hole-------------->
                    // after:
                    // <--hole1--><--packet-->||truncate||
                    if (packet.flags & 0b001) == 0 {
                        if hole.start < frag_start {
                            let hole1 = Ipv4FragmentPiece {
                                is_hole: true,
                                hole: Some(Ipv4FragmentHole { start: hole.start, end: frag_start - 1}),
                                packet: None
                            };
                            new_queue.push_back(hole1);
                        }
                        let new_packet = Ipv4FragmentPiece {
                            is_hole: false,
                            hole: None,
                            packet: Some(packet.clone())
                        };
                        new_queue.push_back(new_packet);
                        break;
                    // if not a last fragment, just insert packet
                    // before:
                    // <--------------hole-------------->
                    // after:
                    // <--hole1--><--packet--><--hole2-->
                    } else {
                        if frag_start != hole.start {
                            // When adding head packet, no hole1 is generated.
                            let hole1 = Ipv4FragmentPiece {
                                is_hole: true,
                                hole: Some(Ipv4FragmentHole { start: hole.start, end: frag_start - 1}),
                                packet: None
                            };
                            new_queue.push_back(hole1);
                        }
                        let new_packet = Ipv4FragmentPiece {
                            is_hole: false,
                            hole: None,
                            packet: Some(packet.clone())
                        };
                        let hole2 = Ipv4FragmentPiece {
                            is_hole: true,
                            hole: Some(Ipv4FragmentHole { start: frag_end + 1, end: hole.end}),
                            packet: None
                        };
                        new_queue.push_back(new_packet);
                        new_queue.push_back(hole2);
                    }
                } else if frag_end <= hole.start || hole.end <= frag_start {
                    log::debug!(
                        "Ignoring a fragmented ipv4 packet suspected of being a duplicate. hole: {}-{} packet: {}-{}",
                        hole.start, hole.end, frag_start, frag_end
                    );
                    new_queue.push_back(piece.clone());
                    continue;
                } else {
                    log::debug!(
                        "Discarding a fragmented ipv4 packet conflicting existing hole. hole: {}-{} packet: {}-{}",
                        hole.start, hole.end, frag_start, frag_end
                    );
                    new_queue.push_back(piece.clone());
                    continue;
                }
            }
            // current piece is packet
            if let Some(p) = &piece.packet {
                let new_piece = Ipv4FragmentPiece {
                    is_hole: false,
                    hole: None,
                    packet: Some(p.clone())
                };
                new_queue.push_back(new_piece);
            }
        }
        self.queue = new_queue;

        !self.check_has_hole()
    }

    pub fn create_complete_packet(&self) -> Result<Ipv4Packet> {
        anyhow::ensure!(!self.has_hole, "Cannot generate complete packet from fragment queue with hole.");
        let mut packets: VecDeque<Ipv4Packet> =
            self.queue.iter()
                .filter_map(|piece| piece.packet.as_ref().cloned())
                .collect();
        let mut payload: Vec<u8> = Vec::new();
        if let Some(mut first_packet) = packets.pop_front() {
            payload.extend_from_slice(&first_packet.payload);
            for packet in packets {
                if first_packet.match_fragment_header(&packet) {
                    payload.extend_from_slice(&packet.payload);
                } else {
                    anyhow::bail!("Fragment queue contains packet with different header value.");
                }
            }
            first_packet.length = payload.len() as u16;
            first_packet.payload = payload;
            first_packet.flags = IPV4_FLAG_ZERO;
            first_packet.frag_offset = 0;
            // No need to re-calc checksum
            first_packet.header_checksum = 0;
            Ok(first_packet)
        } else {
            anyhow::bail!("No packet in the fragment queue.")
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Config {
    pub address: Ipv4Addr,
    pub netmask: usize,
    pub broadcast_address: Ipv4Addr,
    pub network_address: Ipv4Addr
}

impl FromStr for Ipv4Config {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err("Input must be in the format <IPv4Address>/<Netmask>".into());
        }

        let address = parts[0].parse::<Ipv4Addr>().map_err(|_| "Invalid IP address format".to_string())?;
        let netmask = parts[1].parse::<usize>().map_err(|_| "Invalid netmask format".to_string())?;

        if netmask > 32 {
            return Err("Netmask must be between 0 and 32".into());
        }

        let network_address = generate_network_addr(&address, netmask);
        let broadcast_address = generate_broadcast_addr(&address, netmask);

        Ok(Ipv4Config {
            address,
            netmask,
            network_address,
            broadcast_address,
        })
    }
}

#[derive(Debug, Clone, Eq)]
pub struct Ipv4Network {
    pub address: Ipv4Addr,
    pub netmask: usize,
}

impl PartialEq for Ipv4Network {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.netmask == other.netmask
    }
}

impl Hash for Ipv4Network {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.netmask.hash(state);
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfiguration {
    pub interface_name: String,
    pub mac: MacAddress,
    pub mtu: usize,
    pub ip: Ipv4Config,
    pub gateway: HashMap<Ipv4Network, Route>
}

impl NetworkConfiguration {
    pub fn new(
        interface_name: String,
        mac: MacAddress,
        mtu: usize,
        ip: Ipv4Config,
        gateway: HashMap<Ipv4Network, Route>
    ) -> Self {
        Self {
            interface_name,
            mac,
            mtu,
            ip,
            gateway
        }
    }
}

pub fn generate_network_config(
    interface_name: String,
    mac: MacAddress,
    mtu: usize,
    ip: Ipv4Config,
    default_gateway: Ipv4Addr
) -> Result<NetworkConfiguration> {
    let route = vec![
        (Ipv4Network { address: ip.address, netmask: ip.netmask },
        Route { gateway_addr: default_gateway, rank: 1 })
    ];
    let mut config = NetworkConfiguration {
        interface_name: interface_name.clone(), mac, mtu, ip, gateway: route.into_iter().collect()
    };
    if mac == MacAddress::new([0, 0, 0, 0, 0, 0]) {
        if let Some(interface_mac) = get_interface_mac(interface_name)? {
            config.mac = interface_mac;
        }
    }
    Ok(config)
}

#[derive(Clone, Debug)]
pub struct Route {
    pub gateway_addr: Ipv4Addr,
    pub rank: usize
}

fn search_route(routes: &HashMap<Ipv4Network, Route>, target_ip: &Ipv4Addr) -> Option<Route> {
    routes.iter()
        .filter(|(network, _)| is_netmask_range(&network.address, network.netmask, target_ip))
        .max_by_key(|(_, route)| route.rank)
        .map(|(_, route)| route.clone())
}

pub struct L3Interface {
    l2stack: Arc<L2Stack>,
    gateway: HashMap<Ipv4Network, Route>,
    ipv4_identification: Mutex<u16>
}

impl L3Interface {
    pub fn new(
        interface_name: String,
        mac: MacAddress,
        mtu: usize,
        ip: Ipv4Config,
        gateway: HashMap<Ipv4Network, Route>
    ) -> Result<Arc<Self>> {
        if !cfg!(debug_assertions) {
            anyhow::ensure!(mtu >= IPV4_MIN_MTU_2, "Mtu ({}) is less than minimum {}.", mtu, IPV4_MIN_MTU_2);
        }
        let l3 = Arc::new(Self {
            l2stack: L2Stack::new(interface_name, mac, mtu, ip)?,
            gateway: gateway,
            ipv4_identification: Mutex::new(0),
        });

        Ok(l3)
    }

    fn generate_identification(&self) -> u16 {
        let mut id = self.ipv4_identification.lock().unwrap();
        *id = id.wrapping_add(1);

        *id
    }

    fn resolve_ip(&self, ip: &Ipv4Addr) -> Result<Option<MacAddress>> {
        // reject packet to network addr
        if ip == &self.l2stack.interface_ipv4.network_address {
            return Err(anyhow::anyhow!(
                L3Error::AddressError {
                    target_ip: *ip,
                    l2_ip: self.l2stack.interface_ipv4.address,
                    l2_netmask: self.l2stack.interface_ipv4.netmask
                }
            ));
        // set broadcast mac addr if dst is broadcast ip addr
        } else if ip == &self.l2stack.interface_ipv4.broadcast_address {
            return Ok(Some(MacAddress::broadcast()));
        // lookup gateway mac addr if dst is not whitin local network
        } else if !is_netmask_range(
            &self.l2stack.interface_ipv4.address,
            self.l2stack.interface_ipv4.netmask,
            ip
        ) {
            if let Some(gateway) = search_route(&self.gateway, ip) {
                match self.l2stack.lookup_arp(&gateway.gateway_addr) {
                    Ok(mac) => { return Ok(Some(mac)); }
                    Err(e) => {
                        if let Some(L2Error::ResolveError {target_ip: _, retries: _}) = e.downcast_ref::<L2Error>() {
                            log::warn!("Cannot resolve gateway addr {}.", gateway.gateway_addr);
                            return Err(L3Error::GatewayUnreachableError { target_ip: gateway.gateway_addr }.into());
                        } else {
                            return Err(anyhow::anyhow!("Lookup gateway addr {} failed unexpectedly. Err: {}", gateway.gateway_addr, e));
                        }
                    }
                }
            } else {
                return Err(
                    anyhow::anyhow!(
                        "No available gateway. dst ip is {} and l2Stack is {}/{}.",
                        *ip,
                        self.l2stack.interface_ipv4.address,
                        self.l2stack.interface_ipv4.netmask
                    )
                );
            }
        // lookup dst mac addr directly that it is whitin local network
        } else {
            match self.l2stack.lookup_arp(ip) {
                Ok(mac) => { return Ok(Some(mac)); }
                Err(e) => {
                    if let Some(L2Error::ResolveError {target_ip: _, retries: _}) = e.downcast_ref::<L2Error>() {
                        log::warn!("Cannot resolve local addr {}.", ip);
                        return Err(L3Error::LocalUnreachableError { target_ip: *ip }.into());
                    } else {
                        return Err(anyhow::anyhow!("Lookup local addr {} failed unexpectedly. Err: {}", *ip, e));
                    }
                }
            }
        }
    }

    pub fn send(&self, mut ipv4_packet: Ipv4Packet) -> Result<()> {
        // protocol and dst_addr must be set by upper layer.
        ipv4_packet.version = 4;
        ipv4_packet.ihl = 5;
        let header_length = (ipv4_packet.ihl * 4) as usize;
        ipv4_packet.type_of_service = 0;
        ipv4_packet.length = (ipv4_packet.payload.len() + header_length) as u16;
        ipv4_packet.identification = self.generate_identification();
        ipv4_packet.ttl = 0xff;
        ipv4_packet.src_addr = self.l2stack.interface_ipv4.address.octets();
        let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr);
        let dst_mac = self.resolve_ip(&dst_ip)?;
        anyhow::ensure!(ipv4_packet.payload.len() <= IPV4_MAX_SIZE + header_length, "Ipv4 payload is too long ({}).", ipv4_packet.payload.len());
        let packets = ipv4_packet.create_fragment_packets(self.l2stack.interface_mtu)?;
        for fragment in packets {
            self.l2stack.send(fragment, dst_mac)?;
        }
        Ok(())
    }

    pub fn recv(&self) -> Result<Ipv4Packet> {
        loop {
            let mut recv_data = Vec::new();
            match self.l2stack.recv(&mut recv_data) {
                Err(e) => {
                    log::warn!("Failed to recv packet from l2 stack. Err: {}", e);
                    continue;
                }
                Ok(_) => {}
            }
            let mut ipv4_packet = Ipv4Packet::new();
            match ipv4_packet.read(&recv_data) {
                Err(e) => {
                    log::warn!("Reading ipv4 packet failed. Err: {}", e);
                    continue;
                }
                Ok(_) => {}
            }
            let dst_addr = Ipv4Addr::from(ipv4_packet.dst_addr);
            if dst_addr != self.l2stack.interface_ipv4.address &&
               dst_addr != self.l2stack.interface_ipv4.broadcast_address {
                log::warn!(
                    "Discarding packet. Interface ip is {}/{}, but packet dst is to {}.",
                    self.l2stack.interface_ipv4.address,
                    self.l2stack.interface_ipv4.netmask,
                    dst_addr
                );
                continue;
            }

            return Ok(ipv4_packet);
        }
    }
}

pub struct L3Stack {
    pub l3interface: Arc<L3Interface>,
    fragmented_packet_queue: Mutex<HashMap<u16, Ipv4FragmentQueue>>,
    l4_receive_channels: Mutex<HashMap<Ipv4Type, Sender<Ipv4Packet>>>,
    threads: Mutex<Vec<JoinHandle<()>>>
}

impl L3Stack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let l3stack = Arc::new(
            Self {
                l3interface: L3Interface::new(
                    config.interface_name,
                    config.mac,
                    config.mtu,
                    config.ip,
                    config.gateway
                )?,
                fragmented_packet_queue: Mutex::new(HashMap::new()),
                l4_receive_channels: Mutex::new(HashMap::new()),
                threads: Mutex::new(Vec::new())
            }
        );

        let l3stack_recv = l3stack.clone();
        let handle_recv = thread::spawn(move || {
            l3stack_recv.receive_thread().unwrap();
        });
        l3stack.threads.lock().unwrap().push(handle_recv);

        Ok(l3stack)
    }

    pub fn register_protocol(&self, proto: u8, l4_recv_channel: Sender<Ipv4Packet>) -> Result<()> {
        let mut recv_channels = self.l4_receive_channels.lock().unwrap();
        let proto_type = Ipv4Type::from(proto);
        match recv_channels.entry(proto_type) {
            Occupied(_) => { Err(anyhow::anyhow!("Cannot register proto {:?} ({}) to L3Stack because it's already registered.", proto_type, proto)) }
            Vacant(e) => {
                e.insert(l4_recv_channel);
                Ok(())
            }
        }
    }

    fn handle_packet(&self, ipv4_packet: Ipv4Packet) -> Result<()> {
        let proto = Ipv4Type::from(ipv4_packet.protocol);
        let mut channels = self.l4_receive_channels.lock().unwrap();
        // RAW stack using Ipv4Type::Reserved will recieve all protocol packet.
        match channels.entry(Ipv4Type::Reserved) {
            Occupied(e) => {
                match e.get().send(ipv4_packet) {
                    Err(e) => {
                        anyhow::bail!("Failed to transfer packet to RAW stack. Err: {}", e);
                    }
                    Ok(_) => {}
                }
                return Ok(());
            }
            Vacant(_) => {}
        }
        if proto != Ipv4Type::Unknown {
            match channels.entry(proto) {
                Occupied(e) => {
                    match e.get().send(ipv4_packet) {
                        Err(e) => {
                            anyhow::bail!("Failed to transfer packet to {:?} stack. Err: {}", proto, e);
                        }
                        Ok(_) => {}
                    }
                    return Ok(());
                }
                Vacant(_) => {
                    log::trace!("There is no registered L4 stack for the ipv4 packet (proto={:?}).", proto);
                    return Ok(());
                }
            }
        } else {
            // Unkown protocol packet
            return Ok(());
        }
    }

    fn receive_thread(&self) -> Result<()> {
        loop {
            let mut ipv4_packet = Ipv4Packet::new();
            match self.l3interface.recv() {
                Err(e) => {
                    log::warn!("L3Stack failed to recv packet from L3Interface. Err: {}", e);
                }
                Ok(packet) => {
                    ipv4_packet = packet;
                }
            }
            // not a fragmented packet
            if ipv4_packet.frag_offset == 0 && (ipv4_packet.flags & IPV4_FLAG_MF) == 0 {
                if let Err(e) = self.handle_packet(ipv4_packet) {
                    log::warn!("L3Stack failed to handle packet. Err: {}", e);
                }
            // fragmented packet
            } else {
                let mut frag_queue = self.fragmented_packet_queue.lock().unwrap();
                let id = ipv4_packet.identification;
                if let Some(queue) = frag_queue.get_mut(&id) {
                    if queue.check_is_expired(IPV4_FRAGMENT_TIMEOUT) {
                        log::warn!("Ipv4 fragment queue (id={}) is cleared due to timeout ({:?}).", id, IPV4_FRAGMENT_TIMEOUT);
                        frag_queue.remove_entry(&id);
                        continue;
                    }
                    if queue.push_packet(ipv4_packet) {
                        match queue.create_complete_packet() {
                            Ok(packet) => {
                                if let Err(e) = self.handle_packet(packet) {
                                    log::warn!("L3Stack failed to handle packet. Err: {}", e);
                                }
                            }
                            Err(e) => {
                                log::warn!("Creating packet from fragment queue failed. Err: {}", e);
                            }
                        }
                        frag_queue.remove_entry(&id);
                    }
                } else {
                    let mut new_queue = Ipv4FragmentQueue::new();
                    new_queue.push_packet(ipv4_packet);
                    frag_queue.insert(id, new_queue);
                }
            }

        }
    }
}

#[cfg(test)]
mod ipv4_tests {
    use super::*;
    use rstest::rstest;
    use hex::decode;

    #[rstest]
    // normal icmp packet
    #[case(
        "4500005439034000400168d8c0a8c815080808080800dada2062000152f2a862000000003d9a050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        4,      // Version
        5,      // IHL
        0,      // Type of Service
        84,     // Total Length
        0x3903, // Identification
        2,      // Flags
        0,      // Fragment Offset
        64,     // TTL
        1,      // Protocol (ICMP)
        0x68d8, // Header Checksum (calculated value should match this)
        [192, 168, 200, 21],  // Source IP
        [8, 8, 8, 8],         // Destination IP
        None,   // Options
        "0800dada2062000152f2a862000000003d9a050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        true    // Expected validity
    )]
    #[case(
        "4500002e000000004011f96bc0a80001c0a80002abcd",
        4,      // Version
        5,      // IHL
        0,      // Type of Service
        46,     // Total Length
        0,      // Identification
        0,      // Flags
        0,      // Fragment Offset
        64,     // TTL
        17,     // Protocol (UDP)
        0xf96b, // Header Checksum (calculated value should match this)
        [192, 168, 0, 1],  // Source IP
        [192, 168, 0, 2],  // Destination IP
        None,   // Options
        "abcd", // dummy payload
        true    // Expected validity
    )]
    #[case(
        "4600002e000000004006f470c0a80001c0a8000201020304abcd",
        4,      // Version
        6,      // IHL (with options)
        0,      // Type of Service
        46,     // Total Length
        0,      // Identification
        0,      // Flags
        0,      // Fragment Offset
        64,     // TTL
        6,      // Protocol (TCP)
        0xf470, // Header Checksum (calculated value should match this)
        [192, 168, 0, 1],  // Source IP
        [192, 168, 0, 2],  // Destination IP
        Some(0x01020304),  // Options (4 bytes)
        "abcd", // dummy payload
        true    // Expected validity
    )]
    #[case(
        "5500002e000000004011e96bc0a80001c0a80002abcd",
        5,      // Version, which is not ipv4
        5,      // IHL
        0,      // Type of Service
        46,     // Total Length
        0,      // Identification
        0,      // Flags
        0,      // Fragment Offset
        64,     // TTL
        17,     // Protocol (UDP)
        0xe96b, // Header Checksum (calculated value should match this)
        [192, 168, 0, 1],  // Source IP
        [192, 168, 0, 2],  // Destination IP
        None,   // Options
        "abcd", // dummy payload
        false   // Expected validity
    )]
    #[case(
        "5500002e000000004000e97cc0a80001c0a80002abcd",
        5,      // Version, which is not 4
        5,      // IHL
        0,      // Type of Service
        46,     // Total Length
        0,      // Identification
        0,      // Flags
        0,      // Fragment Offset
        64,     // TTL
        0,      // Protocol (Unknown)
        0xe97c, // Header Checksum (calculated value should match this)
        [192, 168, 0, 1],  // Source IP
        [192, 168, 0, 2],  // Destination IP
        None,   // Options
        "abcd", // dummy payload
        false   // Expected validity
    )]
    fn test_ipv4_packet_read(
        #[case] encoded_packet: &str,
        #[case] expected_version: u8,
        #[case] expected_ihl: u8,
        #[case] expected_type_of_service: u8,
        #[case] expected_length: u16,
        #[case] expected_identification: u16,
        #[case] expected_flags: u8,
        #[case] expected_frag_offset: u16,
        #[case] expected_ttl: u8,
        #[case] expected_protocol: u8,
        #[case] expected_header_checksum: u16,
        #[case] expected_src_addr: [u8; 4],
        #[case] expected_dst_addr: [u8; 4],
        #[case] expected_options: Option<u32>,
        #[case] encoded_payload: &str,
        #[case] expected_valid: bool
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let payload = decode(encoded_payload).expect("Failed to decode payload hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        let result = ipv4_packet.read(&packet_data).expect("Failed to read IPv4 packet");
        let recreated_packet = ipv4_packet.create_packet().expect("Failed to recreate packet");

        assert_eq!(ipv4_packet.version, expected_version);
        assert_eq!(ipv4_packet.ihl, expected_ihl);
        assert_eq!(ipv4_packet.type_of_service, expected_type_of_service);
        assert_eq!(ipv4_packet.length, expected_length);
        assert_eq!(ipv4_packet.identification, expected_identification);
        assert_eq!(ipv4_packet.flags, expected_flags);
        assert_eq!(ipv4_packet.frag_offset, expected_frag_offset);
        assert_eq!(ipv4_packet.ttl, expected_ttl);
        assert_eq!(ipv4_packet.protocol, expected_protocol);
        assert_eq!(ipv4_packet.header_checksum, expected_header_checksum);
        assert_eq!(ipv4_packet.src_addr, expected_src_addr);
        assert_eq!(ipv4_packet.dst_addr, expected_dst_addr);
        assert_eq!(ipv4_packet.options, expected_options);
        assert_eq!(ipv4_packet.payload, payload);
        assert_eq!(result, expected_valid);
        assert_eq!(recreated_packet, packet_data, "Recreated packet does not match the original data");
    }

    #[rstest]
    // too short packet
    #[case("45000054390340")]
    // bad ihl (7)
    #[case("4700005439034000400168d9c0a8c815080808080800dada2062000152f2a862000000003d9a050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")]
    // bad checksum (0x68d9)
    #[case("4500005439034000400168d9c0a8c815080808080800dada2062000152f2a862000000003d9a050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")]
    fn test_ipv4_packet_read_error(
        #[case] encoded_packet: &str,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut packet = Ipv4Packet::new();
        let result = packet.read(&packet_data);

        assert!(result.is_err(), "Expected an error for incorrect header");
    }

    #[rstest]
    #[case(
        Ipv4Addr::new(192, 168, 1, 104),
        vec![
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 0), netmask: 24 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 1), rank: 10 }),
            (Ipv4Network { address: Ipv4Addr::new(10, 0, 0, 0), netmask: 8 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 2), rank: 5 }),
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 128), netmask: 25 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 3), rank: 1 }),
            (Ipv4Network { address: Ipv4Addr::new(0, 0, 0, 0), netmask: 0 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 4), rank: 0 })
        ],
        Ipv4Addr::new(192, 168, 1, 1)
    )]
    #[case(
        Ipv4Addr::new(192, 168, 1, 130),
        vec![
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 0), netmask: 24 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 1), rank: 1 }),
            (Ipv4Network { address: Ipv4Addr::new(10, 0, 0, 0), netmask: 8 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 2), rank: 5 }),
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 128), netmask: 25 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 3), rank: 10 }),
            (Ipv4Network { address: Ipv4Addr::new(0, 0, 0, 0), netmask: 0 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 4), rank: 0 })
        ],
        Ipv4Addr::new(192, 168, 1, 3)
    )]
    #[case(
        Ipv4Addr::new(10, 0, 0, 200),
        vec![
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 0), netmask: 24 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 1), rank: 10 }),
            (Ipv4Network { address: Ipv4Addr::new(10, 0, 0, 0), netmask: 8 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 2), rank: 5 }),
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 128), netmask: 25 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 3), rank: 1 }),
            (Ipv4Network { address: Ipv4Addr::new(0, 0, 0, 0), netmask: 0 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 4), rank: 0 })
        ],
        Ipv4Addr::new(192, 168, 1, 2)
    )]
    #[case(
        Ipv4Addr::new(8, 8, 8, 8),
        vec![
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 0), netmask: 24 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 1), rank: 10 }),
            (Ipv4Network { address: Ipv4Addr::new(10, 0, 0, 0), netmask: 8 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 2), rank: 5 }),
            (Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 128), netmask: 25 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 3), rank: 1 }),
            (Ipv4Network { address: Ipv4Addr::new(0, 0, 0, 0), netmask: 0 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 4), rank: 0 })
        ],
        Ipv4Addr::new(192, 168, 1, 4)
    )]
    fn test_search_route(
        #[case] target_ip: Ipv4Addr,
        #[case] routes_data: Vec<(Ipv4Network, Route)>,
        #[case] expected_gateway: Ipv4Addr
    ) {
        let routes: HashMap<Ipv4Network, Route> = routes_data.into_iter().collect();
        let result = search_route(&routes, &target_ip);

        assert!(result.is_some());
        assert_eq!(result.unwrap().gateway_addr, expected_gateway);
    }
}
