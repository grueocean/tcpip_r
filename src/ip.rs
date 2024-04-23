use crate::arp::{L2Stack, is_netmask_range};
use crate::types::{Ipv4Type, L2Error, L3Error};
use anyhow::{Context, Result};
use eui48::MacAddress;
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread::{self, JoinHandle};

const IPv4_HEADER_LENGTH_BASIC: usize = 20;

static L3STACK_GLOBAL: OnceLock<L3Stack> = OnceLock::new();

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
#[derive(Debug)]
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
        if packet.len() < IPv4_HEADER_LENGTH_BASIC {
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
}

pub struct Ipv4Config {
    pub address: Ipv4Addr,
    pub netmask: usize,
    pub broadcast_address: Ipv4Addr,
    pub network_address: Ipv4Addr
}

#[derive(Debug, Clone, Eq)]
pub struct Ipv4Network {
    address: Ipv4Addr,
    netmask: usize,
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

pub struct NetworkConfiguration {
    interface_name: String,
    mac: MacAddress,
    mtu: usize,
    ip: Ipv4Config,
    gateway: HashMap<Ipv4Network, Route>
}

#[derive(Clone)]
pub struct Route {
    gateway_addr: Ipv4Addr,
    rank: usize
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
        ipv4_packet.type_of_service = 0;
        ipv4_packet.length = (ipv4_packet.payload.len() + (ipv4_packet.ihl * 4) as usize) as u16;
        ipv4_packet.identification = self.generate_identification();
        ipv4_packet.flags = 0;
        ipv4_packet.frag_offset = 0;
        ipv4_packet.ttl = 0xff;
        ipv4_packet.src_addr = self.l2stack.interface_ipv4.address.octets();
        let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr);
        let dst_mac = self.resolve_ip(&dst_ip)?;
        ipv4_packet.calc_header_checksum_and_set();
        if ipv4_packet.validate()? {
            self.l2stack.send(ipv4_packet, dst_mac)?;
        } else {
            return Err(anyhow::anyhow!("Failed to send ipv4 packet because it is invalid."));
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
    l3interface: Arc<L3Interface>,
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

    fn receive_thread(&self) -> Result<()> {
        loop {
            let mut ipv4_packet = Ipv4Packet::new();
            match self.l3interface.recv() {
                Err(e) => {
                    log::warn!("Failed to recv packet from L3Interface. Err: {}", e);
                }
                Ok(packet) => {
                    ipv4_packet = packet;
                }
            }
            let proto = Ipv4Type::from(ipv4_packet.protocol);
            let mut channels = self.l4_receive_channels.lock().unwrap();
            // RAW stack using Ipv4Type::Reserved will recieve all protocol packet.
            match channels.entry(Ipv4Type::Reserved) {
                Occupied(e) => {
                    match e.get().send(ipv4_packet) {
                        Err(e) => {
                            log::error!("Failed to send packet to RAW stack. Err: {}", e);
                            continue;
                        }
                        Ok(_) => {}
                    }
                    continue;
                }
                Vacant(_) => {}
            }
            if proto != Ipv4Type::Unknown {
                match channels.entry(proto) {
                    Occupied(e) => {
                        match e.get().send(ipv4_packet) {
                            Err(e) => {
                                log::error!("Failed to send packet to {:?} stack. Err: {}", proto, e);
                                continue;
                            }
                            Ok(_) => {}
                        }
                        continue;
                    }
                    Vacant(_) => {}
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
        1,     // Protocol (ICMP)
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
