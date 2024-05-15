use crate::l2_l3::ip::{Ipv4Packet, NetworkConfiguration, L3Stack, get_global_l3stack};
use crate::l2_l3::defs::{Ipv4Type};
use anyhow::{Context, Result};
use log;
use std::collections::{HashMap, VecDeque};
use std::cmp::min;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::sync::mpsc::{channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const UDP_HEADER_LENGTH: usize = 8;
const UDP_MAX_SOCKET: usize = 10;
const UDP_MAX_PACKET_PER_QUEUE: usize = 1024;
// https://datatracker.ietf.org/doc/html/rfc6335
// the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535 (never assigned)
const UDP_EPHEMERAL_PORT_RANGE: Range<u16> = 49152..65535;

static UDPSTACK_GLOBAL: OnceLock<Arc<UdpStack>> = OnceLock::new();

pub fn get_global_udpstack(config: NetworkConfiguration) -> Result<&'static Arc<UdpStack>> {
    Ok(UDPSTACK_GLOBAL.get_or_init(|| UdpStack::new(config).unwrap()))
}

// https://datatracker.ietf.org/doc/html/rfc768
//
// 0       7 8     15 16    23 24     31
// +--------+--------+--------+--------+
// |     Source      |   Destination   |
// |      Port       |      Port       |
// +--------+--------+--------+--------+
// |                 |                 |
// |     Length      |    Checksum     |
// +--------+--------+--------+--------+
// |
// |          data octets ...
// +---------------- ...
//
//      User Datagram Header Format
//
// 0       7 8     15 16    23 24     31
// +--------+--------+--------+--------+
// |          source address           |
// +--------+--------+--------+--------+
// |        destination address        |
// +--------+--------+--------+--------+
// |  zero  |protocol|   UDP length    |
// +--------+--------+--------+--------+
//
//     pseudo header for checksum calc
//

#[derive(Clone, Debug)]
pub struct UdpPacket {
    pub src_addr: [u8; 4],  // pesudo header
    pub dst_addr: [u8; 4],  // pesudo header
    pub protocol: u8,       // pesudo header
    pub udp_length: u16,    // pesudo header
    pub local_port: u16,
    pub remote_port: u16,
    pub length: u16,        // same as udp_length (udp header (8) + payload)
    pub checksum: u16,
    pub payload: Vec<u8>,
    pub valid: bool
}

impl UdpPacket {
    pub fn new() -> Self {
        Self {
            src_addr: [0; 4],
            dst_addr: [0; 4],
            protocol: 0,
            udp_length: 0,
            local_port: 0,
            remote_port: 0,
            length: 0,
            checksum: 0,
            payload: Vec::new(),
            valid: false
        }
    }

    pub fn read(&mut self, ipv4_packet: &Ipv4Packet) -> Result<bool> {
        let payload_len = ipv4_packet.payload.len();
        if payload_len > 0xffff {
            return Err(anyhow::anyhow!("UDP packet payload length is {}, must be smaller than 65536+1.", payload_len));
        } else if payload_len < UDP_HEADER_LENGTH {
            return Err(anyhow::anyhow!("UDP packet payload length is {}, must be larger than header length ({}).", payload_len, UDP_HEADER_LENGTH));
        } else {
            self.udp_length = payload_len as u16;
        }
        self.src_addr = ipv4_packet.src_addr;
        self.dst_addr = ipv4_packet.dst_addr;
        self.protocol = ipv4_packet.protocol;
        self.local_port = u16::from_be_bytes(ipv4_packet.payload[0..2].try_into()?);
        self.remote_port = u16::from_be_bytes(ipv4_packet.payload[2..4].try_into()?);
        self.length = u16::from_be_bytes(ipv4_packet.payload[4..6].try_into()?);
        self.checksum = u16::from_be_bytes(ipv4_packet.payload[6..8].try_into()?);
        self.payload = ipv4_packet.payload[8..].to_vec();
        self.validate()?;

        Ok(self.valid)
    }

    fn calc_header_checksum(&self) -> u16 {
        let mut packet = self.create_pseudo_header();
        packet.extend(self.create_header());
        packet.extend(&self.payload);
        if packet.len() % 2 != 0 {
            packet.push(0);
        }
        let mut checksum_tmp: u32 = 0;
        for i in (0..packet.len()).step_by(2) {
            if i + 1 < packet.len() {
                let word = u16::from_be_bytes([packet[i], packet[i+1]]);
                checksum_tmp += u32::from(word);
            }
        }
        checksum_tmp -= self.checksum as u32;
        checksum_tmp = (checksum_tmp & 0xffff) + (checksum_tmp >> 16);
        while (checksum_tmp >> 16) > 0 {
            checksum_tmp = (checksum_tmp & 0xffff) + (checksum_tmp >> 16);
        }
        let checksum = !(checksum_tmp as u16);

        checksum
    }

    pub fn calc_header_checksum_and_set(&mut self) {
        self.checksum = self.calc_header_checksum();
    }

    pub fn validate(&mut self) -> Result<bool> {
        self.valid = true;
        if Ipv4Type::from(self.protocol) != Ipv4Type::UDP {
            log::error!("Reading none UDP packet (proto {}) as UDP.", self.protocol);
            self.valid = false;
        }
        let length = (UDP_HEADER_LENGTH + self.payload.len()) as u16;
        if self.udp_length != length {
            // This may be unneccessary becuase it should be also checked in Ipv4Packet.validate.
            return Err(anyhow::anyhow!("Bad length UDP packet. Header expected {} bytes but actually {} bytes.", self.udp_length, length));
        }
        let expected_checksum = self.calc_header_checksum();
        if self.checksum != expected_checksum && self.checksum != 0x0 {
            log::debug!("Unexpected udp header. Header checksum is 0x{:x} but is expected 0x{:x}.", self.checksum, expected_checksum);
            return Err(anyhow::anyhow!("UDP Header has bad checksum 0x{:x}, expected 0x{:x}.", self.checksum, expected_checksum));
        }

        Ok(self.valid)
    }

    fn create_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.local_port.to_be_bytes());
        header.extend_from_slice(&self.remote_port.to_be_bytes());
        header.extend_from_slice(&self.length.to_be_bytes());
        header.extend_from_slice(&self.checksum.to_be_bytes());

        header
    }

    fn create_pseudo_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.src_addr);
        header.extend_from_slice(&self.dst_addr);
        header.extend_from_slice(&(self.protocol as u16).to_be_bytes());
        header.extend_from_slice(&self.udp_length.to_be_bytes());

        header
    }

    fn create_packet(&mut self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        packet
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UdpEventType {
    UdpReceived
}

#[derive(Debug, Clone, PartialEq)]
struct UdpEvent {
    socket_id: usize,
    event: UdpEventType
}

pub struct UdpStack {
    pub config: NetworkConfiguration,
    pub sockets: Mutex<HashMap<usize, Option<UdpNetworkInfo>>>,
    pub receive_queue: Mutex<HashMap<usize, VecDeque<UdpPacket>>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    event_condvar: (Mutex<Option<UdpEvent>>, Condvar)
}

impl UdpStack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let udp = Arc::new(Self {
            config: config,
            sockets: Mutex::new(HashMap::new()),
            receive_queue: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            event_condvar: (Mutex::new(None), Condvar::new())
        });

        let udp_recv = udp.clone();
        let handle_recv = thread::spawn(move || {
            udp_recv.receive_thread().unwrap();
        });
        udp.threads.lock().unwrap().push(handle_recv);

        Ok(udp)
    }

    pub fn send(&self, socket_id: usize, network_info: Option<UdpNetworkInfo>, payload: Vec<u8>) -> Result<()> {
        let mut ipv4_packet = Ipv4Packet::new();
        let mut udp_packet = UdpPacket::new();
        // using send_to (specify dst)
        if let Some(UdpNetworkInfo {
            local,
            remote: Some(remote)
        }) = network_info {
            udp_packet.src_addr = local.ip().octets();
            udp_packet.local_port = local.port();
            udp_packet.dst_addr = remote.ip().octets();
            udp_packet.remote_port = remote.port();
            ipv4_packet.dst_addr = remote.ip().octets();
        // using send (dst is already set to socket.)
        } else {
            let sockets = self.sockets.lock().unwrap();
            if let Some(Some(UdpNetworkInfo {
                local,
                remote: Some(remote)
            })) = sockets.get(&socket_id) {
                udp_packet.src_addr = local.ip().octets();
                udp_packet.local_port = local.port();
                udp_packet.dst_addr = remote.ip().octets();
                udp_packet.remote_port = remote.port();
                ipv4_packet.dst_addr = remote.ip().octets();
            } else {
                return Err(anyhow::anyhow!("Failed to send UDP packet. Specify correct dst info or connect socket."));
            }
        }
        udp_packet.protocol = u8::from(Ipv4Type::UDP);
        let length = (payload.len() + UDP_HEADER_LENGTH) as u16;
        udp_packet.udp_length = length;
        udp_packet.length = length;
        udp_packet.payload = payload;
        udp_packet.calc_header_checksum_and_set();
        ipv4_packet.protocol = u8::from(Ipv4Type::UDP);
        ipv4_packet.payload = udp_packet.create_packet();
        let l3 = get_global_l3stack(self.config.clone())?;
        l3.l3interface.send(ipv4_packet)?;

        Ok(())
    }

    pub fn recv(&self, socket_id: usize) -> Result<(SocketAddrV4, Vec<u8>)> {
        loop {
            let sockets = self.sockets.lock().unwrap();
            let mut queue = self.receive_queue.lock().unwrap();
            if let Some(socket_queue) = queue.get_mut(&socket_id) {
                if let Some(packet) = socket_queue.pop_front() {
                    let src = SocketAddrV4::new(Ipv4Addr::from(packet.src_addr), packet.local_port);
                    return Ok((src, packet.payload));
                }
            }
            let event = UdpEvent {
                socket_id: socket_id,
                event: UdpEventType::UdpReceived
            };
            // drop lock and wait_event is not atomic... this may cause lost wakeup... :P
            drop(sockets);
            drop(queue);
            self.wait_event_with_timeout(event, Duration::from_millis(1000));
            continue;
        }
    }

    pub fn bind(&self, socket_id: usize, mut network_info: UdpNetworkInfo) -> Result<UdpNetworkInfo> {
        let mut sockets = self.sockets.lock().unwrap();
        let used_ports: Vec<u16> = sockets.values()
            .filter_map(|info| info.as_ref().map(|i| i.local.port()))
            .collect();
        if network_info.local.port() == 0 {
            // assign ephemeral port
            for port in UDP_EPHEMERAL_PORT_RANGE {
                if !used_ports.contains(&port) {
                    network_info.local.set_port(port);
                    sockets.insert(socket_id, Some(network_info));
                    self.update_queue(socket_id, network_info)?;
                    return Ok(network_info);
                }
            }
            anyhow::bail!("Failed to bind socket. No available ephemeral port.");
        } else {
            // verify if specified port is already used
            if used_ports.contains(&network_info.local.port()) {
                anyhow::bail!("Failed to bind socket. Port {} is already used.", network_info.local.port())
            } else {
                sockets.insert(socket_id, Some(network_info));
                self.update_queue(socket_id, network_info)?;
                Ok(network_info)
            }
        }
    }

    pub fn connect(&self, socket_id: usize, netwrok_info: UdpNetworkInfo) -> Result<UdpNetworkInfo> {
        let mut sockets = self.sockets.lock().unwrap();
        if let Some(Some(info)) = sockets.get_mut(&socket_id)  {
            *info = netwrok_info;
            Ok(netwrok_info)
        } else {
            anyhow::bail!("Cannot connect unbound socket.");
        }
    }

    // Should hold lock of sockets while executing.
    fn update_queue(&self, socket_id: usize, network_info: UdpNetworkInfo) -> Result<()> {
        let mut receive_queue = self.receive_queue.lock().unwrap();
        if let Some(queue) = receive_queue.get_mut(&socket_id) {
            if let UdpNetworkInfo { local, remote: None} =  network_info {
                let filtered: VecDeque<UdpPacket> = queue.iter()
                    .filter(|udp_packet|
                        udp_packet.dst_addr == local.ip().octets() &&
                        udp_packet.remote_port == local.port()
                    )
                    .cloned()
                    .collect();
                *queue = filtered;
                return Ok(());
            }
            if let UdpNetworkInfo { local, remote: Some(remote)} =  network_info {
                let filtered: VecDeque<UdpPacket> = queue.iter()
                    .filter(|udp_packet|
                        udp_packet.dst_addr == local.ip().octets() &&
                        udp_packet.remote_port == local.port() &&
                        udp_packet.src_addr == remote.ip().octets() &&
                        udp_packet.remote_port == remote.port()
                    )
                    .cloned()
                    .collect();
                *queue = filtered;
                return Ok(());
            }
        }

        Ok(())
    }

    pub fn generate_socket(&self) -> Result<usize> {
        let mut sockets = self.sockets.lock().unwrap();
        let mut queue = self.receive_queue.lock().unwrap();
        for id in 1..UDP_MAX_SOCKET {
            if sockets.contains_key(&id) {
                continue;
            } else {
                sockets.insert(id, None);
                queue.insert(id, VecDeque::new());

                return Ok(id);
            }
        }

        anyhow::bail!("Failed to generate new socket because no available id. UDP_MAX_SOCKET={}", UDP_MAX_SOCKET)
    }

    pub fn release_socket(&self, socket_id: usize) -> Result<()> {
        let mut sockets = self.sockets.lock().unwrap();
        let mut queue = self.receive_queue.lock().unwrap();
        sockets.remove(&socket_id);
        queue.remove(&socket_id);

        Ok(())
    }

    fn receive_thread(&self) -> Result<()> {
        let l3 = get_global_l3stack(self.config.clone())?;
        let (udp_send_channel, udp_recv_channel) = channel();
        l3.register_protocol(u8::from(Ipv4Type::UDP), udp_send_channel)?;
        loop {
            let ipv4_packet = udp_recv_channel.recv()?;
            let mut udp_packet = UdpPacket::new();
            match udp_packet.read(&ipv4_packet) {
                Err(e) => {
                    log::warn!("Failed to read udp packet. Err: {}", e);
                    continue;
                }
                Ok(_) => {}
            }
            match self.try_push_queue(udp_packet) {
                Err(e) => {
                    log::error!("Push udp packet to receive queue failed. Err: {}", e);
                }
                Ok(_) => {}
            }
        }
    }

    fn try_push_queue(&self, udp_packet: UdpPacket) -> Result<bool> {
        for (id, udp_info) in self.sockets.lock().unwrap().iter() {
            if let Some(network) = udp_info {
                if let UdpNetworkInfo {
                    local,
                    remote: Some(remote)
                } = network {
                    if local.ip().octets() != udp_packet.dst_addr ||
                       local.port() != udp_packet.remote_port ||
                       remote.ip().octets() != udp_packet.src_addr ||
                       remote.port() != udp_packet.local_port {
                        continue;
                    }
                };
                if let UdpNetworkInfo {
                    local,
                    remote: None
                } = network {
                    if local.ip().octets() != udp_packet.dst_addr || local.port() != udp_packet.remote_port { continue; }
                };
                let mut queue = self.receive_queue.lock().unwrap();
                if let Some(q) = queue.get_mut(id) {
                    if q.len() < UDP_MAX_PACKET_PER_QUEUE {
                        q.push_back(udp_packet);
                        let event = UdpEvent {
                            socket_id: *id,
                            event: UdpEventType::UdpReceived
                        };
                        self.publish_event(event);
                        return Ok(true);
                    } else {
                        log::warn!("Discarding udp packet due to queue full ({}). ", q.len());
                    }
                }
            } else {
                log::debug!("Udp socket (id={}) info is empty. Maybe it's not bind to port.", id);
            }
        }

        log::debug!(
            "Discarding udp packet. Port is unbound for this packet. src={}:{} dst={}:{}",
            Ipv4Addr::from(udp_packet.src_addr), udp_packet.local_port,
            Ipv4Addr::from(udp_packet.dst_addr), udp_packet.remote_port
        );
        Ok(false)
    }

    fn wait_event_with_timeout(&self, wait_event: UdpEvent, timeout: Duration) -> bool {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if *e == wait_event {
                    *event = None;
                    return true;
                }
            }
            let elapsed = start_time.elapsed();
            if elapsed >= timeout {
                return false; // Timeout expired
            }
            let remaining_time = timeout - elapsed;
            let (new_event, timeout_result) = condvar.wait_timeout(event, remaining_time).unwrap();
            event = new_event;
            if timeout_result.timed_out() {
                return false; // Timeout occurred
            }
        }
    }

    fn publish_event(&self, event: UdpEvent) {
        let (lock, condvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(event);
        condvar.notify_all();
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub struct UdpNetworkInfo {
    pub local: SocketAddrV4,
    pub remote: Option<SocketAddrV4>
}

pub struct UdpSocket {
    config: NetworkConfiguration,
    socket_id: usize,
    pub info: Option<UdpNetworkInfo>
}

// follow stdlib interface https://doc.rust-lang.org/std/net/struct.UdpSocket.html
impl UdpSocket {
    pub fn new(config: NetworkConfiguration) -> Result<Self> {
        let udp = get_global_udpstack(config.clone())?;
        let socket = udp.generate_socket()?;

        Ok(Self { config: config, socket_id: socket, info: None })
    }

    pub fn bind<A: ToSocketAddrs>(&mut self, addr: A) -> Result<()> {
        if let Some(info) = self.info {
            anyhow::bail!("It is already bound to {}/{}.", info.local.ip(), info.local.port());
        } else {
            match addr.to_socket_addrs()?.next() {
                Some(addr) => {
                    // We only assign port and ignore ip address because l3stack currently have an exact 1 interface and ip address.
                    let info = UdpNetworkInfo {
                        local: SocketAddrV4::new(self.config.ip.address, addr.port()),
                        remote: None
                    };
                    self.info = Some(info);
                    let udp = get_global_udpstack(self.config.clone())?;
                    let new_info = udp.bind(self.socket_id, info)?;
                    self.info = Some(new_info);

                    return Ok(());
                }
                None => {
                    anyhow::bail!("Failed to bind socket. Address may be invalid.");
                }
            }
        }
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<()> {
        if let Some(mut info) = self.info {
            if let Some(remote) = info.remote {
                anyhow::bail!("It is already connected to {}:{}.", remote.ip(), remote.port())
            } else {
                match addr.to_socket_addrs()?.next() {
                    Some(addr) => {
                        match addr.ip() {
                            IpAddr::V4(v4_addr) => {
                                info.remote = Some(SocketAddrV4::new(v4_addr, addr.port()));
                                let udp = get_global_udpstack(self.config.clone())?;
                                let new_info = udp.connect(self.socket_id, info)?;
                                self.info = Some(new_info);

                                return Ok(());
                            }
                            IpAddr::V6(_) => {
                                anyhow::bail!("Ipv6 is not supported.")
                            }
                        }
                    }
                    None => {
                        anyhow::bail!("Address may be invalid.");
                    }
                }
            }
        } else {
            anyhow::bail!("Udp socket is unbound. Need to bind at first.")
        }
    }

    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> Result<()> {
        if let Some(info) = self.info {
            anyhow::ensure!(info.remote == None, "send_to is only available for non-connected socket.");
            match addr.to_socket_addrs()?.next() {
                Some(addr) => {
                    match addr.ip() {
                        IpAddr::V4(v4_addr) => {
                            let udp = get_global_udpstack(self.config.clone())?;
                            let network_info = UdpNetworkInfo {
                                local: info.local,
                                remote: Some(SocketAddrV4::new(v4_addr, addr.port()))
                            };
                            udp.send(
                                self.socket_id,
                                Some(network_info),
                                buf.to_vec()
                            )?;
                            return Ok(());
                        }
                        IpAddr::V6(_) => {
                            anyhow::bail!("Ipv6 is not supported.")
                        }
                    }
                }
                None => {
                    anyhow::bail!("Address may be invalid.");
                }
            }
        } else {
            anyhow::bail!("Udp socket is unbound. Need to bind at first.");
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4)> {
        if let Some(info) = self.info {
            anyhow::ensure!(info.remote == None, "recv_from is only available for non-connected socket.");
            let udp = get_global_udpstack(self.config.clone())?;
            let (src, payload) = udp.recv(self.socket_id)?;
            let length = min(buf.len(), payload.len());
            buf[..length].copy_from_slice(&payload[..length]);

            Ok((length, src))
        } else {
            anyhow::bail!("Udp socket is unbound. Need to bind at first.");
        }
    }

    pub fn send(&self, buf: &[u8]) -> Result<()> {
        if let Some(info) = self.info {
            anyhow::ensure!(info.remote != None, "send is only available for connected socket.");
            let udp = get_global_udpstack(self.config.clone())?;
            udp.send(self.socket_id, None, buf.to_vec())?;

            Ok(())
        } else {
            anyhow::bail!("Udp socket is unbound. Need to bind at first.");
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if let Some(info) = self.info {
            anyhow::ensure!(info.remote != None, "recv is only available for connected socket.");
            let udp = get_global_udpstack(self.config.clone())?;
            let (_src, payload) = udp.recv(self.socket_id)?;
            let length = min(buf.len(), payload.len());
            buf[..length].copy_from_slice(&payload[..length]);

            Ok(length)
        } else {
            anyhow::bail!("Udp socket is unbound. Need to bind at first.");
        }
    }
}

#[cfg(test)]
mod udp_tests {
    use super::*;
    use rstest::rstest;
    use hex::decode;

    #[rstest]
    #[case(
        "4500003cfe5e4000401153eeac136f760ad9c20194e7003500286c038650012000010000000000000378787806676f6f676c6503636f6d0000010001",
        [172, 19, 111, 118], // pesudo header src ip addr
        [10, 217, 194, 1],   // pesudo header dst ip addr
        17,                  // pesudo header protocol (UDP)
        40,                  // pesudo header udp length
        38119,               // local port
        53,                  // remote port
        40,                  // length
        0x6c03,              // checksum
        "8650012000010000000000000378787806676f6f676c6503636f6d0000010001",
        true
    )]
    #[case(
        "4500003cfe5e4000400653f9ac136f760ad9c20194e7003500286c0e8650012000010000000000000378787806676f6f676c6503636f6d0000010001",
        [172, 19, 111, 118], // pesudo header src ip addr
        [10, 217, 194, 1],   // pesudo header dst ip addr
        6,                   // pesudo header protocol (TCP which is invalid)
        40,                  // pesudo header udp length
        38119,               // local port
        53,                  // remote port
        40,                  // length
        0x6c0e,              // checksum
        "8650012000010000000000000378787806676f6f676c6503636f6d0000010001",
        false
    )]
    fn test_udp_packet_read(
        #[case] encoded_packet: &str,
        #[case] expected_src_addr: [u8; 4],
        #[case] expected_dst_addr: [u8; 4],
        #[case] expected_protocol: u8,
        #[case] expected_udp_length: u16,
        #[case] expected_local_port: u16,
        #[case] expected_remote_port: u16,
        #[case] expected_length: u16,
        #[case] expected_checksum: u16,
        #[case] udp_payload_hex: &str,
        #[case] expected_valid: bool
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        assert!(ipv4_packet.read(&packet_data).is_ok(), "Failed to read IPv4 packet");

        let mut udp_packet = UdpPacket::new();
        assert_eq!(ipv4_packet.protocol, expected_protocol);
        let read_result = udp_packet.read(&ipv4_packet);
        assert!(read_result.is_ok(), "UDP packet read failed when it should not have");

        if read_result.is_ok() {
            assert_eq!(udp_packet.src_addr, expected_src_addr);
            assert_eq!(udp_packet.dst_addr, expected_dst_addr);
            assert_eq!(udp_packet.protocol, expected_protocol);
            assert_eq!(udp_packet.udp_length, expected_udp_length);
            assert_eq!(udp_packet.local_port, expected_local_port);
            assert_eq!(udp_packet.remote_port, expected_remote_port);
            assert_eq!(udp_packet.length, expected_length);
            assert_eq!(udp_packet.checksum, expected_checksum);
            assert_eq!(udp_packet.valid, expected_valid);

            let payload_data = decode(udp_payload_hex).expect("Failed to decode payload hex string");
            assert_eq!(udp_packet.payload, payload_data, "UDP payload does not match");
            let recreated_packet = udp_packet.create_packet();
            assert_eq!(ipv4_packet.payload, recreated_packet);
        }
    }
    #[rstest]
    // too short packet, omit 1 byte from checksum
    #[case("4500003cfe5e4000401153eeac136f760ad9c20194e7003500286c")]
    // bad udp checksum, last byte is 02 but should be 01
    #[case("4500003cfe5e4000401153eeac136f760ad9c20194e7003500286c038650012000010000000000000378787806676f6f676c6503636f6d0000010002")]
    fn test_udp_packet_read_error(
        #[case] encoded_packet: &str,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        let _ = ipv4_packet.read(&packet_data);
        let mut udp_packet = UdpPacket::new();
        let result = udp_packet.read(&ipv4_packet);

        assert!(result.is_err(), "Expected an error for incorrect header");
    }

}