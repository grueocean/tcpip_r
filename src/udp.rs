use crate::ip::{Ipv4Packet, NetworkConfiguration, L3Stack, get_global_l3stack};
use crate::types::{Ipv4Type};
use crate::udp;
use anyhow::{Context, Result};
use pnet::packet::udp::Udp;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const UDP_HEADER_LENGTH: usize = 8;
const UDP_MAX_SOCKET: usize = 10;
const UDP_MAX_PACKET_PER_QUEUE: usize = 1024;

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

#[derive(Debug)]
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

    fn create_packet(&mut self) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        Ok(packet)
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
    pub available_socket_id: Mutex<VecDeque<usize>>,
    pub sockets: Mutex<HashMap<usize, Option<UdpNetworkInfo>>>,
    pub receive_queue: Mutex<HashMap<usize, VecDeque<UdpPacket>>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    event_condvar: (Mutex<Option<UdpEvent>>, Condvar)
}

impl UdpStack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let udp = Arc::new(Self {
            config: config,
            available_socket_id: Mutex::new(VecDeque::from((1..=UDP_MAX_SOCKET).collect::<Vec<_>>())),
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
        if let Some(UdpNetworkInfo {
            local_addr,
            remote_addr: Some(remote_addr),
            local_port,
            remote_port: Some(remote_port)
        }) = network_info {
            udp_packet.src_addr = local_addr.octets();
            udp_packet.local_port = local_port;
            udp_packet.dst_addr = remote_addr.octets();
            udp_packet.remote_port = remote_port;
            ipv4_packet.dst_addr = remote_addr.octets();
        } else {
            let sockets = self.sockets.lock().unwrap();
            if let Some(Some(UdpNetworkInfo {
                local_addr,
                remote_addr: Some(remote_addr),
                local_port,
                remote_port: Some(remote_port)
            })) = sockets.get(&socket_id) {
                udp_packet.src_addr = local_addr.octets();
                udp_packet.local_port = *local_port;
                udp_packet.dst_addr = remote_addr.octets();
                udp_packet.remote_port = *remote_port;
                ipv4_packet.dst_addr = remote_addr.octets();
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
        ipv4_packet.payload = udp_packet.create_packet()?;
        let l3 = get_global_l3stack(self.config.clone())?;
        l3.l3interface.send(ipv4_packet)?;

        Ok(())
    }

    pub fn recv(&self, socket_id: usize) -> Result<(UdpNetworkInfo, Vec<u8>)> {
        loop {
            let sockets = self.sockets.lock().unwrap();
            let mut queue = self.receive_queue.lock().unwrap();
            if let (Some(socket_queue), Some(Some(socket))) = (queue.get_mut(&socket_id), sockets.get(&socket_id)) {
                if let Some(packet) = socket_queue.pop_front() {
                    return Ok((*socket, packet.payload));
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

    pub fn bind(&self, socket_id: usize, network_info: UdpNetworkInfo) -> Result<()> {
        let mut sockets = self.sockets.lock().unwrap();
        sockets.insert(socket_id, Some(network_info));

        Ok(())
    }

    pub fn generate_socket(&self) -> Result<usize> {
        let mut ids = self.available_socket_id.lock().unwrap();
        if let Some(new_id) = ids.pop_front() {
            let mut sockets = self.sockets.lock().unwrap();
            sockets.insert(new_id, None);
            let mut queue = self.receive_queue.lock().unwrap();
            queue.insert(new_id, VecDeque::new());
            Ok(new_id)
        } else {
            Err(anyhow::anyhow!("Failed to generate new socket because no available id. UDP_MAX_SOCKET={}", UDP_MAX_SOCKET))
        }
    }

    pub fn release_socket(&self, socket_id: usize) -> Result<()> {
        let mut ids = self.available_socket_id.lock().unwrap();
        let mut sockets = self.sockets.lock().unwrap();
        let mut queue = self.receive_queue.lock().unwrap();
        ids.push_back(socket_id);
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
                    local_addr,
                    remote_addr: Some(remote_addr),
                    local_port,
                    remote_port: Some(remote_port)
                } = network {
                    if local_addr.octets() != udp_packet.dst_addr ||
                       *local_port != udp_packet.local_port ||
                       remote_addr.octets() != udp_packet.src_addr ||
                       *remote_port != udp_packet.remote_port {
                        continue;
                    }
                };
                if let UdpNetworkInfo {
                    local_addr,
                    remote_addr: None,
                    local_port,
                    remote_port: None
                } = network {
                    if local_addr.octets() != udp_packet.dst_addr || *local_port != udp_packet.remote_port { continue; }
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
    pub local_addr: Ipv4Addr,
    pub remote_addr: Option<Ipv4Addr>,
    pub local_port: u16,
    pub remote_port: Option<u16>,
}

pub struct UdpSocket {
    config: NetworkConfiguration,
    socket_id: usize,
    info: UdpNetworkInfo
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
            let recreated_packet = udp_packet.create_packet().expect("Failed to recreate packet");
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