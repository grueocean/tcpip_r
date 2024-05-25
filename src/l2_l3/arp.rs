use crate::l2_l3::ethernet::{self, EthernetPacket, EthernetRecveiver, EthernetSender};
use crate::l2_l3::ip::{Ipv4Packet, Ipv4Config};
use crate::l2_l3::defs::{EtherType, L2Error};
use anyhow::{Context, Result};
use eui48::MacAddress;
use log;
use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Formatter, Display};
use std::net::Ipv4Addr;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::time::{Duration, Instant};
use std::thread::{self, JoinHandle};

const ARP_LENGTH: usize = 28; // bytes
const ARP_CACHE_TIME: Duration = Duration::from_secs(10); // seconds
const ARP_CACHE_REFREASH: Duration = Duration::from_millis(100);
const ARP_RETRY: usize = 3;

#[derive(Debug, PartialEq)]
enum L2StackEvent {
    ArpReceived,
    Ipv4Received
}


// https://datatracker.ietf.org/doc/html/rfc826
#[derive(Debug)]
pub struct ArpPacket {
    hw_type: u16,
    proto_type: u16,
    hw_size: u8,
    proto_size: u8,
    opcode: u16,
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    valid: bool
}

impl ArpPacket {
    pub fn new() -> Self {
        ArpPacket {
            hw_type: 0,
            proto_type: 0,
            hw_size: 0,
            proto_size: 0,
            opcode: 0,
            src_mac: [0; 6],
            src_ip: [0; 4],
            dst_mac: [0; 6],
            dst_ip: [0; 4],
            valid: false
        }
    }

    pub fn read(&mut self, packet: &Vec<u8>) -> Result<bool> {
        if packet.len() != ARP_LENGTH {
            return Err(anyhow::anyhow!("ARP must be {} bytes. packet.len()={}", ARP_LENGTH, packet.len()));
        }
        self.hw_type = u16::from_be_bytes(packet[0..2].try_into()?);
        self.proto_type = u16::from_be_bytes(packet[2..4].try_into()?);
        self.hw_size = u8::from_be_bytes(packet[4..5].try_into()?);
        self.proto_size = u8::from_be_bytes(packet[5..6].try_into()?);
        self.opcode = u16::from_be_bytes(packet[6..8].try_into()?);
        self.src_mac = packet[8..14].try_into()?;
        self.src_ip = packet[14..18].try_into()?;
        self.dst_mac = packet[18..24].try_into()?;
        self.dst_ip = packet[24..28].try_into()?;
        self.validate()?;

        Ok(self.valid)
    }

    pub fn validate(&mut self) -> Result<bool> {
        self.valid = true;
        // https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
        if self.hw_type != 0x1 as u16 ||
           (self.opcode != 0x1 as u16 && self.opcode != 0x2 as u16) {
            log::warn!("Reading Unknown Type (hw type: 0x{:x} opcode: 0x{:x}) packet. Mark packet as invalid.", self.hw_type, self.opcode);
            self.valid = false;
        }

        Ok(self.valid)
    }

    pub fn create_packet(&self) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.hw_type.to_be_bytes());
        packet.extend_from_slice(&self.proto_type.to_be_bytes());
        packet.extend_from_slice(&self.hw_size.to_be_bytes());
        packet.extend_from_slice(&self.proto_size.to_be_bytes());
        packet.extend_from_slice(&self.opcode.to_be_bytes());
        packet.extend_from_slice(&self.src_mac);
        packet.extend_from_slice(&self.src_ip);
        packet.extend_from_slice(&self.dst_mac);
        packet.extend_from_slice(&self.dst_ip);

        Ok(packet)
    }
}

#[derive(Clone)]
pub struct ArpEntry {
    mac: MacAddress,
    creation_time: Instant,
    ttl: Duration,
}

impl Display for ArpEntry {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "mac: {} creation_time: {:?} ttl: {:?}", self.mac, self.creation_time, self.ttl)
    }
}

pub struct L2Stack {
    pub interface_name: String,
    pub interface_mac: MacAddress,
    pub interface_mtu: usize,
    pub interface_ipv4: Ipv4Config, // ip, netmask, net addr, broadcast addr
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    send_channel: Mutex<Sender<Box<[u8]>>>,
    event_condvar: (Mutex<Option<L2StackEvent>>, Condvar),
    receive_queue: Mutex<VecDeque<Vec<u8>>>,
    arp_table: Mutex<HashMap<Ipv4Addr, ArpEntry>>
}

impl L2Stack {
    pub fn new(interface_name: String, mac: MacAddress, mtu: usize, ip: Ipv4Config) -> Result<Arc<Self>> {
        let (send_channel, recv_channel) = channel();
        let l2 = Arc::new(
            Self {
                interface_name: interface_name,
                interface_mac: mac,
                interface_mtu: mtu,
                interface_ipv4: ip,
                threads: Mutex::new(Vec::new()),
                send_channel: Mutex::new(send_channel),
                event_condvar: (Mutex::new(None), Condvar::new()),
                receive_queue: Mutex::new(VecDeque::new()),
                arp_table: Mutex::new(HashMap::new())
            }
        );
        let l2_send = l2.clone();
        let handle_send = thread::spawn(move || {
            l2_send.send_thread(recv_channel).unwrap();
        });
        l2.threads.lock().unwrap().push(handle_send);

        let l2_recv = l2.clone();
        let handle_recv = thread::spawn(move || {
            l2_recv.receive_thread().unwrap();
        });
        l2.threads.lock().unwrap().push(handle_recv);

        let l2_timer = l2.clone();
        let handle_timer = thread::spawn(move || {
            l2_timer.timer_thread().unwrap();
        });
        l2.threads.lock().unwrap().push(handle_timer);

        Ok(l2)
    }

    // manage arp cache expire
    fn timer_thread(&self) -> Result<()> {
        log::info!("Starting L2Stack timer_thread.");
        loop {
            let mut arp_table = self.arp_table.lock().unwrap();
            arp_table.retain(|_, entry| Instant::now() < entry.creation_time + entry.ttl);
            drop(arp_table);
            thread::sleep(ARP_CACHE_REFREASH);
        }
    }

    fn send_thread(&self, recv_channl: Receiver<Box<[u8]>>) -> Result<()> {
        let mut iface_send = EthernetSender::new(&self.interface_name)?;
        loop {
            let packet = recv_channl.recv().unwrap();
            iface_send.send_packet(&*packet)?;
        }

        Ok(())
    }

    fn receive_thread(&self) -> Result<()> {
        log::info!("Starting L2Stack receive_thread.");
        let mut iface_recv = EthernetRecveiver::new(&self.interface_name)?;
        loop {
            let packet = iface_recv.recv_packet()?;
            log::trace!("Packet Received in L2Stack: {:x?}", packet);
            let mut ethernet_packet = EthernetPacket::new();
            match ethernet_packet.read(&packet) {
                Err(e) => {
                    log::warn!("Reading ethernet packet faild. Err: {}", e);
                    continue;
                }
                Ok(valid) => { if !valid { continue; } }
            }
            let dst_mac = MacAddress::from_bytes(&ethernet_packet.dst)?;
            if dst_mac != self.interface_mac && dst_mac != MacAddress::broadcast() {
                log::trace!("Discarding packet. Interface mac is {}, but packet dst is to {}.", self.interface_mac, dst_mac);
                continue;
            }
            if EtherType::from(ethernet_packet.ethertype) == EtherType::ARP {
                let mut arp = ArpPacket::new();
                match arp.read(&ethernet_packet.payload) {
                    Err(e) => {
                        log::warn!("Reading arp packet faild. Err: {}", e);
                        continue;
                    }
                    Ok(valid) => { if !valid { continue; } }
                }
                match self.arp_handler(ethernet_packet, arp) {
                    Err(e) => {
                        log::warn!("Handling arp failed. Err: {}", e);
                    }
                    Ok(_) => {}
                }
            } else if EtherType::from(ethernet_packet.ethertype) == EtherType::IPv4 {
                // We do not check if the packet is in the correct IPv4 format or if the dst
                // IP matches the interface IP here; those are handled at the L3 layer.
                let mut queue = self.receive_queue.lock().unwrap();
                queue.push_back(ethernet_packet.payload);
                self.publish_event(L2StackEvent::Ipv4Received);
            }
        }
    }

    pub fn send(&self, mut ipv4_packet: Ipv4Packet, dst_mac: Option<MacAddress>) -> Result<()> {
        let dst_ip_addr = Ipv4Addr::from(ipv4_packet.dst_addr);
        if dst_mac == None && !is_netmask_range(
            &self.interface_ipv4.address,
            self.interface_ipv4.netmask,
            &dst_ip_addr
        ) {
            log::error!(
                "L3 stack don't specify gateway mac addr while packet dst ({}) is out of local netwrok {}/{}.",
                dst_ip_addr, self.interface_ipv4.address, self.interface_ipv4.netmask
            );
            return Err(L2Error::NoGatewayError { target_ip: dst_ip_addr, l2_ip: self.interface_ipv4.address, l2_netmask: self.interface_ipv4.netmask }.into());
        }
        let mut ethernet_packet = EthernetPacket::new();
        // Currently we resolve ip from L3 that L2 is unaware of gateway info.
        // But L2Stack itself is also able to resolve ip within local network.
        if let Some(dst) = dst_mac {
            ethernet_packet.dst = dst.as_bytes().try_into()?;
        } else {
            ethernet_packet.dst = self.lookup_arp(&Ipv4Addr::from(ipv4_packet.dst_addr))?.as_bytes().try_into()?;
        }
        ethernet_packet.src = self.interface_mac.as_bytes().try_into()?;
        ethernet_packet.ethertype = u16::from(EtherType::IPv4);
        ethernet_packet.payload = ipv4_packet.create_packet()?;
        let send_channel_lock = self.send_channel.lock().unwrap();
        send_channel_lock.send(ethernet_packet.create_packet()?.into_boxed_slice())?;

        Ok(())
    }

    pub fn recv(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        loop {
            if let Some(data) = self.receive_queue.lock().unwrap().pop_front() {
                *buffer = data;
                return Ok(buffer.len());
            }
            self.wait_event_with_timeout(L2StackEvent::Ipv4Received, Duration::from_millis(100));
        }
    }

    pub fn close(&self) -> Result<()> {
        Ok(())
    }

    fn wait_event(&self, wait_event: L2StackEvent) {
        let (lock, condvar) = &self.event_condvar;
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if *e == wait_event { break; }
            }
            event = condvar.wait(event).unwrap();
        }
    }

    fn wait_event_with_timeout(&self, wait_event: L2StackEvent, timeout: Duration) -> bool {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if *e == wait_event { return true; }
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

    fn publish_event(&self, event: L2StackEvent) {
        let (lock, condvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(event);
        condvar.notify_all();
    }

    fn resolve_arp(&self, target_ip: &Ipv4Addr) -> Result<ArpEntry> {
        let mut count = 0;
        let mut ethernet_packet = EthernetPacket::new();
        ethernet_packet.dst = MacAddress::broadcast().as_bytes().try_into()?;
        ethernet_packet.src = self.interface_mac.as_bytes().try_into()?;
        ethernet_packet.ethertype = u16::from(EtherType::ARP);
        let mut arp_request = ArpPacket::new();
        arp_request.hw_type = 0x0001;
        arp_request.proto_type = u16::from(EtherType::IPv4);
        arp_request.hw_size = 0x6;
        arp_request.proto_size = 0x4;
        arp_request.opcode = 0x0001;
        arp_request.src_mac = self.interface_mac.as_bytes().try_into()?;
        arp_request.src_ip = self.interface_ipv4.address.octets();
        arp_request.dst_mac = [0; 6];
        arp_request.dst_ip = target_ip.octets();
        ethernet_packet.payload = arp_request.create_packet()?;
        while count < ARP_RETRY {
            let send_channel_lock = self.send_channel.lock().unwrap();
            send_channel_lock.send(ethernet_packet.create_packet()?.into_boxed_slice())?;
            // should wait with timeout, in case we miss wake up.
            self.wait_event_with_timeout(L2StackEvent::ArpReceived, Duration::from_millis(100));
            let arp_entry = {
                self.arp_table.lock().unwrap().get(target_ip).cloned()
            };
            if let Some(arp) = arp_entry {
                return Ok(arp);
            }
            count += 1;
        }

        Err(L2Error::ResolveError { target_ip: *target_ip, retries: ARP_RETRY }.into())
    }

    pub fn lookup_arp(&self, target_ip: &Ipv4Addr) -> Result<MacAddress> {
        let arp_entry = {
            self.arp_table.lock().unwrap().get(target_ip).cloned()
        };
        if let Some(arp) = arp_entry {
            return Ok(arp.mac);
        } else {
            return Ok(self.resolve_arp(target_ip)?.mac);
        }
    }

    fn arp_handler(&self, ethernet: EthernetPacket, arp: ArpPacket) -> Result<()> {
        let arp_src_ip = Ipv4Addr::from(arp.src_ip);
        let arp_dst_ip = Ipv4Addr::from(arp.dst_ip);
        let arp_src_mac = MacAddress::from_bytes(&arp.src_mac)?;
        if arp.opcode == 0x1 && arp_dst_ip == self.interface_ipv4.address &&
           is_netmask_range(&self.interface_ipv4.address, self.interface_ipv4.netmask, &arp_src_ip) {
            // request to me, from local network.
            if !arp_src_mac.is_nil() && !arp_src_mac.is_broadcast() && !arp_src_mac.is_multicast() &&
               !arp_src_ip.is_broadcast() && !arp_src_ip.is_multicast() && !arp_src_ip.is_link_local() && !arp_src_ip.is_loopback() {
                let mut arp_table = self.arp_table.lock().unwrap();
                let arp_entry = ArpEntry {
                    mac: arp_src_mac,
                    creation_time: Instant::now(),
                    ttl: ARP_CACHE_TIME
                };
                log::debug!("Arp entry added from request. ip: {} {}", arp_src_ip, arp_entry);
                arp_table.insert(arp_src_ip, arp_entry);
                drop(arp_table);
                self.publish_event(L2StackEvent::ArpReceived);
            }
            // reply to request
            let mut arp_reply = ArpPacket::new();
            arp_reply.hw_type = 0x0001;
            arp_reply.proto_type = u16::from(EtherType::IPv4);
            arp_reply.hw_size = 0x06;
            arp_reply.proto_size = 0x04;
            arp_reply.opcode = 0x2;
            arp_reply.src_mac = self.interface_mac.as_bytes().try_into()?;
            arp_reply.src_ip = self.interface_ipv4.address.octets();
            arp_reply.dst_mac = arp.src_mac;
            arp_reply.dst_ip = arp.src_ip;
            let mut ethernet_packet = EthernetPacket::new();
            ethernet_packet.dst = ethernet.src;
            ethernet_packet.src = self.interface_mac.as_bytes().try_into()?;
            ethernet_packet.ethertype = u16::from(EtherType::ARP);
            ethernet_packet.payload = arp_reply.create_packet()?;
            log::debug!("Replying to arp request. dst mac: {} dst ip: {}", arp_src_mac, arp_src_ip);
            let send_lock = self.send_channel.lock().unwrap();
            send_lock.send(ethernet_packet.create_packet()?.into_boxed_slice()).context("Failed to send reply arp packet.")?;
        } else if arp.opcode == 0x2 && is_netmask_range(&self.interface_ipv4.address, self.interface_ipv4.netmask, &arp_dst_ip) {
            // reply
            let mut arp_table = self.arp_table.lock().unwrap();
            let arp_entry = ArpEntry {
                mac: arp_src_mac,
                creation_time: Instant::now(),
                ttl: ARP_CACHE_TIME
            };
            log::debug!("Arp entry added from reply. ip: {} {}", arp_src_ip, arp_entry);
            arp_table.insert(arp_src_ip, arp_entry);
            self.publish_event(L2StackEvent::ArpReceived);
        }
        Ok(())
    }
}

pub fn generate_network_addr(ip: &Ipv4Addr, netmask: usize) -> Ipv4Addr {
    if netmask == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let ip_u32: u32 = u32::from_be_bytes(ip.octets());
    let mask_u32: u32 = 0xffffffff << (32 - netmask);

    Ipv4Addr::from(ip_u32 & mask_u32)
}

pub fn generate_broadcast_addr(ip: &Ipv4Addr, netmask: usize) -> Ipv4Addr {
    if netmask == 0 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    let ip_u32: u32 = u32::from_be_bytes(ip.octets());
    let mask_u32: u32 = 0xffffffff << (32 - netmask);

    Ipv4Addr::from(ip_u32 | !mask_u32)
}

pub fn is_netmask_range(ip: &Ipv4Addr, netmask: usize, target_ip: &Ipv4Addr) -> bool {
    let network_addr_u32 = u32::from(generate_network_addr(ip, netmask));
    let broadcast_addr_u32 = u32::from(generate_broadcast_addr(ip, netmask));
    let target_u32: u32 = u32::from_be_bytes(target_ip.octets());
    if (network_addr_u32 <= target_u32) && (target_u32 <= broadcast_addr_u32) {
        return true;
    } else {
        return false;
    }
}

#[cfg(test)]
mod arp_tests {
    use super::*;
    use rstest::rstest;
    use hex::decode;

    #[rstest]
    #[case(
        "0001080006040001bebeff74a578c0a80001000000000000c0a80002",
        0x0001,  // HW type (Ethernet)
        0x0800,  // Protocol type (IPv4)
        6,       // HW size
        4,       // Protocol size
        0x0001,  // Opcode (request)
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],  // Src MAC
        [192, 168, 0, 1],  // Src IP
        [0, 0, 0, 0, 0, 0],  // Dst MAC (unspecified in requests)
        [192, 168, 0, 2],  // Dst IP
        true    // Expected validity
    )]
    #[case(
        "0001080006040002bebeff74a578c0a80001bebeff74a578c0a80002",
        0x0001,  // HW type (Ethernet)
        0x0800,  // Protocol type (IPv4)
        6,       // HW size
        4,       // Protocol size
        0x0002,  // Opcode (reply)
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],  // Src MAC
        [192, 168, 0, 1],  // Src IP
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],  // Dst MAC
        [192, 168, 0, 2],  // Dst IP
        true    // Expected validity
    )]
    #[case(
        "0001080006040000bebeff74a578c0a80001bebeff74a578c0a80002",
        0x0001,  // HW type (Ethernet)
        0x0800,  // Protocol type (IPv4)
        6,       // HW size
        4,       // Protocol size
        0x0000,  // Opcode (invalid)
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],  // Src MAC
        [192, 168, 0, 1],  // Src IP
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],  // Dst MAC
        [192, 168, 0, 2],  // Dst IP
        false    // Expected validity
    )]
    fn test_arp_packet_read(
        #[case] encoded_packet: &str,
        #[case] expected_hw_type: u16,
        #[case] expected_proto_type: u16,
        #[case] expected_hw_size: u8,
        #[case] expected_proto_size: u8,
        #[case] expected_opcode: u16,
        #[case] expected_src_mac: [u8; 6],
        #[case] expected_src_ip: [u8; 4],
        #[case] expected_dst_mac: [u8; 6],
        #[case] expected_dst_ip: [u8; 4],
        #[case] expected_valid: bool
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut arp_packet = ArpPacket::new();
        let result = arp_packet.read(&packet_data).expect("Failed to read ARP packet");
        let recreated_packet = arp_packet.create_packet().expect("Failed to recreate packet");

        assert_eq!(arp_packet.hw_type, expected_hw_type);
        assert_eq!(arp_packet.proto_type, expected_proto_type);
        assert_eq!(arp_packet.hw_size, expected_hw_size);
        assert_eq!(arp_packet.proto_size, expected_proto_size);
        assert_eq!(arp_packet.opcode, expected_opcode);
        assert_eq!(arp_packet.src_mac, expected_src_mac);
        assert_eq!(arp_packet.src_ip, expected_src_ip);
        assert_eq!(arp_packet.dst_mac, expected_dst_mac);
        assert_eq!(arp_packet.dst_ip, expected_dst_ip);
        assert_eq!(result, expected_valid);
        assert_eq!(recreated_packet, packet_data, "Recreated packet does not match the original data");
    }

    #[rstest]
    // too short packet
    #[case("0102030405")]
    // too long packet
    #[case("0001080006040001bebeff74a578c0a80001000000000000c0a800020111")]
    fn test_arp_packet_read_error(
        #[case] encoded_packet: &str,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut packet = ArpPacket::new();
        let result = packet.read(&packet_data);

        assert!(result.is_err(), "Expected an error for incorrect packet length");
    }


    #[rstest]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 24, Ipv4Addr::new(192, 168, 1, 0))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 16, Ipv4Addr::new(192, 168, 0, 0))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 8, Ipv4Addr::new(192, 0, 0, 0))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 0, Ipv4Addr::new(0, 0, 0, 0))]
    fn test_generate_network_addr(
        #[case] ip: Ipv4Addr,
        #[case] netmask: usize,
        #[case] expected: Ipv4Addr,
    ) {
        assert_eq!(generate_network_addr(&ip, netmask), expected);
    }

    #[rstest]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 24, Ipv4Addr::new(192, 168, 1, 255))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 16, Ipv4Addr::new(192, 168, 255, 255))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 8, Ipv4Addr::new(192, 255, 255, 255))]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 0, Ipv4Addr::new(255, 255, 255, 255))]
    fn test_generate_broadcast_addr(
        #[case] ip: Ipv4Addr,
        #[case] netmask: usize,
        #[case] expected: Ipv4Addr,
    ) {
        assert_eq!(generate_broadcast_addr(&ip, netmask), expected);
    }

    #[rstest]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 24, Ipv4Addr::new(192, 168, 1, 10), true)]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 24, Ipv4Addr::new(192, 168, 2, 1), false)]
    #[case(Ipv4Addr::new(192, 168, 1, 1), 16, Ipv4Addr::new(192, 168, 255, 255), true)]
    #[case(Ipv4Addr::new(10, 0, 0, 1), 8, Ipv4Addr::new(10, 255, 255, 255), true)]
    #[case(Ipv4Addr::new(10, 0, 0, 1), 16, Ipv4Addr::new(11, 0, 0, 1), false)]
    #[case(Ipv4Addr::new(10, 0, 0, 1), 0, Ipv4Addr::new(8, 8, 8, 8), true)]
    fn test_is_netmask_range(
        #[case] ip: Ipv4Addr,
        #[case] netmask: usize,
        #[case] target_ip: Ipv4Addr,
        #[case] expected: bool,
    ) {
        assert_eq!(is_netmask_range(&ip, netmask, &target_ip), expected);
    }
}
