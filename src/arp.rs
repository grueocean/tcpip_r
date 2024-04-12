use crate::ethernet::{EthernetPacket, EthernetRecveiver, EthernetSender};
use crate::types::{EtherType};
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

    pub fn read(&mut self, packet: Vec<u8>) -> Result<bool> {
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
    interface_name: String,
    interface_mac: MacAddress,
    interface_ipv4: (Ipv4Addr, usize),
    threads: Mutex<Vec<JoinHandle<()>>>,
    send_channel: Mutex<Sender<Box<[u8]>>>,
    event_condvar: (Mutex<Option<L2StackEvent>>, Condvar),
    receive_queue: Mutex<VecDeque<Vec<u8>>>,
    arp_table: Mutex<HashMap<Ipv4Addr, ArpEntry>>
}

impl L2Stack {
    pub fn new(interface_name: String, mac: MacAddress, ip: (Ipv4Addr, usize)) -> Result<Arc<Self>> {
        let (_, netmask) = ip;
        if netmask > 33 { return Err(anyhow::anyhow!("Incorrect subnet mask ({}). ", netmask)); }
        let (send_channl, recv_channl) = channel();
        let l2 = Arc::new(
            Self {
                interface_name: interface_name,
                interface_mac: mac,
                interface_ipv4: ip,
                threads: Mutex::new(Vec::new()),
                send_channel: Mutex::new(send_channl),
                event_condvar: (Mutex::new(None), Condvar::new()),
                receive_queue: Mutex::new(VecDeque::new()),
                arp_table: Mutex::new(HashMap::new())
            }
        );
        let l2_send = l2.clone();
        let handle_send = thread::spawn(move || {
            l2_send.send_thread(recv_channl).unwrap();
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
        loop {
            let mut arp_table = self.arp_table.lock().unwrap();
            arp_table.retain(|_, entry| Instant::now() < entry.creation_time + entry.ttl);
            drop(arp_table);
            thread::sleep(ARP_CACHE_REFREASH);
        }

        Ok(())
    }

    fn send_thread(&self, recv_channl: Receiver<Box<[u8]>>) -> Result<()> {
        let mut iface_send = EthernetSender::new(&self.interface_name)?;
        loop {
            let packet = recv_channl.recv().unwrap();
            iface_send.send_packet(&*packet)?
        }

        Ok(())
    }

    fn receive_thread(&self) -> Result<()> {
        let mut iface_recv = EthernetRecveiver::new(&self.interface_name)?;
        loop {
            let packet = iface_recv.recv_packet()?;
            log::trace!("Packet Recieved: {:x?}", packet);
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
                log::trace!("Discarding packet. Interface mac is {} but packet dst is to {}.", self.interface_mac, dst_mac);
                continue;
            }
            if EtherType::from(ethernet_packet.ethertype) == EtherType::ARP {
                let mut arp = ArpPacket::new();
                match arp.read(ethernet_packet.payload.clone()) {
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
                let mut queue = self.receive_queue.lock().unwrap();
                queue.push_back(ethernet_packet.payload);
                self.publish_event(L2StackEvent::Ipv4Received);
            }
        }
    }

    pub fn send(&self, packet: &[u8]) -> Result<()> {
        let send_channel_lock = self.send_channel.lock().unwrap();
        send_channel_lock.send(packet.to_vec().into_boxed_slice())?;

        Ok(())
    }

    pub fn recv(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        loop {
            if let Some(data) = self.receive_queue.lock().unwrap().pop_front() {
                *buffer = data;
                return Ok(buffer.len());
            }
            self.wait_event(L2StackEvent::Ipv4Received);
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

    fn publish_event(&self, event: L2StackEvent) {
        let (lock, condvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(event);
        condvar.notify_all();
    }

    fn arp_handler(&self, ethernet: EthernetPacket, arp: ArpPacket) -> Result<()> {
        let (ip, netmask) = self.interface_ipv4;
        let arp_src_ip = Ipv4Addr::from(arp.src_ip);
        let arp_dst_ip = Ipv4Addr::from(arp.dst_ip);
        if arp.opcode == 0x1 && Ipv4Addr::from(arp.dst_ip) == ip && is_netmask_range(ip, netmask, arp_src_ip) {
            // request to me, from my network.
            let mut arp_reply = ArpPacket::new();
            arp_reply.hw_type = 0x0001;
            arp_reply.proto_type = 0x0800;
            arp_reply.hw_size = 0x06;
            arp_reply.proto_size = 0x04;
            arp_reply.opcode = 0x2;
            arp_reply.src_mac = self.interface_mac.as_bytes().try_into()?;
            arp_reply.src_ip = ip.octets();
            arp_reply.dst_mac = arp.src_mac;
            arp_reply.dst_ip = arp.src_ip;
            let mut ethernet_packet = EthernetPacket::new();
            ethernet_packet.dst = ethernet.src;
            ethernet_packet.src = self.interface_mac.as_bytes().try_into()?;
            ethernet_packet.ethertype = u16::from(EtherType::ARP);
            ethernet_packet.payload = arp_reply.create_packet()?;
            log::debug!("Replying to arp request. dst mac: {} dst ip: {}", MacAddress::from_bytes(&arp.src_mac)?, arp_src_ip);
            let send_lock = self.send_channel.lock().unwrap();
            send_lock.send(ethernet_packet.create_packet()?.into_boxed_slice()).context("Failed to send reply arp packet.")?;
        } else if arp.opcode == 0x2 && is_netmask_range(ip, netmask, arp_dst_ip) {
            // reply
            let mut arp_table = self.arp_table.lock().unwrap();
            let arp_entry = ArpEntry {
                mac: MacAddress::from_bytes(&arp.dst_mac)?,
                creation_time: Instant::now(),
                ttl: ARP_CACHE_TIME
            };
            log::debug!("Arp entry added. ip: {} {}", arp_dst_ip, arp_entry);
            arp_table.insert(arp_dst_ip, arp_entry);
        }
        Ok(())
    }
}

fn is_netmask_range(ip: Ipv4Addr, netmask: usize, target_ip: Ipv4Addr) -> bool {
    let ip_u32: u32 = u32::from_be_bytes(ip.octets());
    let mask_u32: u32 = 0xffffffff >> netmask;
    let target_u32: u32 = u32::from_be_bytes(target_ip.octets());
    if (ip_u32 & mask_u32 <= target_u32) && (target_u32 <= ip_u32 | !mask_u32) {
        return true;
    } else {
        return false;
    }
}
