use crate::types::EtherType;
use anyhow::{Context, Result};
use log;
use pnet_datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::sync::{Arc, Mutex};

const ETHERNET_HEADER_SIZE: usize = 14;

#[derive(Debug)]
pub struct EthernetPacket {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: Vec<u8>,
    pub valid: bool
}

impl EthernetPacket {
    pub fn new() -> Self {
        EthernetPacket {
            dst: [0; 6],
            src: [0; 6],
            ethertype: 0,
            payload: Vec::new(),
            valid: false
        }
    }

    pub fn read(&mut self, packet: &Vec<u8>) -> Result<bool> {
        if packet.len() < ETHERNET_HEADER_SIZE {
            return Err(anyhow::anyhow!("Insufficient packet length. packet.len()={}", packet.len()));
        }
        self.dst = packet[0..6].try_into()?;
        self.src = packet[6..12].try_into()?;
        self.ethertype = u16::from_be_bytes(packet[12..14].try_into()?);
        self.payload = packet[ETHERNET_HEADER_SIZE..].to_vec();
        self.validate()?;

        Ok(self.valid)
    }

    pub fn validate(&mut self) -> Result<bool> {
        self.valid = true;
        if EtherType::from(self.ethertype) == EtherType::Unknown {
            log::warn!("Reading Unknown EtherType (0x{:x}) packet. Mark packet as invalid.", self.ethertype);
            self.valid = false;
        }

        Ok(self.valid)
    }

    pub fn create_packet(&self) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.dst);
        packet.extend_from_slice(&self.src);
        packet.extend_from_slice(&self.ethertype.to_be_bytes());
        packet.extend_from_slice(&self.payload);

        Ok(packet)
    }
}

pub struct EthernetRecveiver {
    pub rx: Mutex<Box<dyn DataLinkReceiver>>
}

impl EthernetRecveiver {
    pub fn new(interface_name: &str) -> Result<Self> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .context(format!("cannot find interface {interface_name:?}"))?;
        let (_, rx) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("Ethernet channel is not available")),
            Err(e) => return Err(e.into())
        };

        Ok(Self { rx: Mutex::new(rx) })
    }

    pub fn recv_packet(&mut self) -> Result<Vec<u8>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.next() {
            Ok(packet) => Ok(packet.to_vec()),
            Err(e) => Err(anyhow::Error::from(e)).context("Failed to receive packet"),
        }
    }
}

pub struct EthernetSender {
    pub tx: Mutex<Box<dyn DataLinkSender>>
}

impl EthernetSender {
    pub fn new(interface_name: &str) -> Result<Self> {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .context(format!("cannot find interface {interface_name:?}"))?;
        let (tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("Ethernet channel is not available")),
            Err(e) => return Err(e.into())
        };

        Ok(Self { tx: Mutex::new(tx) })
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut tx = self.tx.lock().unwrap();
        match tx.send_to(packet, None) {
            Some(result) => {
                result.map_err(anyhow::Error::from).context("Failed to send packet")
            }
            None => Err(anyhow::anyhow!("Send operation did not return a result"))
        }
    }
}