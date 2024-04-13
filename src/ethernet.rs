use crate::types::EtherType;
use anyhow::{Context, Result};
use log;
use pnet_datalink::{self, Channel, DataLinkReceiver, DataLinkSender};
use std::sync::Mutex;

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

#[cfg(test)]
mod ethrenet_tests {
    use super::*;
    use rstest::rstest;
    use hex::decode;

    #[rstest]
    #[case(
        // normal arp packet
        "010203040506bebeff74a57808060001080006040001bebeff74a578ac140a6effffffffffffac140a0a",
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],
        u16::from(EtherType::ARP),
        "0001080006040001bebeff74a578ac140a6effffffffffffac140a0a",
        true
    )]
    #[case(
        // normal icmp packet
        "f09fc2df161f000c29faa337080045000054000040004001a1dbc0a8c8150808080808009b9b206500018af2a8620000000044d6050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        [0xf0, 0x9f, 0xc2, 0xdf, 0x16, 0x1f],
        [0x00, 0x0c, 0x29, 0xfa, 0xa3, 0x37],
        u16::from(EtherType::IPv4),
        "45000054000040004001a1dbc0a8c8150808080808009b9b206500018af2a8620000000044d6050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        true
    )]
    #[case(
        // Packet EtherType is 0x0000
        "010203040506bebeff74a57800000001080006040001bebeff74a578ac140a6effffffffffffac140a0a",
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        [0xbe, 0xbe, 0xff, 0x74, 0xa5, 0x78],
        0x0000 as u16,
        "0001080006040001bebeff74a578ac140a6effffffffffffac140a0a",
        false
    )]
    fn test_ethernet_packet_read(
        #[case] encoded_packet: &str,
        #[case] expected_dst: [u8; 6],
        #[case] expected_src: [u8; 6],
        #[case] expected_ethertype: u16,
        #[case] encoded_payload: &str,
        #[case] expected_valid: bool
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let payload = decode(encoded_payload).expect("Failed to decode payload hex string");
        let mut packet = EthernetPacket::new();
        let _ = packet.read(&packet_data).expect("Failed to read packet");
        let recreated_packet = packet.create_packet().expect("Failed to recreate packet");

        assert_eq!(packet.dst, expected_dst);
        assert_eq!(packet.src, expected_src);
        assert_eq!(packet.ethertype, expected_ethertype);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.valid, expected_valid);
        assert_eq!(recreated_packet, packet_data, "Recreated packet does not match the original data");
    }

    #[rstest]
    #[case("0102030405")]
    fn test_ethernet_packet_read_error(
        #[case] encoded_packet: &str,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut packet = EthernetPacket::new();
        let result = packet.read(&packet_data);

        assert!(result.is_err(), "Expected an error for insufficient packet length");
    }
}