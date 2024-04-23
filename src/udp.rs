use crate::ip::{Ipv4Packet};
use crate::types::{Ipv4Type};
use anyhow::{Context, Result};

const UDP_HEADER_LENGTH: usize = 8;

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

pub struct UdpPacket {
    pub src_addr: [u8; 4],  // pesudo header
    pub dst_addr: [u8; 4],  // pesudo header
    pub protocol: u8,       // pesudo header
    pub udp_length: u16,    // pesudo header
    pub local_port: u16,
    pub remote_port: u16,
    pub length: u16,
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