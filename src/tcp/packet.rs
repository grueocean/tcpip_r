use crate::l2_l3::{
    defs::Ipv4Type,
    ip::Ipv4Packet,
};
use crate::tcp::defs::{TcpOptionKind};
use anyhow::{Context, Result};
use pnet::util::Octets;

// Tcp header max size is 60 (15*4) bytes  because Max Data Offset is 15 (0b1111).
const TCP_HEADER_LENGTH_BASIC: usize = 20;

// https://datatracker.ietf.org/doc/html/rfc9293
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |       |C|E|U|A|P|R|S|F|                               |
// | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
// |       |       |R|E|G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           [Options]                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               :
// :                             Data                              :
// :                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
pub struct TcpPacket {
    pub src_addr: [u8; 4],  // pesudo header
    pub dst_addr: [u8; 4],  // pesudo header
    pub protocol: u8,       // pesudo header
    pub tcp_length: u16,    // pesudo header
    pub local_port: u16,
    pub remote_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub offset: u8,         // 4 bit (payload begins from 4*offset bytes)
    pub flag_cwr: bool,     // Congestion Window Reduced
    pub flag_ece: bool,     // ECN-Echo
    pub flag_urg: bool,     // Urgent pointer field
    pub flag_ack: bool,     // Acknowledgment field
    pub flag_psh: bool,     // Push function
    pub flag_rst: bool,     // Reset the connection.
    pub flag_syn: bool,     // Synchronize sequence numbers.
    pub flag_fin: bool,     // No more data from sender.
    pub windows_size: u16,
    pub checksum: u16,
    pub urg_pointer: u16,
    pub option_raw: Vec<u8>,
    pub option: TcpOption,
    pub payload: Vec<u8>,
    pub valid: bool
}

impl TcpPacket {
    pub fn new() -> Self {
        Self {
            src_addr: [0; 4],
            dst_addr: [0; 4],
            protocol: 0,
            tcp_length: 0,
            local_port: 0,
            remote_port: 0,
            seq_number: 0,
            ack_number: 0,
            offset: 0,
            flag_cwr: false,
            flag_ece: false,
            flag_urg: false,
            flag_ack: false,
            flag_psh: false,
            flag_rst: false,
            flag_syn: false,
            flag_fin: false,
            windows_size: 0,
            checksum: 0,
            urg_pointer: 0,
            option_raw: Vec::new(),
            option: TcpOption::new(),
            payload: Vec::new(),
            valid: false
        }
    }

    pub fn read(&mut self, ipv4_packet: &Ipv4Packet) -> Result<bool> {
        let tcp_len = ipv4_packet.payload.len();
        if tcp_len > 0xffff {
            anyhow::bail!("TCP packet payload length is {}, must be smaller than 65536+1.", tcp_len);
        } else if tcp_len < TCP_HEADER_LENGTH_BASIC {
            anyhow::bail!("TCP packet payload length is {}, must be larger than header length ({}).", tcp_len, TCP_HEADER_LENGTH_BASIC);
        } else {
            self.tcp_length = tcp_len as u16;
        }

        self.src_addr = ipv4_packet.src_addr;
        self.dst_addr = ipv4_packet.dst_addr;
        self.protocol = ipv4_packet.protocol;
        self.local_port = u16::from_be_bytes(ipv4_packet.payload[0..2].try_into()?);
        self.remote_port = u16::from_be_bytes(ipv4_packet.payload[2..4].try_into()?);
        self.seq_number = u32::from_be_bytes(ipv4_packet.payload[4..8].try_into()?);
        self.ack_number = u32::from_be_bytes(ipv4_packet.payload[8..12].try_into()?);
        self.offset = u8::from_be_bytes(ipv4_packet.payload[12..13].try_into()?) >> 4;
        let offset_bytes = (self.offset * 4) as usize;
        anyhow::ensure!(tcp_len >= offset_bytes, "TCP packet payload length is {}, but header's data offset indicate {}.", tcp_len, offset_bytes);

        let flag = u8::from_be_bytes(ipv4_packet.payload[13..14].try_into()?);
        self.flag_cwr = (flag >> 7 & 0b1) == 0b1;
        self.flag_ece = (flag >> 6 & 0b1) == 0b1;
        self.flag_urg = (flag >> 5 & 0b1) == 0b1;
        self.flag_ack = (flag >> 4 & 0b1) == 0b1;
        self.flag_psh = (flag >> 3 & 0b1) == 0b1;
        self.flag_rst = (flag >> 2 & 0b1) == 0b1;
        self.flag_syn = (flag >> 1 & 0b1) == 0b1;
        self.flag_fin = (flag & 0b1) == 0b1;

        self.windows_size = u16::from_be_bytes(ipv4_packet.payload[14..16].try_into()?);
        self.checksum = u16::from_be_bytes(ipv4_packet.payload[16..18].try_into()?);
        self.urg_pointer = u16::from_be_bytes(ipv4_packet.payload[18..20].try_into()?);
        self.option_raw = ipv4_packet.payload[20..offset_bytes].to_vec();
        self.option.read(&self.option_raw)?;
        self.payload = ipv4_packet.payload[offset_bytes..].to_vec();
        self.validate()?;

        Ok(self.valid)
    }

    fn calc_header_checksum(&mut self) -> u16 {
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

    fn calc_header_checksum_and_set(&mut self) {
        self.checksum = self.calc_header_checksum();
    }

    pub fn validate(&mut self) -> Result<bool> {
        self.valid = true;
        if Ipv4Type::from(self.protocol) != Ipv4Type::TCP {
            log::error!("Reading none TCP packet (proto {}) as TCP.", self.protocol);
            self.valid = false;
        }
        let expected_checksum = self.calc_header_checksum();
        if self.checksum != expected_checksum && self.checksum != 0x0 {
            println!("ex: {:x} act: {:x}", expected_checksum, self.checksum);
            log::debug!("Unexpected tcp header. Header checksum is 0x{:x} but is expected 0x{:x}.", self.checksum, expected_checksum);
            anyhow::bail!("TCP Header has bad checksum 0x{:x}, expected 0x{:x}.", self.checksum, expected_checksum);
        }

        Ok(self.valid)
    }

    pub fn create_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.local_port.to_be_bytes());
        header.extend_from_slice(&self.remote_port.to_be_bytes());
        header.extend_from_slice(&self.seq_number.to_be_bytes());
        header.extend_from_slice(&self.ack_number.to_be_bytes());

        let mut offset_flags = 0u16;
        offset_flags = offset_flags | ((self.offset as u16) << 12) as u16;
        if self.flag_cwr { offset_flags |= 1 << 7; }
        if self.flag_ece { offset_flags |= 1 << 6; }
        if self.flag_urg { offset_flags |= 1 << 5; }
        if self.flag_ack { offset_flags |= 1 << 4; }
        if self.flag_psh { offset_flags |= 1 << 3; }
        if self.flag_rst { offset_flags |= 1 << 2; }
        if self.flag_syn { offset_flags |= 1 << 1; }
        if self.flag_fin { offset_flags |= 1 << 0; }
        header.extend_from_slice(&offset_flags.to_be_bytes());

        header.extend_from_slice(&self.windows_size.to_be_bytes());
        header.extend_from_slice(&self.checksum.to_be_bytes());
        header.extend_from_slice(&self.urg_pointer.to_be_bytes());
        header.extend(&self.option_raw);

        header
    }

    fn create_pseudo_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.src_addr);
        header.extend_from_slice(&self.dst_addr);
        header.extend_from_slice(&(self.protocol as u16).to_be_bytes());
        header.extend_from_slice(&self.tcp_length.to_be_bytes());

        header
    }

    fn create_packet(&mut self) -> Vec<u8> {
        let mut packet = Vec::new();
        self.set_option_raw();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        packet
    }

    fn set_option_raw(&mut self) {
        self.option_raw = self.option.create_packet_option();
    }
}

#[derive(Debug, PartialEq)]
pub struct TcpOption {
    mss: Option<u16>,                         // kind=2 Maximum Segment Size  2 bytes
    window_scale: Option<u8>,                 // kind=3 Window Scale Option   1 bytes
    sack_permitted: bool,                     // kind=4 Sack-Permitted Option 0 bytes (only kind and length=2)
    sack: Option<Vec<(u32, u32)>>,            // kind=5 Sack Option           8 bytes * n
    timestamps: Option<TcpOptionTimestamp>    // kind=8 Timestamps Option     4 bytes * 2
}

impl TcpOption {
    pub fn new() -> Self {
        Self {
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: None,
            timestamps: None
        }
    }

    pub fn read(&mut self, option: &Vec<u8>) -> Result<()> {
        let mut offset: usize = 0;
        let length = option.len();
        while offset < length {
            let kind = u8::from_be_bytes(option[offset..offset+1].try_into()?);
            match TcpOptionKind::from(kind) {
                TcpOptionKind::EndOption => {
                    anyhow::ensure!(offset + 1 == length, "EndOption offset is {} but option length is {}.", offset, length);
                    offset += 1;
                }
                TcpOptionKind::NoOperation => {
                    offset += 1;
                }
                TcpOptionKind::MaxSegmentSize => {
                    anyhow::ensure!(offset + 4 <= length, "MaxSegmentSize needs 4 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?);
                    anyhow::ensure!(len == 4, "Length field of MaxSegmentSize must be 4 but is {}.", len);
                    self.mss = Some(u16::from_be_bytes(option[offset+2..offset+4].try_into()?));
                    offset += 4;
                }
                TcpOptionKind::WindowScale => {
                    anyhow::ensure!(offset + 3 <= length, "WindowScale needs 3 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?);
                    anyhow::ensure!(len == 3, "Length field of WindowScale must be 3 but is {}.", len);
                    self.window_scale = Some(u8::from_be_bytes(option[offset+2..offset+3].try_into()?));
                    offset += 3;
                }
                TcpOptionKind::SackPermission => {
                    anyhow::ensure!(offset + 2 <= length, "SackPermission needs 2 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?);
                    anyhow::ensure!(len == 2, "Length field of WindowScale must be 2 but is {}.", len);
                    self.sack_permitted = true;
                    offset += 2;
                }
                TcpOptionKind::SackOption => {
                    anyhow::ensure!(offset + 2 <= length, "SackOption needs 2 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?) as usize;
                    anyhow::ensure!(offset + len <= length, "Length field of SackOption is {} but only {} bytes left.", len, length - offset);
                    anyhow::ensure!((length - offset - 2) % 8 == 0, "SackOption payload must be 8 bytes alligned but len-2 is {}.", len - 2);
                    for i in (offset+2..offset+len).step_by(8) {
                        if let Some(sack) = self.sack.as_mut() {
                            sack.push((
                                u32::from_be_bytes(option[i..i+4].try_into()?),
                                u32::from_be_bytes(option[i+4..i+8].try_into()?)
                            ));
                        } else {
                            let mut new_sack = Vec::new();
                            new_sack.push((
                                u32::from_be_bytes(option[i..i+4].try_into()?),
                                u32::from_be_bytes(option[i+4..i+8].try_into()?)
                            ));
                            self.sack = Some(new_sack);
                        }
                    }
                    offset += len;
                }
                TcpOptionKind::Timestamp => {
                    anyhow::ensure!(offset + 10 <= length, "Timestamp needs 10 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?);
                    anyhow::ensure!(len == 10, "Length field of Timestamp must be 10 but is {}.", len);
                    self.timestamps = Some(TcpOptionTimestamp {
                        ts_value: u32::from_be_bytes(option[offset+2..offset+6].try_into()?),
                        ts_echo_reply: u32::from_be_bytes(option[offset+6..offset+10].try_into()?),
                    });
                    offset += 10;
                }
                TcpOptionKind::Unknown => {
                    log::debug!("Unknown tcp option. kind: {}", kind);
                    anyhow::ensure!(offset + 2 <= length, "This option kind is unknown, at least need 2 bytes but only {} bytes left.", length - offset);
                    let len = u8::from_be_bytes(option[offset+1..offset+2].try_into()?) as usize;
                    if len > 2 {
                        anyhow::ensure!(offset + len <= length, "Length field of unkown option is {} but only {} bytes left.", len, length - offset);
                    }
                    offset += len;
                }
            }
        }

        Ok(())
    }

    fn create_packet_option(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        if let Some(mss) = self.mss {
            packet.push(u8::from(TcpOptionKind::MaxSegmentSize));
            packet.push(4 as u8);
            packet.extend_from_slice(&mss.to_be_bytes());
        }
        if let Some(window) = self.window_scale {
            packet.push(u8::from(TcpOptionKind::WindowScale));
            packet.push(3);
            packet.push(window);
        }
        if self.sack_permitted {
            packet.push(u8::from(TcpOptionKind::SackPermission));
            packet.push(2);
        }
        if let Some(sack) = &self.sack {
            let len = sack.len();
            packet.push(u8::from(TcpOptionKind::SackOption));
            packet.push((len * 8 + 2) as u8);
            for (left, right) in sack {
                packet.extend_from_slice(&left.octets());
                packet.extend_from_slice(&right.octets());
            }
        }
        if let Some(TcpOptionTimestamp {ts_value, ts_echo_reply}) = self.timestamps {
            packet.push(u8::from(TcpOptionKind::Timestamp));
            packet.push(10);
            packet.extend_from_slice(&ts_value.octets());
            packet.extend_from_slice(&ts_echo_reply.octets());
        }
        let len = packet.len();
        let mut padding = vec![u8::from(TcpOptionKind::NoOperation); (4 - len % 4) % 4];
        packet.append(&mut padding);

        packet
    }
}

// https://datatracker.ietf.org/doc/html/rfc7323#section-3
//
// TCP Timestamps option (TSopt):
//
// Kind: 8
//
// Length: 10 bytes
//
//        +-------+-------+---------------------+---------------------+
//        |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
//        +-------+-------+---------------------+---------------------+
//            1       1              4                     4
#[derive(Debug, PartialEq)]
pub struct TcpOptionTimestamp {
    ts_value: u32,       // 4 bytes
    ts_echo_reply: u32   // 4 bytes
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use rstest::rstest;
    use hex::decode;

    #[rstest]
    #[case(
        "4500003450bf40008006ff4b0a000091ba0fe618d4a40050dd65a54700000000800220004cbb0000020405b40103030201010402",
        [10, 0, 0, 145],     // pesudo header src ip addr
        [186, 15, 230, 24],  // pesudo header dst ip addr
        6,                   // pesudo header protocol (TCP)
        32,                  // pesudo header tcp length
        54436,               // local port
        80,                  // remote port
        3714426183,          // sequence number
        0,                   // acknowledgment number
        8,                   // data offset
        0x2,                 // flag
        8192,                // window
        0x4cbb,              // checksum
        0,                   // urg pointer
        TcpOption {
            mss: Some(1460),
            window_scale: Some(2),
            sack_permitted: true,
            sack: None,
            timestamps: None
        },
        "",
        true                 // expected valid
    )]
    #[case(
        "45000034000040003c06940bba0fe6180a0000910050d4a496d38404dd65a5488012390818cb0000020405b40101040201030301",
        [186, 15, 230, 24],  // pesudo header src ip addr
        [10, 0, 0, 145],     // pesudo header dst ip addr
        6,                   // pesudo header protocol (TCP)
        32,                  // pesudo header tcp length
        80,                  // local port
        54436,               // remote port
        2530444292,          // sequence number
        3714426184,          // acknowledgment number
        8,                   // data offset
        0x12,                // flag
        14600,               // window
        0x18cb,              // checksum
        0,                   // urg pointer
        TcpOption {
            mss: Some(1460),
            window_scale: Some(1),
            sack_permitted: true,
            sack: None,
            timestamps: None
        },
        "",
        true                 // expected valid
    )]
    #[case(
        "4500003450f640008006ff140a000091ba0fe618d4a40050dd65a68c96d43a858010111c7ee300000101050a96d46dd996d47941",
        [10, 0, 0, 145],     // pesudo header src ip addr
        [186, 15, 230, 24],  // pesudo header dst ip addr
        6,                   // pesudo header protocol (TCP)
        32,                  // pesudo header tcp length
        54436,               // local port
        80,                  // remote port
        3714426508,          // sequence number
        2530491013,          // acknowledgment number
        8,                   // data offset
        0x10,                // flag
        4380,                // window
        0x7ee3,              // checksum
        0,                   // urg pointer
        TcpOption {
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: Some(vec![(0x96d46dd9, 0x96d47941)]),
            timestamps: None
        },
        "",
        true                 // expected valid
    )]
    fn test_tcp_packet_read(
        #[case] encoded_packet: &str,
        #[case] expected_src_addr: [u8; 4],
        #[case] expected_dst_addr: [u8; 4],
        #[case] expected_protocol: u8,
        #[case] expected_tcp_length: u16,
        #[case] expected_local_port: u16,
        #[case] expected_remote_port: u16,
        #[case] expected_seq_number: u32,
        #[case] expected_ack_number: u32,
        #[case] expected_data_offset: u8,
        #[case] expected_flag: u8,
        #[case] expected_window: u16,
        #[case] expected_checksum: u16,
        #[case] expected_urg_pointer: u16,
        #[case] expected_option: TcpOption,
        #[case] tcp_payload_hex: &str,
        #[case] expected_valid: bool
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        assert!(ipv4_packet.read(&packet_data).is_ok(), "Failed to read IPv4 packet");

        let mut tcp_packet = TcpPacket::new();
        assert_eq!(ipv4_packet.protocol, expected_protocol);
        let read_result = tcp_packet.read(&ipv4_packet);
        assert!(read_result.is_ok(), "TCP packet read failed when it should not have");

        if read_result.is_ok() {
            assert_eq!(tcp_packet.src_addr, expected_src_addr);
            assert_eq!(tcp_packet.dst_addr, expected_dst_addr);
            assert_eq!(tcp_packet.protocol, expected_protocol);
            assert_eq!(tcp_packet.tcp_length, expected_tcp_length);
            assert_eq!(tcp_packet.local_port, expected_local_port);
            assert_eq!(tcp_packet.remote_port, expected_remote_port);
            assert_eq!(tcp_packet.seq_number, expected_seq_number);
            assert_eq!(tcp_packet.ack_number, expected_ack_number);
            assert_eq!(tcp_packet.offset, expected_data_offset);
            assert_eq!(tcp_packet.flag_cwr, expected_flag & (0b1 << 7) != 0);
            assert_eq!(tcp_packet.flag_ece, expected_flag & (0b1 << 6) != 0);
            assert_eq!(tcp_packet.flag_urg, expected_flag & (0b1 << 5) != 0);
            assert_eq!(tcp_packet.flag_ack, expected_flag & (0b1 << 4) != 0);
            assert_eq!(tcp_packet.flag_psh, expected_flag & (0b1 << 3) != 0);
            assert_eq!(tcp_packet.flag_rst, expected_flag & (0b1 << 2) != 0);
            assert_eq!(tcp_packet.flag_syn, expected_flag & (0b1 << 1) != 0);
            assert_eq!(tcp_packet.flag_fin, expected_flag & (0b1 << 0) != 0);
            assert_eq!(tcp_packet.windows_size, expected_window);
            assert_eq!(tcp_packet.checksum, expected_checksum);
            assert_eq!(tcp_packet.urg_pointer, expected_urg_pointer);
            assert_eq!(tcp_packet.option, expected_option);
            assert_eq!(tcp_packet.valid, expected_valid);

            let payload_data = decode(tcp_payload_hex).expect("Failed to decode payload hex string");
            assert_eq!(tcp_packet.payload, payload_data, "TCP payload does not match");
        }
    }
    #[rstest]
    // too short packet, missing bytes from checksum and payload
    #[case("4500003450bf40008006ff4b0a000091ba0fe618d4a40050dd65a54700000000800220004cbb0000020405b401030302010104")]
    // bad tcp checksum, last byte is 01 but should be 02
    #[case("4500003450bf40008006ff4b0a000091ba0fe618d4a40050dd65a54700000000800220004cbb0000020405b40103030201010401")]
    fn test_tcp_packet_read_error(
        #[case] encoded_packet: &str,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        let _ = ipv4_packet.read(&packet_data);
        let mut tcp_packet = TcpPacket::new();
        let result = tcp_packet.read(&ipv4_packet);

        assert!(result.is_err(), "Expected an error for incorrect TCP header");
    }
}
