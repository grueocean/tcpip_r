use crate::l2_l3::ip::Ipv4Packet;
use anyhow::{Context, Result};

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
    pub option: Vec<u8>,
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
            option: Vec::new(),
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

        let flag = u16::from_be_bytes(ipv4_packet.payload[14..15].try_into()?);
        self.flag_cwr = (flag >> 7 & 0b1) == 0b1;
        self.flag_ece = (flag >> 6 & 0b1) == 0b1;
        self.flag_urg = (flag >> 5 & 0b1) == 0b1;
        self.flag_ack = (flag >> 4 & 0b1) == 0b1;
        self.flag_psh = (flag >> 3 & 0b1) == 0b1;
        self.flag_rst = (flag >> 2 & 0b1) == 0b1;
        self.flag_syn = (flag >> 1 & 0b1) == 0b1;
        self.flag_fin = (flag & 0b1) == 0b1;

        self.windows_size = u16::from_be_bytes(ipv4_packet.payload[16..18].try_into()?);
        self.checksum = u16::from_be_bytes(ipv4_packet.payload[18..20].try_into()?);
        self.urg_pointer = u16::from_be_bytes(ipv4_packet.payload[20..22].try_into()?);
        self.option = ipv4_packet.payload[22..offset_bytes].to_vec();
        self.payload = ipv4_packet.payload[offset_bytes..].to_vec();

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
        header.extend(&self.option);

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

    fn create_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        packet
    }
}