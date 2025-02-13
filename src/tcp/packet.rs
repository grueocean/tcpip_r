use crate::l2_l3::{defs::Ipv4Type, ip::Ipv4Packet};
use crate::tcp::{
    defs::{TcpOptionKind, TcpStatus},
    input::TcpConnection,
};
use anyhow::{Context, Result};
use bitflags::bitflags;
use std::{
    cmp::{max, min},
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    sync::MutexGuard,
    time::{Duration, Instant},
};

// Tcp header max size is 60 (15*4) bytes because Max Data Offset is 15 (0b1111).
const TCP_HEADER_LENGTH_BASIC: usize = 20;
pub const TCP_DEFAULT_WINDOW_SCALE: u8 = 7;

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
#[derive(Default, Debug)]
pub struct TcpPacket {
    pub src_addr: [u8; 4], // pesudo header
    pub dst_addr: [u8; 4], // pesudo header
    pub protocol: u8,      // pesudo header
    pub tcp_length: u16,   // pesudo header
    pub local_port: u16,
    pub remote_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub offset: u8, // 4 bit (payload begins from 4*offset bytes)
    pub flag: TcpFlag,
    pub window_size: u16,
    pub checksum: u16,
    pub urg_pointer: u16,
    pub option_raw: Vec<u8>,
    pub option: TcpOption,
    pub payload: Vec<u8>,
    pub valid: bool,
}

impl TcpPacket {
    pub fn new() -> Self {
        Self {
            option_raw: Vec::new(),
            option: TcpOption::new(),
            payload: Vec::new(),
            ..Default::default()
        }
    }

    pub fn read(&mut self, ipv4_packet: &Ipv4Packet) -> Result<bool> {
        let tcp_len = ipv4_packet.payload.len();
        if tcp_len > 0xffff {
            anyhow::bail!(
                "TCP packet payload length is {}, must be smaller than 65536+1.",
                tcp_len
            );
        } else if tcp_len < TCP_HEADER_LENGTH_BASIC {
            anyhow::bail!(
                "TCP packet payload length is {}, must be larger than header length ({}).",
                tcp_len,
                TCP_HEADER_LENGTH_BASIC
            );
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
        anyhow::ensure!(
            tcp_len >= offset_bytes,
            "TCP packet payload length is {}, but header's data offset indicate {}.",
            tcp_len,
            offset_bytes
        );
        self.flag =
            TcpFlag::from_bits_retain(u8::from_be_bytes(ipv4_packet.payload[13..14].try_into()?));
        self.window_size = u16::from_be_bytes(ipv4_packet.payload[14..16].try_into()?);
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
                let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
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
            log::debug!(
                "Unexpected tcp header. Header checksum is 0x{:x} but is expected 0x{:x}.",
                self.checksum,
                expected_checksum
            );
            anyhow::bail!(
                "TCP Header has bad checksum 0x{:x}, expected 0x{:x}.",
                self.checksum,
                expected_checksum
            );
        }

        Ok(self.valid)
    }

    pub fn create_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.local_port.to_be_bytes());
        header.extend_from_slice(&self.remote_port.to_be_bytes());
        header.extend_from_slice(&self.seq_number.to_be_bytes());
        header.extend_from_slice(&self.ack_number.to_be_bytes());

        let offset_flags = self.flag.bits() as u16 | ((self.offset as u16) << 12) as u16;
        header.extend_from_slice(&offset_flags.to_be_bytes());

        header.extend_from_slice(&self.window_size.to_be_bytes());
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

    pub fn create_packet(&mut self) -> Vec<u8> {
        self.set_packet_params();
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.create_header());
        packet.extend_from_slice(&self.payload);

        packet
    }

    fn set_option_raw(&mut self) {
        self.option_raw = self.option.create_packet_option();
    }

    fn set_offset(&mut self) {
        self.offset = ((TCP_HEADER_LENGTH_BASIC + self.option_raw.len()) / 4) as u8;
    }

    fn set_tcp_length(&mut self) {
        self.tcp_length =
            (TCP_HEADER_LENGTH_BASIC + self.option_raw.len() + self.payload.len()) as u16;
    }

    fn set_packet_params(&mut self) {
        // set option_raw, tcp_length, offset and checksum
        self.set_option_raw();
        self.set_offset();
        self.set_tcp_length();
        self.calc_header_checksum_and_set()
    }

    pub fn create_reply_base(&self) -> Self {
        let mut reply = Self::new();
        reply.src_addr = self.dst_addr;
        reply.dst_addr = self.src_addr;
        reply.protocol = u8::from(Ipv4Type::TCP);
        reply.local_port = self.remote_port;
        reply.remote_port = self.local_port;
        reply
    }

    pub fn create_rst_syn(&self) -> Self {
        let mut rst = self.create_reply_base();
        rst.ack_number = self.seq_number + 1;
        rst.flag = TcpFlag::RST | TcpFlag::SYN;
        rst
    }

    // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> rfc9293
    pub fn create_rst_ack(&self) -> Self {
        let mut rst = self.create_reply_base();
        rst.seq_number = 0;
        rst.seq_number = self.seq_number.wrapping_add(self.payload.len() as u32);
        rst.flag = TcpFlag::RST | TcpFlag::ACK;
        rst
    }

    // <SEQ=SEG.ACK><CTL=RST> rfc9293
    pub fn create_rst(&self) -> Self {
        let mut rst = self.create_reply_base();
        rst.seq_number = self.ack_number;
        rst.flag = TcpFlag::RST;
        rst
    }

    pub fn new_out_packet(conn: &mut TcpConnection, start_seq: Option<u32>) -> Result<Self> {
        match &conn.status {
            TcpStatus::SynSent => {
                Ok(Self::new_syn_sent(conn).context("Failed to create syn_sent packet.")?)
            }
            TcpStatus::SynRcvd => {
                Ok(Self::new_syn_rcvd(conn).context("Failed to create syn_rcvd packet.")?)
            }
            TcpStatus::Established => {
                if !conn.send_flag.snd_from_una {
                    Ok(Self::new_established_next(conn)
                        .context("Failed to create established_next packet.")?)
                } else {
                    if let Some(start_seq) = start_seq {
                        Ok(Self::new_established_rexmt(conn, start_seq)
                            .context("Failed to create established_rexmt packet.")?)
                    } else {
                        anyhow::bail!("Retransmission should specify start_seq.");
                    }
                }
            }
            TcpStatus::FinWait1 | TcpStatus::LastAck => Ok(Self::new_datagram_fin(conn)
                .context("Failed to create new_datagram_fin packet.")?),
            TcpStatus::CloseWait => {
                Ok(Self::new_close_wait(conn).context("Failed to create close_wait packet.")?)
            }
            TcpStatus::FinWait2 | TcpStatus::Closing | TcpStatus::TimeWait => {
                Ok(Self::new_ack(conn).context("Failed to create new_ack packet.")?)
            }
            other => {
                anyhow::bail!("Cannot generate packet from connection {}.", other);
            }
        }
    }

    pub fn new_syn_sent(conn: &TcpConnection) -> Result<Self> {
        let mut syn_sent = Self::new();
        syn_sent.option.set_default_option()?;
        syn_sent.src_addr = conn.src_addr.octets();
        syn_sent.dst_addr = conn.dst_addr.octets();
        syn_sent.protocol = u8::from(Ipv4Type::TCP);
        syn_sent.local_port = conn.local_port;
        syn_sent.remote_port = conn.remote_port;
        syn_sent.seq_number = conn.send_vars.unacknowledged;
        syn_sent.flag = TcpFlag::SYN;
        syn_sent.window_size = conn.get_recv_window_for_syn_pkt();
        syn_sent.option.window_scale = Some(TCP_DEFAULT_WINDOW_SCALE);
        syn_sent.option.mss = Some(conn.send_vars.send_mss);
        Ok(syn_sent)
    }

    pub fn new_syn_rcvd(conn: &TcpConnection) -> Result<Self> {
        let mut syn_rcvd = Self::new();
        syn_rcvd.option.set_default_option()?;
        syn_rcvd.src_addr = conn.src_addr.octets();
        syn_rcvd.dst_addr = conn.dst_addr.octets();
        syn_rcvd.protocol = u8::from(Ipv4Type::TCP);
        syn_rcvd.local_port = conn.local_port;
        syn_rcvd.remote_port = conn.remote_port;
        syn_rcvd.seq_number = conn.send_vars.unacknowledged;
        syn_rcvd.ack_number = conn.recv_vars.next_sequence_num;
        syn_rcvd.flag = TcpFlag::SYN | TcpFlag::ACK;
        syn_rcvd.window_size = conn.get_recv_window_for_syn_pkt();
        if conn.send_vars.window_shift != 0 {
            syn_rcvd.option.window_scale = Some(TCP_DEFAULT_WINDOW_SCALE);
        }
        syn_rcvd.option.mss = Some(conn.send_vars.send_mss);
        Ok(syn_rcvd)
    }

    // create datagram packet starting from SND.NXT
    fn new_datagram_next(conn: &mut TcpConnection) -> Result<(Self, bool)> {
        let mut datagram = Self::new();
        datagram.option.set_default_option()?;
        datagram.src_addr = conn.src_addr.octets();
        datagram.dst_addr = conn.dst_addr.octets();
        datagram.protocol = u8::from(Ipv4Type::TCP);
        datagram.local_port = conn.local_port;
        datagram.remote_port = conn.remote_port;
        datagram.seq_number = conn.send_vars.next_sequence_num;
        datagram.ack_number = conn.recv_vars.next_sequence_num;
        datagram.window_size = conn.get_recv_window_for_pkt();
        let start_offset = conn
            .send_vars
            .next_sequence_num
            .wrapping_sub(conn.send_vars.unacknowledged) as usize;
        let window_limit_payload_len = conn.send_vars.unacknowledged as usize
            + conn.send_vars.get_scaled_send_window_size()
            - conn.send_vars.next_sequence_num as usize;
        let remain_payload_len = conn.send_queue.payload.len() - start_offset;
        let payload_len = *[
            remain_payload_len,
            conn.send_vars.send_mss as usize,
            window_limit_payload_len,
        ]
        .iter()
        .min()
        .unwrap();
        let end_offset = start_offset + payload_len;
        datagram.payload = conn.send_queue.payload[start_offset..end_offset].to_vec();
        Ok((
            datagram,
            remain_payload_len == payload_len || window_limit_payload_len == payload_len,
        ))
    }

    // create datagram packet starting from start_seq
    fn new_datagram_rexmt(conn: &mut TcpConnection, start_seq: u32) -> Result<(Self, bool)> {
        let mut datagram = Self::new();
        datagram.option.set_default_option()?;
        datagram.src_addr = conn.src_addr.octets();
        datagram.dst_addr = conn.dst_addr.octets();
        datagram.protocol = u8::from(Ipv4Type::TCP);
        datagram.local_port = conn.local_port;
        datagram.remote_port = conn.remote_port;
        datagram.seq_number = start_seq;
        datagram.ack_number = conn.recv_vars.next_sequence_num;
        datagram.window_size = conn.get_recv_window_for_pkt();
        let start_offset = start_seq.wrapping_sub(conn.send_vars.unacknowledged) as usize;
        let window_limit_payload_len = conn.send_vars.unacknowledged as usize
            + conn.send_vars.get_scaled_send_window_size()
            - start_seq as usize;
        let remain_payload_len = conn.send_queue.payload.len() - start_offset;
        let payload_len = *[
            remain_payload_len,
            conn.send_vars.send_mss as usize,
            window_limit_payload_len,
        ]
        .iter()
        .min()
        .unwrap();
        let end_offset = start_offset + payload_len;
        datagram.payload = conn.send_queue.payload[start_offset..end_offset].to_vec();
        Ok((datagram, remain_payload_len == payload_len))
    }

    pub fn new_established_next(conn: &mut TcpConnection) -> Result<Self> {
        let (mut datagram, _) = Self::new_datagram_next(conn)?;
        datagram.flag = TcpFlag::ACK;
        Ok(datagram)
    }

    pub fn new_fin(conn: &TcpConnection, fin_seq: u32) -> Result<Self> {
        let mut fin = Self::new();
        fin.option.set_default_option()?;
        fin.src_addr = conn.src_addr.octets();
        fin.dst_addr = conn.dst_addr.octets();
        fin.protocol = u8::from(Ipv4Type::TCP);
        fin.local_port = conn.local_port;
        fin.remote_port = conn.remote_port;
        fin.seq_number = fin_seq;
        fin.ack_number = conn.recv_vars.next_sequence_num;
        fin.window_size = conn.get_recv_window_for_pkt();
        fin.flag = TcpFlag::ACK | TcpFlag::FIN;
        Ok(fin)
    }

    pub fn new_established_rexmt(conn: &mut TcpConnection, start_seq: u32) -> Result<Self> {
        let (mut datagram, _) = Self::new_datagram_rexmt(conn, start_seq)?;
        datagram.flag = TcpFlag::ACK;
        Ok(datagram)
    }

    pub fn new_datagram_fin(conn: &mut TcpConnection) -> Result<Self> {
        if let Some(fin_seq) = conn.fin_seq {
            Ok(Self::new_fin(conn, fin_seq)?)
        } else {
            let (mut fin, sent_all) = Self::new_datagram_next(conn)?;
            if sent_all {
                fin.flag = TcpFlag::ACK | TcpFlag::FIN;
            } else {
                fin.flag = TcpFlag::ACK;
            }
            Ok(fin)
        }
    }

    pub fn new_close_wait(conn: &mut TcpConnection) -> Result<Self> {
        let (mut ack_of_fin, _) = Self::new_datagram_next(conn)?;
        // +1 for fin
        ack_of_fin.ack_number = ack_of_fin.ack_number.wrapping_add(1);
        Ok(ack_of_fin)
    }

    pub fn new_ack(conn: &TcpConnection) -> Result<Self> {
        let mut ack = Self::new();
        ack.option.set_default_option()?;
        ack.src_addr = conn.src_addr.octets();
        ack.dst_addr = conn.dst_addr.octets();
        ack.protocol = u8::from(Ipv4Type::TCP);
        ack.local_port = conn.local_port;
        ack.remote_port = conn.remote_port;
        ack.seq_number = conn.send_vars.next_sequence_num;
        ack.ack_number = conn.recv_vars.next_sequence_num;
        ack.window_size = conn.get_recv_window_for_pkt();
        ack.flag = TcpFlag::ACK;
        Ok(ack)
    }

    pub fn print_general_info(&self) -> String {
        format!(
            "SEGINFO: SRC={}:{} DST={}:{} SEQ={} ACK={} LENGTH={} WND(RAW)={} FLAG={:?}",
            Ipv4Addr::from(self.src_addr),
            self.local_port,
            Ipv4Addr::from(self.dst_addr),
            self.remote_port,
            self.seq_number,
            self.ack_number,
            self.payload.len(),
            self.window_size,
            self.flag
        )
    }
}

bitflags! {
    #[derive(Clone, Default, Debug, PartialEq)]
    pub struct TcpFlag: u8 {
        const FIN = 0b00_00_00_01; // No more data from sender.
        const SYN = 0b00_00_00_10; // Synchronize sequence numbers.
        const RST = 0b00_00_01_00; // Reset the connection.
        const PSH = 0b00_00_10_00; // Push function
        const ACK = 0b00_01_00_00; // Acknowledgment field
        const URG = 0b00_10_00_00; // Urgent pointer field
        const ECE = 0b01_00_00_00; // ECN-Echo
        const CWR = 0b10_00_00_00; // Congestion Window Reduced
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct TcpOption {
    pub mss: Option<u16>,              // kind=2 Maximum Segment Size  2 bytes
    pub window_scale: Option<u8>,      // kind=3 Window Scale Option   1 bytes
    pub sack_permitted: bool, // kind=4 Sack-Permitted Option 0 bytes (only kind and length=2)
    pub sack: Option<Vec<(u32, u32)>>, // kind=5 Sack Option           8 bytes * n
    pub timestamps: Option<TcpOptionTimestamp>, // kind=8 Timestamps Option     4 bytes * 2
}

impl TcpOption {
    pub fn new() -> Self {
        Self {
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack: None,
            timestamps: None,
        }
    }

    pub fn read(&mut self, option: &Vec<u8>) -> Result<()> {
        let mut offset: usize = 0;
        let length = option.len();
        while offset < length {
            let kind = u8::from_be_bytes(option[offset..offset + 1].try_into()?);
            match TcpOptionKind::from(kind) {
                TcpOptionKind::EndOption => {
                    anyhow::ensure!(
                        offset + 1 == length,
                        "EndOption offset is {} but option length is {}.",
                        offset,
                        length
                    );
                    offset += 1;
                }
                TcpOptionKind::NoOperation => {
                    offset += 1;
                }
                TcpOptionKind::MaxSegmentSize => {
                    anyhow::ensure!(
                        offset + 4 <= length,
                        "MaxSegmentSize needs 4 bytes but only {} bytes left.",
                        length - offset
                    );
                    let len = u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?);
                    anyhow::ensure!(
                        len == 4,
                        "Length field of MaxSegmentSize must be 4 but is {}.",
                        len
                    );
                    self.mss = Some(u16::from_be_bytes(
                        option[offset + 2..offset + 4].try_into()?,
                    ));
                    offset += 4;
                }
                TcpOptionKind::WindowScale => {
                    anyhow::ensure!(
                        offset + 3 <= length,
                        "WindowScale needs 3 bytes but only {} bytes left.",
                        length - offset
                    );
                    let len = u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?);
                    anyhow::ensure!(
                        len == 3,
                        "Length field of WindowScale must be 3 but is {}.",
                        len
                    );
                    self.window_scale = Some(u8::from_be_bytes(
                        option[offset + 2..offset + 3].try_into()?,
                    ));
                    offset += 3;
                }
                TcpOptionKind::SackPermission => {
                    anyhow::ensure!(
                        offset + 2 <= length,
                        "SackPermission needs 2 bytes but only {} bytes left.",
                        length - offset
                    );
                    let len = u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?);
                    anyhow::ensure!(
                        len == 2,
                        "Length field of WindowScale must be 2 but is {}.",
                        len
                    );
                    self.sack_permitted = true;
                    offset += 2;
                }
                TcpOptionKind::SackOption => {
                    anyhow::ensure!(
                        offset + 2 <= length,
                        "SackOption needs 2 bytes but only {} bytes left.",
                        length - offset
                    );
                    let len =
                        u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?) as usize;
                    anyhow::ensure!(
                        offset + len <= length,
                        "Length field of SackOption is {} but only {} bytes left.",
                        len,
                        length - offset
                    );
                    anyhow::ensure!(
                        (length - offset - 2) % 8 == 0,
                        "SackOption payload must be 8 bytes aligned but len-2 is {}.",
                        len - 2
                    );
                    for i in (offset + 2..offset + len).step_by(8) {
                        if let Some(sack) = self.sack.as_mut() {
                            sack.push((
                                u32::from_be_bytes(option[i..i + 4].try_into()?),
                                u32::from_be_bytes(option[i + 4..i + 8].try_into()?),
                            ));
                        } else {
                            let mut new_sack = Vec::new();
                            new_sack.push((
                                u32::from_be_bytes(option[i..i + 4].try_into()?),
                                u32::from_be_bytes(option[i + 4..i + 8].try_into()?),
                            ));
                            self.sack = Some(new_sack);
                        }
                    }
                    offset += len;
                }
                TcpOptionKind::Timestamp => {
                    anyhow::ensure!(
                        offset + 10 <= length,
                        "Timestamp needs 10 bytes but only {} bytes left.",
                        length - offset
                    );
                    let len = u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?);
                    anyhow::ensure!(
                        len == 10,
                        "Length field of Timestamp must be 10 but is {}.",
                        len
                    );
                    self.timestamps = Some(TcpOptionTimestamp {
                        ts_value: u32::from_be_bytes(option[offset + 2..offset + 6].try_into()?),
                        ts_echo_reply: u32::from_be_bytes(
                            option[offset + 6..offset + 10].try_into()?,
                        ),
                    });
                    offset += 10;
                }
                TcpOptionKind::Unknown => {
                    log::debug!("Unknown tcp option. kind: {}", kind);
                    anyhow::ensure!(offset + 2 <= length, "This option kind is unknown, at least need 2 bytes but only {} bytes left.", length - offset);
                    let len =
                        u8::from_be_bytes(option[offset + 1..offset + 2].try_into()?) as usize;
                    if len > 2 {
                        anyhow::ensure!(
                            offset + len <= length,
                            "Length field of unkown option is {} but only {} bytes left.",
                            len,
                            length - offset
                        );
                    }
                    offset += len;
                }
            }
        }

        Ok(())
    }

    pub fn set_default_option(&mut self) -> Result<()> {
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
                packet.extend_from_slice(&left.to_be_bytes());
                packet.extend_from_slice(&right.to_be_bytes());
            }
        }
        if let Some(TcpOptionTimestamp {
            ts_value,
            ts_echo_reply,
        }) = self.timestamps
        {
            packet.push(u8::from(TcpOptionKind::Timestamp));
            packet.push(10);
            packet.extend_from_slice(&ts_value.to_be_bytes());
            packet.extend_from_slice(&ts_echo_reply.to_be_bytes());
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
    ts_value: u32,      // 4 bytes
    ts_echo_reply: u32, // 4 bytes
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use hex::decode;
    use rstest::rstest;

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
        #[case] expected_valid: bool,
    ) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        assert!(
            ipv4_packet.read(&packet_data).is_ok(),
            "Failed to read IPv4 packet"
        );

        let mut tcp_packet = TcpPacket::new();
        assert_eq!(ipv4_packet.protocol, expected_protocol);
        let read_result = tcp_packet.read(&ipv4_packet);
        assert!(
            read_result.is_ok(),
            "TCP packet read failed when it should not have"
        );

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
            assert_eq!(tcp_packet.flag, TcpFlag::from_bits_retain(expected_flag));
            assert_eq!(tcp_packet.window_size, expected_window);
            assert_eq!(tcp_packet.checksum, expected_checksum);
            assert_eq!(tcp_packet.urg_pointer, expected_urg_pointer);
            assert_eq!(tcp_packet.option, expected_option);
            assert_eq!(tcp_packet.valid, expected_valid);

            let payload_data =
                decode(tcp_payload_hex).expect("Failed to decode payload hex string");
            assert_eq!(
                tcp_packet.payload, payload_data,
                "TCP payload does not match"
            );
        }
    }
    #[rstest]
    // too short packet, missing bytes from checksum and payload
    #[case("4500003450bf40008006ff4b0a000091ba0fe618d4a40050dd65a54700000000800220004cbb0000020405b401030302010104")]
    // bad tcp checksum, last byte is 01 but should be 02
    #[case("4500003450bf40008006ff4b0a000091ba0fe618d4a40050dd65a54700000000800220004cbb0000020405b40103030201010401")]
    fn test_tcp_packet_read_error(#[case] encoded_packet: &str) {
        let packet_data = decode(encoded_packet).expect("Failed to decode hex string");
        let mut ipv4_packet = Ipv4Packet::new();
        let _ = ipv4_packet.read(&packet_data);
        let mut tcp_packet = TcpPacket::new();
        let result = tcp_packet.read(&ipv4_packet);

        assert!(
            result.is_err(),
            "Expected an error for incorrect TCP packet"
        );
    }
}
