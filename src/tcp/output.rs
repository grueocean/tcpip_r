use crate::{
    l2_l3::{defs::Ipv4Type, ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration}},
    tcp::{
        self, defs::{TcpError, TcpStatus}, packet::{TcpFlag, TcpPacket, TCP_DEFAULT_WINDOW_SCALE},
        usrreq::{TcpStack}, input::{TcpConnection, seq_in_range, seq_less_than, seq_less_equal, seq_greater_than, seq_greater_equal},
        timer::{TcpTimer, update_retransmission_param, TCP_SRTT_SHIFT, TCP_RTTVAR_SHIFT}
    }
};
use anyhow::{Context, Result};
use std::time::{Instant};

impl TcpStack {
        // It behaves as an entry point for sending packets, like tcp_output in BSD.
        pub fn send_handler(
            &self,
            conn: &mut TcpConnection
        ) -> Result<usize> {
            match &conn.status {
                TcpStatus::SynSent => { Ok(self.send_handler_syn_sent(conn).context("send_handler_syn_sent failed.")?) }
                TcpStatus::SynRcvd => { Ok(self.send_handler_syn_rcvd(conn).context("send_handler_syn_rcvd failed.")?) }
                TcpStatus::Established => { Ok(self.send_handler_established(conn).context("send_handler_established failed.")?) }
                other => {
                    anyhow::bail!("Send handler for {} is not implemented.", other);
                }
            }
        }

        pub fn send_handler_syn_sent(
            &self,
            conn: &mut TcpConnection
        ) -> Result<usize> {
            let mut syn_packet = TcpPacket::new_out_packet(conn, None)?;
            syn_packet.option.mss = Some(conn.recv_vars.recv_mss as u16);
            self.send_tcp_packet(syn_packet)?;
            Ok(0)
        }

        pub fn send_handler_syn_rcvd(
            &self,
            conn: &mut TcpConnection
        ) -> Result<usize> {
            let syn_ack_packet = TcpPacket::new_out_packet(conn, None)?;
            self.send_tcp_packet(syn_ack_packet)?;
            Ok(0)
        }

        pub fn send_handler_established(
            &self,
            conn: &mut TcpConnection
        ) -> Result<usize> {
            let send_una = conn.send_vars.unacknowledged;
            let send_nxt = conn.send_vars.next_sequence_num;
            let send_wnd = conn.send_vars.get_scaled_send_window_size();
            let send_mss = conn.send_vars.send_mss;
            let new_data = conn.send_queue.payload.len() - send_nxt.wrapping_sub(send_una) as usize;
            let next_send_nxt = send_una.wrapping_add(conn.send_queue.payload.len() as u32);
            if !conn.flag.no_delay && send_una != send_nxt && ((new_data as u16) < send_mss || send_wnd < send_mss as usize) && !conn.flag.ack_now {
                log::debug!(
                    "[status={} {}] We won't send a datagram here based on Nagle's algo. SND.UNA={} SND.NXT={} SND.WND={} SND.MSS={} PENDING_DATAGRAM_LENGTH={}",
                    conn.status, conn.print_address(), send_una, send_nxt, send_wnd, send_mss, new_data
                );
                Ok(0)
            } else if !conn.flag.snd_from_una {
                loop {
                    if next_send_nxt == conn.send_vars.next_sequence_num && conn.last_snd_ack == conn.recv_vars.next_sequence_num && !conn.flag.ack_now {
                        log::debug!("Nothing to send. snd_from_una={} SND.UNA=SND.NXT={} RCV.NXT={}", conn.flag.snd_from_una, next_send_nxt, conn.last_snd_ack);
                        break;
                    }
                    let datagram = TcpPacket::new_out_packet(conn, None).context("Failed to create a datagram packet.")?;
                    let datagram_size = datagram.payload.len() as u32;
                    let snd_seq = datagram.seq_number;
                    let snd_ack = datagram.ack_number;
                    self.send_tcp_packet(datagram).map_err(|e| {
                        // We need to update SND.NXT even if a packet failed to be sent to trigger retransmission.
                        conn.send_vars.next_sequence_num = conn.send_vars.next_sequence_num.wrapping_add(datagram_size);
                        anyhow::anyhow!(e)
                    })?;
                    if conn.rtt_start.is_none() && datagram_size > 0 {
                        conn.rtt_start = Some(Instant::now());
                        conn.rtt_seq = Some(snd_seq);
                    }
                    conn.send_vars.next_sequence_num = conn.send_vars.next_sequence_num.wrapping_add(datagram_size);
                    conn.last_snd_ack = snd_ack;
                    if next_send_nxt == conn.send_vars.next_sequence_num { break; };
                }
                Ok(0)
            } else {
                let mut start_seq = conn.send_vars.unacknowledged;
                loop {
                    if next_send_nxt == conn.send_vars.next_sequence_num && conn.last_snd_ack == conn.recv_vars.next_sequence_num && !conn.flag.ack_now {
                        log::debug!("Nothing to send. snd_from_una={} SND.UNA=SND.NXT={} RCV.NXT={}", conn.flag.snd_from_una, next_send_nxt, conn.last_snd_ack);
                        break;
                    }
                    let datagram = TcpPacket::new_out_packet(conn, Some(start_seq)).context("Failed to create a datagram packet.")?;
                    let datagram_size = datagram.payload.len() as u32;
                    let snd_seq = datagram.seq_number;
                    let snd_ack = datagram.ack_number;
                    // We don't need to update SND.NXT because retransmission will trigger anyway.
                    self.send_tcp_packet(datagram)?;
                    if conn.rtt_start.is_none() && datagram_size > 0 {
                        conn.rtt_start = Some(Instant::now());
                        conn.rtt_seq = Some(snd_seq);
                    }
                    start_seq = start_seq.wrapping_add(datagram_size);
                    if seq_greater_equal(start_seq, conn.send_vars.next_sequence_num) {
                        conn.send_vars.next_sequence_num = start_seq;
                    }
                    conn.last_snd_ack = snd_ack;
                    if next_send_nxt == conn.send_vars.next_sequence_num { break; };
                }
                Ok(0)
            }
        }

        pub fn send_tcp_packet(&self, mut tcp_packet: TcpPacket) -> Result<()> {
            let mut ipv4_packet = Ipv4Packet::new();
            ipv4_packet.protocol = u8::from(Ipv4Type::TCP);
            ipv4_packet.dst_addr = tcp_packet.dst_addr;
            ipv4_packet.payload = tcp_packet.create_packet();
            let l3 = get_global_l3stack(self.config.clone())?;
            l3.l3interface.send(ipv4_packet)?;
            log::trace!("Send a tcp packet. {}", tcp_packet.print_general_info());
            Ok(())
        }

        pub fn send_tcp_packet_safe(&self, mut tcp_packet: TcpPacket) -> Result<()> {
            let mut ipv4_packet = Ipv4Packet::new();
            ipv4_packet.protocol = u8::from(Ipv4Type::TCP);
            ipv4_packet.dst_addr = tcp_packet.dst_addr;
            ipv4_packet.payload = tcp_packet.create_packet();
            let l3 = get_global_l3stack(self.config.clone())?;
            if let Err(e) = l3.l3interface.send(ipv4_packet) {
                log::warn!("Failed to send a tcp packet. Err: {e:?}");
            };
            Ok(())
        }

        pub fn send_back_rst_syn(&self, original_packet: &TcpPacket) -> Result<()> {
            let rst_packet = original_packet.create_rst_syn();
            self.send_tcp_packet(rst_packet)?;
            Ok(())
        }

        pub fn send_back_rst_ack(&self, original_packet: &TcpPacket) -> Result<()> {
            let rst_packet = original_packet.create_rst_ack();
            self.send_tcp_packet(rst_packet)?;
            Ok(())
        }
}