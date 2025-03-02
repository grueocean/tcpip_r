use crate::{
    l2_l3::{
        defs::Ipv4Type,
        ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration},
    },
    tcp::{
        self,
        defs::{TcpError, TcpStatus},
        input::{
            seq_greater_equal, seq_greater_than, seq_in_range, seq_less_equal, seq_less_than,
            TcpConnection,
        },
        packet::{TcpFlag, TcpPacket, TCP_DEFAULT_WINDOW_SCALE},
        timer::{update_retransmission_param, TcpTimer, TCP_RTTVAR_SHIFT, TCP_SRTT_SHIFT},
        usrreq::TcpStack,
    },
};
use anyhow::{Context, Result};
use std::{cmp::min, time::Instant};

const TCP_SEND_LOOP_MAX: usize = 1000;

impl TcpStack {
    // It behaves as an entry point for sending packets, like tcp_output in BSD.
    pub fn send_handler(&self, conn: &mut TcpConnection) -> Result<usize> {
        let result = match &conn.status {
            TcpStatus::SynSent => self
                .send_handler_syn_sent(conn)
                .context("send_handler_syn_sent failed."),
            TcpStatus::SynRcvd => self
                .send_handler_syn_rcvd(conn)
                .context("send_handler_syn_rcvd failed."),
            TcpStatus::Established | TcpStatus::CloseWait => self
                .send_handler_datagram(conn)
                .context("send_handler_datagram failed."),
            TcpStatus::FinWait1 | TcpStatus::LastAck => self
                .send_handler_fin_or_ack(conn)
                .context("send_handler_fin_or_ack failed."),
            TcpStatus::FinWait2 | TcpStatus::Closing => self
                .send_handler_ack(conn)
                .context("send_handler_ack failed."),
            other => {
                conn.send_flag.init();
                anyhow::bail!("Send handler for {} is not implemented.", other);
            }
        };
        conn.send_flag.init();
        result
    }

    pub fn send_handler_syn_sent(&self, conn: &mut TcpConnection) -> Result<usize> {
        let mut syn_packet = TcpPacket::new_out_packet(conn, None)?;
        syn_packet.option.mss = Some(conn.recv_vars.recv_mss as u16);
        let snd_wnd = (syn_packet.window_size as usize) << conn.recv_vars.window_shift;
        let snd_ack = syn_packet.ack_number;
        self.send_tcp_packet(syn_packet)?;
        conn.last_sent_window = snd_wnd;
        conn.last_snd_ack = snd_ack;
        Ok(0)
    }

    pub fn send_handler_syn_rcvd(&self, conn: &mut TcpConnection) -> Result<usize> {
        let syn_ack_packet = TcpPacket::new_out_packet(conn, None)?;
        let snd_wnd = (syn_ack_packet.window_size as usize) << conn.recv_vars.window_shift;
        let snd_ack = syn_ack_packet.ack_number;
        self.send_tcp_packet(syn_ack_packet)?;
        conn.last_sent_window = snd_wnd;
        conn.last_snd_ack = snd_ack;
        Ok(0)
    }

    pub fn send_handler_datagram(&self, conn: &mut TcpConnection) -> Result<usize> {
        let send_una = conn.send_vars.unacknowledged;
        let send_nxt = conn.send_vars.next_sequence_num;
        let send_wnd = conn.send_vars.get_scaled_send_window_size();
        let send_mss = conn.send_vars.send_mss;
        let new_data = conn.send_queue.payload.len() - send_nxt.wrapping_sub(send_una) as usize;
        let next_send_nxt = send_una.wrapping_add(min(
            conn.send_queue.payload.len(),
            conn.send_vars.get_scaled_send_window_size(),
        ) as u32);
        let send_allowed = send_una.wrapping_add(send_wnd as u32);
        if conn.send_flag.ack_delayed && new_data == 0 {
            log::debug!(
                "[status={} {}] Delayed ack situation. (Not sending ack here.) RCV.NXT={}",
                conn.status,
                conn.print_address(),
                conn.recv_vars.next_sequence_num
            );
            Ok(0)
        } else if send_una != send_nxt
            && ((new_data as u16) < send_mss || send_wnd < send_mss as usize)
            && !conn.send_flag.ack_now
        {
            log::debug!(
                    "[status={} {}] We won't send a datagram here based on Nagle's algo. SND.UNA={} SND.NXT={} SND.WND={} SND.MSS={} PENDING_DATAGRAM_LENGTH={}",
                    conn.status, conn.print_address(), send_una, send_nxt, send_wnd, send_mss, new_data
                );
            Ok(0)
        } else if !conn.send_flag.snd_from_una {
            let mut loop_count: usize = 0;
            loop {
                anyhow::ensure!(
                    loop_count < TCP_SEND_LOOP_MAX,
                    "Tcp send loop count is {} should be lower than {}.",
                    loop_count,
                    TCP_SEND_LOOP_MAX
                );
                loop_count += 1;
                if next_send_nxt == conn.send_vars.next_sequence_num
                    && conn.last_snd_ack == conn.recv_vars.next_sequence_num
                    && !conn.send_flag.ack_now
                    && conn.get_recv_window_size() == conn.last_sent_window
                {
                    log::debug!(
                        "Nothing to send. snd_from_una={} SND.UNA=SND.NXT={} SND.WND={} RCV.NXT={} LAST.SND.ACK={} RCV.WND={} LAST.SENT.RCV.WND={}",
                        conn.send_flag.snd_from_una,
                        next_send_nxt,
                        conn.send_vars.get_scaled_send_window_size(),
                        conn.recv_vars.next_sequence_num,
                        conn.last_snd_ack,
                        conn.get_recv_window_size(),
                        conn.last_sent_window,
                    );
                    break;
                }
                let datagram = TcpPacket::new_out_packet(conn, None)
                    .context("Failed to create a datagram packet.")?;
                let datagram_size = datagram.payload.len() as u32;
                let snd_seq = datagram.seq_number;
                let snd_ack = datagram.ack_number;
                let snd_wnd = (datagram.window_size as usize) << conn.recv_vars.window_shift;
                self.send_tcp_packet(datagram).map_err(|e| {
                    // We need to update SND.NXT even if a packet failed to be sent to trigger retransmission.
                    conn.send_vars.next_sequence_num =
                        conn.send_vars.next_sequence_num.wrapping_add(datagram_size);
                    anyhow::anyhow!(e)
                })?;
                conn.last_sent_window = snd_wnd;
                if conn.timer.delayed_ack.timer_param.active {
                    conn.timer.delayed_ack.init();
                }
                if conn.rtt_start.is_none() && datagram_size > 0 {
                    conn.rtt_start = Some(Instant::now());
                    conn.rtt_seq = Some(snd_seq);
                }
                conn.send_vars.next_sequence_num = snd_seq.wrapping_add(datagram_size);
                conn.last_snd_ack = snd_ack;
                if next_send_nxt == conn.send_vars.next_sequence_num
                    || send_allowed == conn.send_vars.next_sequence_num
                {
                    break;
                };
            }
            Ok(0)
        } else {
            // Usually, it's done by retransmission timer.
            let mut loop_count: usize = 0;
            let mut start_seq = conn.send_vars.unacknowledged;
            loop {
                anyhow::ensure!(
                    loop_count < TCP_SEND_LOOP_MAX,
                    "Tcp send loop count is {} should be lower than {}.",
                    loop_count,
                    TCP_SEND_LOOP_MAX
                );
                loop_count += 1;
                if next_send_nxt == conn.send_vars.next_sequence_num
                    && conn.last_snd_ack == conn.recv_vars.next_sequence_num
                    && !conn.send_flag.ack_now
                    && conn.get_recv_window_size() == conn.last_sent_window
                {
                    log::debug!(
                        "Nothing to send. snd_from_una={} SND.UNA=SND.NXT={} SND.WND={} RCV.NXT={} LAST.SND.ACK={} RCV.WND={} LAST.SENT.RCV.WND={}",
                        conn.send_flag.snd_from_una,
                        next_send_nxt,
                        conn.send_vars.get_scaled_send_window_size(),
                        conn.recv_vars.next_sequence_num,
                        conn.last_snd_ack,
                        conn.get_recv_window_size(),
                        conn.last_sent_window,
                    );
                    break;
                }
                let datagram = TcpPacket::new_out_packet(conn, Some(start_seq))
                    .context("Failed to create a datagram packet.")?;
                let datagram_size = datagram.payload.len() as u32;
                let snd_seq = datagram.seq_number;
                let snd_ack = datagram.ack_number;
                let snd_wnd = (datagram.window_size as usize) << conn.recv_vars.window_shift;
                // We don't need to update SND.NXT even if a packet failed to be sent because retransmission will be triggered anyway.
                self.send_tcp_packet(datagram)?;
                conn.last_sent_window = snd_wnd;
                if conn.rtt_start.is_none() && datagram_size > 0 {
                    conn.rtt_start = Some(Instant::now());
                    conn.rtt_seq = Some(snd_seq);
                }
                if conn.timer.delayed_ack.timer_param.active {
                    conn.timer.delayed_ack.init();
                }
                start_seq = start_seq.wrapping_add(datagram_size);
                if seq_greater_equal(start_seq, conn.send_vars.next_sequence_num) {
                    conn.send_vars.next_sequence_num = start_seq;
                }
                conn.last_snd_ack = snd_ack;
                if next_send_nxt == conn.send_vars.next_sequence_num
                    || send_allowed == conn.send_vars.next_sequence_num
                {
                    break;
                };
            }
            Ok(0)
        }
    }

    // todo: handle the case if no SND.WND available before sending FIN
    pub fn send_handler_fin_or_ack(&self, conn: &mut TcpConnection) -> Result<usize> {
        let mut loop_count: usize = 0;
        loop {
            anyhow::ensure!(
                loop_count < TCP_SEND_LOOP_MAX,
                "Tcp send loop count is {} should be lower than {}.",
                loop_count,
                TCP_SEND_LOOP_MAX
            );
            loop_count += 1;
            let datagram = TcpPacket::new_out_packet(conn, None)
                .context("Failed to create a datagram/fin packet.")?;
            let datagram_size = datagram.payload.len() as u32;
            let snd_seq = datagram.seq_number;
            let snd_ack = datagram.ack_number;
            let snd_wnd = (datagram.window_size as usize) << conn.recv_vars.window_shift;
            let seg_fin = datagram.flag.contains(TcpFlag::FIN);
            if let Err(e) = self.send_tcp_packet(datagram) {
                log::warn!("Failed to send in send_handler_fin_or_ack. Err: {e}");
            }
            conn.last_sent_window = snd_wnd;
            if conn.rtt_start.is_none() && datagram_size > 0 {
                conn.rtt_start = Some(Instant::now());
                conn.rtt_seq = Some(snd_seq);
            }
            conn.send_vars.next_sequence_num = snd_seq.wrapping_add(datagram_size);
            conn.last_snd_ack = snd_ack;
            if seg_fin {
                conn.fin_seq_sent = Some(conn.send_vars.next_sequence_num);
                conn.send_vars.next_sequence_num = conn.send_vars.next_sequence_num.wrapping_add(1);
                break;
            }
        }
        Ok(0)
    }

    pub fn send_handler_ack(&self, conn: &mut TcpConnection) -> Result<usize> {
        let ack =
            TcpPacket::new_out_packet(conn, None).context("Failed to create an ack packet.")?;
        let snd_wnd = (ack.window_size as usize) << conn.recv_vars.window_shift;
        let snd_ack = ack.ack_number;
        if let Err(e) = self.send_tcp_packet(ack) {
            log::warn!("Failed to send in send_handler_ack. Err: {e}");
        }
        conn.last_sent_window = snd_wnd;
        conn.last_snd_ack = snd_ack;
        Ok(0)
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
        let rst_syn_packet = original_packet.create_rst_syn();
        self.send_tcp_packet(rst_syn_packet)?;
        Ok(())
    }

    pub fn send_back_rst_ack(&self, original_packet: &TcpPacket) -> Result<()> {
        let rst_ack_packet = original_packet.create_rst_ack();
        self.send_tcp_packet(rst_ack_packet)?;
        Ok(())
    }

    pub fn send_back_rst(&self, original_packet: &TcpPacket) -> Result<()> {
        let rst_packet = original_packet.create_rst();
        self.send_tcp_packet(rst_packet)?;
        Ok(())
    }
}
