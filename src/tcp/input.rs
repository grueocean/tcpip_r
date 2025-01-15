use crate::{
    l2_l3::{
        defs::Ipv4Type,
        ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration},
    },
    tcp::{
        self,
        defs::{TcpError, TcpStatus},
        input, output,
        packet::{TcpFlag, TcpPacket, TCP_DEFAULT_WINDOW_SCALE},
        timer::{update_retransmission_param, TcpTimer, TCP_RTTVAR_SHIFT, TCP_SRTT_SHIFT},
        usrreq::{TcpStack, TCP_MAX_SOCKET},
    },
};
use anyhow::{Context, Result};
use log;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::ops::Range;
use std::sync::{mpsc::channel, Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;
use std::{
    cmp::{max, min},
    collections::{HashMap, VecDeque},
    sync::MutexGuard,
    time::Duration,
};

const MAX_SEQ: u32 = u32::MAX;
// "The present global default is five minutes." rfc9293
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_MAX_CONCURRENT_SESSION: usize = 10;
const TCP_MAX_LISTEN_QUEUE: usize = TCP_MAX_CONCURRENT_SESSION * 3 / 2;
const TCP_DEFAULT_SEND_QUEUE_LENGTH: usize = 4096;
const TCP_DEFAULT_RECV_QUEUE_LENGTH: usize = 4096;
const TCP_RECV_QUEUE_WRAP: usize = 1 << 32;
const TCP_NO_DELAY: bool = false;
const TCP_DELAY_ACK: bool = true;
const FR_RCV_BUFF_RATIO: usize = 10;

impl TcpStack {
    pub fn receive_thread(&self) -> Result<()> {
        log::info!("Starting TcpStack receive_thread.");
        let l3 = get_global_l3stack(self.config.clone())?;
        let (tcp_send_channel, tcp_recv_channel) = channel();
        l3.register_protocol(u8::from(Ipv4Type::TCP), tcp_send_channel)?;
        loop {
            let ipv4_packet = tcp_recv_channel.recv()?;
            let mut tcp_packet = TcpPacket::new();
            match tcp_packet.read(&ipv4_packet) {
                Err(e) => {
                    log::warn!("Failed to read tcp packet. Err: {:?}", e);
                    continue;
                }
                Ok(valid) => {
                    if !valid {
                        log::warn!("Discarding invalid tcp packet.");
                        continue;
                    }
                }
            }
            match self.recv_handler(&tcp_packet) {
                Err(e) => {
                    log::warn!("Failed to handle tcp packet. Err: {:?}", e);
                    continue;
                }
                Ok(_) => {}
            }
        }
    }

    pub fn recv_handler(&self, tcp_packet: &TcpPacket) -> Result<()> {
        let src_addr = &Ipv4Addr::from(tcp_packet.src_addr);
        let dst_addr = &Ipv4Addr::from(tcp_packet.dst_addr);
        let (socket_id, conns) = self.get_socket_id(
            src_addr,
            dst_addr,
            &tcp_packet.local_port,
            &tcp_packet.remote_port,
        )?;
        if let Some(id) = socket_id {
            if let Some(Some(conn)) = conns.get(&id) {
                log::trace!(
                    "Handling packet for {} socket (id={}). {}",
                    conn.status,
                    id,
                    tcp_packet.print_general_info()
                );
                match &conn.status {
                    TcpStatus::Listen => {
                        self.recv_handler_listen(id, tcp_packet, conns)
                            .context("recv_handler_listen failed.")?;
                    }
                    TcpStatus::SynSent => {
                        self.recv_handler_syn_sent(id, tcp_packet, conns)
                            .context("recv_handler_syn_sent failed.")?;
                    }
                    TcpStatus::SynRcvd => {
                        self.recv_handler_syn_rcvd(id, tcp_packet, conns)
                            .context("recv_handler_syn_rcvd failed.")?;
                    }
                    TcpStatus::Established => {
                        self.recv_handler_established(id, tcp_packet, conns)
                            .context("recv_handler_established failed.")?;
                    }
                    other => {
                        anyhow::bail!("Recv handler for TcpStatus {} is not implemented.", other);
                    }
                }
                return Ok(());
            } else {
                anyhow::bail!("No TcpConnection Data for the socket (id={}). This should be impossible if locking logic is correct.", id);
            }
        } else {
            // "An incoming segment not containing a RST causes a RST to be sent in response." rfc9293
            if !tcp_packet.flag.contains(TcpFlag::RST) {
                self.send_back_rst_syn(tcp_packet)?;
                log::debug!(
                    "No socket bound for the packet to {}:{}, send back rst packet.",
                    dst_addr,
                    tcp_packet.remote_port
                );
            // "An incoming segment containing a RST is discarded." rfc9293
            } else {
                log::debug!(
                    "No socket bound for the rst packet to {}:{}, ignored it.",
                    dst_addr,
                    tcp_packet.remote_port
                );
            }
            Ok(())
        }
    }

    // 3.10.7.2 LISTEN STATE rfc9293
    pub fn recv_handler_listen(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if tcp_packet.flag.contains(TcpFlag::RST) {
            log::debug!(
                "LISTEN socket (id={}) ignores any rst packet. remote={}:{}",
                socket_id,
                Ipv4Addr::from(tcp_packet.src_addr),
                tcp_packet.local_port
            );
            return Ok(());
        };
        if tcp_packet.flag.contains(TcpFlag::ACK) {
            self.send_back_rst_ack(tcp_packet)?;
            log::debug!(
                "LISTEN socket (id={}) rejects any ack packet and send back rst. remote={}:{}",
                socket_id,
                Ipv4Addr::from(tcp_packet.src_addr),
                tcp_packet.local_port
            );
            return Ok(());
        };
        if !tcp_packet.flag.contains(TcpFlag::SYN) {
            log::debug!(
                "LISTEN socket (id={}) ignores any not a syn packet (also no rst/ack flag). remote={}:{}",
                socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
            );
            return Ok(());
        }
        let mut listen_queue = self.listen_queue.lock().unwrap();
        if let Some(queue) = listen_queue.get_mut(&socket_id) {
            let len_established =
                queue.established_unconsumed.len() + queue.established_consumed.len();
            let len_all = queue.pending.len() + queue.pending_acked.len() + len_established;
            // May be we should return RST here. Linux control this behavior by tcp_abort_on_overflow param.
            anyhow::ensure!(
                len_established < TCP_MAX_CONCURRENT_SESSION && len_all < TCP_MAX_LISTEN_QUEUE,
                "No more concurrent tcp session for the socket (id={}). established: {}/{} all: {}/{}",
                socket_id, len_established, TCP_MAX_CONCURRENT_SESSION, len_all, TCP_MAX_LISTEN_QUEUE
            );
            for id in 1..=TCP_MAX_SOCKET {
                if conns.contains_key(&id) {
                    continue;
                } else {
                    let mut send_vars = SendVariables::new();
                    let mut recv_vars = ReceiveVariables::new();
                    let mut recv_queue = ReceiveQueue::new();
                    let iss = self.generate_initial_sequence();
                    send_vars.unacknowledged = iss;
                    send_vars.next_sequence_num = iss.wrapping_add(1);
                    send_vars.last_sequence_num = tcp_packet.seq_number;
                    send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    send_vars.initial_sequence_num = iss;
                    if let Some(mss) = tcp_packet.option.mss {
                        send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        send_vars.send_mss = 536;
                    }
                    if let Some(scale) = tcp_packet.option.window_scale {
                        // I'm sorry... fractions may be rounded down...
                        send_vars.window_shift = scale as usize;
                        send_vars.window_size = tcp_packet.window_size >> scale;
                        recv_vars.window_shift = TCP_DEFAULT_WINDOW_SCALE as usize;
                    } else {
                        send_vars.window_size = tcp_packet.window_size;
                    }
                    let recv_nxt = tcp_packet.seq_number.wrapping_add(1);
                    recv_vars.next_sequence_num = recv_nxt;
                    recv_vars.initial_sequence_num = tcp_packet.seq_number;
                    recv_vars.recv_mss = self.config.mtu - 40;
                    recv_queue.complete_datagram.sequence_num = recv_nxt as usize;
                    let src_addr = Ipv4Addr::from(tcp_packet.dst_addr);
                    let dst_addr = Ipv4Addr::from(tcp_packet.src_addr);
                    let mut new_conn = TcpConnection {
                        src_addr: src_addr,
                        dst_addr: dst_addr,
                        local_port: tcp_packet.remote_port,
                        remote_port: tcp_packet.local_port,
                        status: TcpStatus::SynRcvd,
                        parent_id: Some(socket_id),
                        syn_replied: false,
                        send_vars: send_vars,
                        recv_vars: recv_vars,
                        send_queue: SendQueue::new(),
                        recv_queue: recv_queue,
                        timer: TcpTimer::new(),
                        rtt_start: None,
                        rtt_seq: None,
                        last_snd_ack: 0,
                        last_sent_window: 0,
                        send_flag: TcpSendControlFlag::new(),
                        conn_flag: TcpConnectionFlag::new(),
                    };
                    if queue.accepted > 0 {
                        // socket has already accepted and waiting for new established connection.
                        let mut syn_ack = TcpPacket::new_syn_rcvd(&new_conn)?;
                        let seq = new_conn.send_vars.initial_sequence_num;
                        let ack = new_conn.recv_vars.next_sequence_num;
                        // 40 = ip header size (20) + tcp header size (20)
                        syn_ack.option.mss = Some((self.config.mtu - 40) as u16);
                        new_conn.syn_replied = true;
                        conns.insert(id, Some(new_conn));
                        log::debug!(
                            "Generated SYN-RECEIVED socket (id={} local={}:{} remote={}:{}) from LISTEN socket (id={}).",
                            id, src_addr, tcp_packet.remote_port, dst_addr, tcp_packet.local_port, socket_id
                        );
                        queue.pending_acked.push_back(id);
                        if let Some(Some(conn)) = conns.get_mut(&id) {
                            conn.timer.retransmission.init();
                            if let Err(e) = self
                                .send_tcp_packet(syn_ack)
                                .context("Failed to send SYN/ACK.")
                            {
                                log::debug!(
                                    "An accepted socket (id={}) failed to send SYN/ACK to {}:{} in listen_handler. SEQ={} ACK={} Err: {:?}",
                                    id, dst_addr, tcp_packet.local_port, seq, ack, e
                                );
                            } else {
                                log::debug!(
                                    "An accepted socket (id={}) replies SYN/ACK to {}:{} in listen_handler. SEQ={} ACK={}",
                                    id, dst_addr, tcp_packet.local_port, seq, ack
                                );
                            }
                            conn.timer.retransmission.fire_syn();
                        } else {
                            anyhow::bail!("No socket (id={}).", socket_id);
                        }
                        self.publish_event(TcpEvent {
                            socket_id: socket_id,
                            event: TcpEventType::SynReceived,
                        });
                    } else {
                        conns.insert(id, Some(new_conn));
                        queue.pending.push_back(id);
                    }
                    return Ok(());
                }
            }
            anyhow::bail!("Failed to generate a new tcp socket because there is no available id. TCP_MAX_SOCKET={}", TCP_MAX_SOCKET)
        } else {
            anyhow::bail!(
                "No listen queue for socket id {} which status is Listen.",
                socket_id
            );
        }
    }

    // 3.10.7.3 SYN-SENT STATE rfc9293
    pub fn recv_handler_syn_sent(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if tcp_packet.flag.contains(TcpFlag::ACK) {
                // This case includes "Recovery from Old Duplicate SYN" rfc9293
                if tcp_packet.ack_number <= conn.recv_vars.initial_sequence_num
                    || tcp_packet.ack_number > conn.send_vars.next_sequence_num
                {
                    self.send_back_rst_ack(tcp_packet)?;
                    log::debug!(
                        "[{}] Rejects an unacceptable ACK packet and send back RST. Expected ACK={} but received ACK={}",
                        conn.print_log_prefix(socket_id), conn.send_vars.next_sequence_num, tcp_packet.ack_number
                    );
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                if tcp_packet.ack_number == conn.send_vars.next_sequence_num {
                    log::debug!(
                        "[{}] Status changed from SYN-SENT to CLOSED. Received acceptable RST. ACK={})",
                        conn.print_log_prefix(socket_id), tcp_packet.ack_number
                    );
                    conn.status = TcpStatus::Closed;
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    });
                    return Ok(());
                } else {
                    log::debug!(
                        "[{}] Ignores a RST packet with unacceptable ACK. Expected ACK={} but received ACK={}",
                        conn.print_log_prefix(socket_id), conn.recv_vars.next_sequence_num, tcp_packet.ack_number
                    );
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::SYN) {
                // SYN/ACK, which means Normal 3-way handshake (local: active remote: passive)
                if tcp_packet.flag.contains(TcpFlag::ACK) {
                    let next_seq = tcp_packet.ack_number;
                    let next_ack = tcp_packet.seq_number.wrapping_add(1); // syn is treated as 1 byte.
                    let mut ack_packet = tcp_packet.create_reply_base();
                    ack_packet.seq_number = next_seq;
                    ack_packet.ack_number = next_ack;
                    ack_packet.flag = TcpFlag::ACK;
                    if let Some(scale) = tcp_packet.option.window_scale {
                        ack_packet.window_size = (conn.get_recv_window_size() >> scale) as u16;
                    } else {
                        ack_packet.window_size = conn.get_recv_window_for_pkt();
                    }
                    self.send_tcp_packet(ack_packet)
                        .context("Failed to reply ACK.")?;
                    if let Some(mss) = tcp_packet.option.mss {
                        conn.send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        conn.send_vars.send_mss = 536;
                    }
                    if let Some(scale) = tcp_packet.option.window_scale {
                        // I'm sorry... fractions may be rounded down...
                        conn.send_vars.window_shift = scale as usize;
                        conn.send_vars.window_size = tcp_packet.window_size >> scale;
                        conn.recv_vars.window_shift = TCP_DEFAULT_WINDOW_SCALE as usize;
                    } else {
                        conn.send_vars.window_size = tcp_packet.window_size;
                    }
                    conn.send_vars.unacknowledged = next_seq;
                    conn.send_vars.next_sequence_num = next_seq; // change nothing.
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    conn.send_vars.max_window_size = tcp_packet.window_size as usize;
                    conn.recv_vars.initial_sequence_num = tcp_packet.seq_number;
                    conn.recv_vars.next_sequence_num = next_ack;
                    conn.recv_queue.complete_datagram.sequence_num = next_ack as usize;
                    conn.status = TcpStatus::Established;
                    conn.timer.retransmission.init();
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Established,
                    });
                    // SYN-SENT socket is always active open, so we don't need to push it to listen_queue.
                    log::debug!(
                        "[{}] Status changed from SYN-SENT to ESTABLISHED. SND.NXT={} RCV.NXT={}",
                        conn.print_log_prefix(socket_id),
                        next_ack,
                        next_seq
                    );
                    return Ok(());
                // SYN, which means Simultaneous Connection (Both sides are trying active open)
                } else {
                    let next_seq = conn.send_vars.initial_sequence_num; // send same seq that has already sent
                    let next_ack = tcp_packet.seq_number.wrapping_add(1);
                    if let Some(mss) = tcp_packet.option.mss {
                        conn.send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        conn.send_vars.send_mss = 536;
                    }
                    if let Some(scale) = tcp_packet.option.window_scale {
                        // I'm sorry... fractions may be rounded down...
                        conn.send_vars.window_shift = scale as usize;
                        conn.send_vars.window_size = tcp_packet.window_size >> scale;
                        conn.recv_vars.window_shift = TCP_DEFAULT_WINDOW_SCALE as usize;
                    } else {
                        conn.send_vars.window_size = tcp_packet.window_size;
                    }
                    conn.syn_replied = true;
                    conn.send_vars.unacknowledged = next_seq;
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    conn.send_vars.max_window_size = tcp_packet.window_size as usize;
                    conn.recv_vars.next_sequence_num = next_ack;
                    conn.recv_queue.complete_datagram.sequence_num = next_ack as usize;
                    conn.status = TcpStatus::SynRcvd;
                    conn.timer.retransmission.init();
                    if let Err(e) = self.send_handler(conn) {
                        log::debug!(
                            "[{}] Failed to send SYN/ACK. Err: {:?}",
                            conn.print_log_prefix(socket_id),
                            e
                        );
                    }
                    log::debug!(
                        "[{}] Status changed from SYN-SENT to SYN-RECEIVED. This is a Simultaneous Connection situation.",
                        conn.print_log_prefix(socket_id)
                    );
                    conn.timer.retransmission.fire_syn();
                    return Ok(());
                }
            }
            log::debug!(
                "[{}] SYN-SENT socket ignores packet. SEG.FLAG={:?}",
                conn.print_log_prefix(socket_id),
                tcp_packet.flag
            );
            Ok(())
        } else {
            anyhow::bail!("No socket (id={}).", socket_id);
        }
    }

    pub fn recv_handler_syn_rcvd(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if !conn.syn_replied {
                log::debug!(
                    "[{}] Ignores every packet because syn_replied is false. In fact, this condition is not SYN-RECVED but is classified as such for convenience.",
                    conn.print_log_prefix(socket_id)
                );
                return Ok(());
            };
            // check if a segment is acceptable
            if !is_segment_acceptable(conn, tcp_packet) {
                if !tcp_packet.flag.contains(TcpFlag::RST) {
                    let mut ack = tcp_packet.create_reply_base();
                    ack.seq_number = conn.send_vars.next_sequence_num;
                    ack.ack_number = conn.recv_vars.next_sequence_num;
                    ack.flag = TcpFlag::ACK;
                    self.send_tcp_packet(ack).context("Failed to send ACK.")?;
                    log::debug!(
                        "[{}] Received an unacceptable non-RST packet and just send back ACK. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={} SEG.FLAG={:?}",
                        conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size, tcp_packet.flag
                    );
                } else {
                    log::debug!(
                        "[{}] Received an unacceptable RST packet and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={} SEG.FLAG={:?}",
                        conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size, tcp_packet.flag
                    );
                }
                return Ok(());
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                // 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment. rfc9293
                if !(conn.recv_vars.next_sequence_num <= tcp_packet.seq_number
                    && tcp_packet.seq_number
                        < conn.recv_vars.next_sequence_num + conn.recv_vars.window_size as u32)
                {
                    log::debug!(
                        "[{}] Received a RST packet that is outside of receive window and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                // 2) If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT) ... rfc9293
                } else if conn.recv_vars.next_sequence_num == tcp_packet.seq_number {
                    let parent_id = conn.parent_id;
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    // passive open
                    if let Some(parent) = parent_id {
                        if let Some(queue) = listen_queue.get_mut(&parent) {
                            queue.pending.retain(|&x| x != socket_id);
                            queue.pending_acked.retain(|&x| x != socket_id);
                        }
                        log::debug!(
                            "[{}] A Passive open connection (parent={}) is removed because of RST.",
                            conn.print_log_prefix(socket_id),
                            parent
                        );
                    // active open don't have a parent socket.
                    } else {
                        listen_queue.remove(&socket_id);
                        log::debug!(
                            "[{}] An active open connection is removed because of a RST packet.",
                            conn.print_log_prefix(socket_id)
                        );
                    }
                    conns.remove(&socket_id);
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Refused,
                    });
                    return Ok(());
                // 3) If the RST bit is set and the sequence number does not exactly match the next expected sequence value, ... rfc9293
                } else {
                    // It's a challenge ACK situation, but I don't implement this now.
                    return Ok(());
                }
            }
            // If the connection was initiated with a passive OPEN, then return this connection to the LISTEN state and return. rfc9293
            if tcp_packet.flag.contains(TcpFlag::SYN) {
                if let Some(parent) = conn.parent_id {
                    log::debug!(
                        "[{}] A Passive open connection (parent={}) is removed because of SYN.",
                        conn.print_log_prefix(socket_id),
                        parent
                    );
                    conns.remove(&socket_id);
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    if let Some(queue) = listen_queue.get_mut(&parent) {
                        queue.pending.retain(|&x| x != socket_id);
                        queue.pending_acked.retain(|&x| x != socket_id);
                    }
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Refused,
                    });
                    return Ok(());
                }
            }
            // if the ACK bit is off, drop the segment and return rfc9293
            if !tcp_packet.flag.contains(TcpFlag::ACK) && !tcp_packet.flag.contains(TcpFlag::FIN) {
                log::debug!(
                    "[{}] Received a packet with SEG.FLAG={:?} and ignored.",
                    conn.print_log_prefix(socket_id),
                    tcp_packet.flag
                );
                return Ok(());
            } else if tcp_packet.flag.contains(TcpFlag::ACK) {
                // If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state... rfc9293
                if conn.send_vars.unacknowledged < tcp_packet.ack_number
                    && tcp_packet.ack_number <= conn.send_vars.next_sequence_num
                {
                    // SND.UNA is updated. It's not written in RFC9293 but obviously it should.
                    conn.send_vars.unacknowledged = tcp_packet.ack_number;
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    let current_window = conn.send_vars.get_scaled_send_window_size();
                    conn.send_vars.window_size = tcp_packet.window_size;
                    conn.send_vars.max_window_size =
                        max(current_window, conn.get_recv_window_size());
                    conn.status = TcpStatus::Established;
                    conn.timer.retransmission.init();
                    let parent_id = conn.parent_id;
                    let mut listen_queue: MutexGuard<HashMap<usize, ListenQueue>> =
                        self.listen_queue.lock().unwrap();
                    // If this socket is passive open, update listenQueue.
                    if let Some(parent) = parent_id {
                        if let Some(queue) = listen_queue.get_mut(&parent) {
                            queue.pending_acked.retain(|&x| x != socket_id);
                            queue.established_unconsumed.push_back(socket_id);
                        }
                    }
                    log::debug!(
                        "[{}] Status changed from SYN-RECEIVED to ESTABLISHED. SEG.FLAG={:?}",
                        conn.print_log_prefix(socket_id),
                        tcp_packet.flag
                    );
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Established,
                    });
                    return Ok(());
                // If the segment acknowledgment is not acceptable, form a reset segment rfc9293
                } else {
                    self.send_back_rst_ack(tcp_packet)?;
                    log::debug!(
                        "[{}] Rejects an unacceptable ACK packet and send back RST. SEG.ACK={} SND.UNA={} SND.NXT={}",
                        conn.print_log_prefix(socket_id), tcp_packet.ack_number, conn.send_vars.unacknowledged, conn.send_vars.next_sequence_num
                    );
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::FIN) {
                log::debug!(
                    "[{}] Status changed from SYN-RECEIVED to CLOSE-WAIT. SEG.FLAG={:?}",
                    conn.print_log_prefix(socket_id),
                    tcp_packet.flag
                );
                conn.status = TcpStatus::CloseWait;
                self.publish_event(TcpEvent {
                    socket_id: socket_id,
                    event: TcpEventType::Closed,
                });
                return Ok(());
            }
            Ok(())
        } else {
            anyhow::bail!("No socket (id={}).", socket_id);
        }
    }

    pub fn recv_handler_established(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            // check if a segment is acceptable
            if !is_segment_acceptable(conn, tcp_packet) {
                if !tcp_packet.flag.contains(TcpFlag::RST) {
                    conn.send_flag.ack_now = true;
                    if let Err(e) = self.send_handler(conn) {
                        log::warn!(
                            "[{}] Received an unacceptable non-RST packet and just send back ACK, but failed. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={} SEG.FLAG={:?} Err: {:?}",
                            conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size, tcp_packet.flag, e
                        );
                    } else {
                        log::debug!(
                            "[{}] Received an unacceptable non-RST packet and just send back ACK. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={} SEG.FLAG={:?}",
                            conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.get_recv_window_size(), tcp_packet.flag
                        );
                    }
                } else {
                    log::debug!(
                        "[{}] Received an unacceptable RST packet and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                }
                return Ok(());
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                // 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment. rfc9293
                if !(conn.recv_vars.next_sequence_num <= tcp_packet.seq_number
                    && tcp_packet.seq_number
                        < conn.recv_vars.next_sequence_num + conn.recv_vars.window_size as u32)
                {
                    log::debug!(
                        "[{}] Received a RST packet that is outside of receive window and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        conn.print_log_prefix(socket_id), tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                // 2) If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT) ... rfc9293
                } else if conn.recv_vars.next_sequence_num == tcp_packet.seq_number {
                    let parent_id = conn.parent_id;
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    if let Some(parent) = parent_id {
                        if let Some(queue) = listen_queue.get_mut(&parent) {
                            queue.established_unconsumed.retain(|&x| x != socket_id);
                            queue.established_consumed.retain(|&x| x != socket_id);
                        }
                    }
                    log::debug!("[{}] An ESTABLISHED connection is removed because of RST packet. SEG.FLAG={:?}", conn.print_log_prefix(socket_id), tcp_packet.flag);
                    conns.remove(&socket_id);
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    });
                    return Ok(());
                } else {
                    // It's a challenge ACK situation, but I don't implement this now.
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::SYN) {
                // It's a challenge ACK situation too, but I don't implement this now.
                //
                // RFC 5961 recommends that in these synchronized states, if the SYN bit is set,
                // irrespective of the sequence number, TCP endpoints MUST send a "challenge ACK"
                // to the remote peer: rfc9293
                return Ok(());
            }
            if tcp_packet.flag.contains(TcpFlag::ACK) {
                // TCP stacks that implement RFC 5961 MUST add an input check that the ACK value is acceptable
                // only if it is in the range of ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT). rfc9293
                if !seq_in_range(
                    conn.send_vars
                        .unacknowledged
                        .wrapping_sub(conn.send_vars.max_window_size as u32),
                    conn.send_vars.next_sequence_num,
                    tcp_packet.ack_number,
                ) {
                    // It's a challenge ACK situation too, but I don't implement this now.
                    return Ok(());
                }
                // If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. ... rfc9293
                if seq_in_range(
                    conn.send_vars.unacknowledged.wrapping_add(1),
                    conn.send_vars.next_sequence_num,
                    tcp_packet.ack_number,
                ) {
                    if conn.send_vars.unacknowledged != tcp_packet.ack_number {
                        log::debug!(
                            "[{}] SND.UNA advanced ({}->{} SND.NXT={}).",
                            conn.print_log_prefix(socket_id),
                            conn.send_vars.unacknowledged,
                            tcp_packet.ack_number,
                            conn.send_vars.next_sequence_num
                        );
                    }
                    if conn.update_snd_una(tcp_packet.ack_number)? {
                        self.publish_event(TcpEvent {
                            socket_id: socket_id,
                            event: TcpEventType::SendMore,
                        });
                    };
                } else if seq_less_equal(tcp_packet.ack_number, conn.send_vars.unacknowledged) {
                    // If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored. rfc9293
                    log::debug!(
                        "[{}] Duplicate ack. SEG.LENGTH={} SND.UNA={} SEG.ACK={} ",
                        conn.print_log_prefix(socket_id),
                        tcp_packet.payload.len(),
                        conn.send_vars.unacknowledged,
                        tcp_packet.ack_number
                    );
                } else if seq_greater_than(tcp_packet.ack_number, conn.send_vars.next_sequence_num)
                {
                    // If the ACK acks something not yet sent (SEG.ACK > SND.NXT),
                    // then send an ACK, drop the segment, and return. rfc9293
                    if let Err(e) = self.send_handler(conn) {
                        log::warn!(
                            "[{}] Acked, but failed. SEG.ACK={} SND.NXT={} Err: {:?}",
                            conn.print_log_prefix(socket_id),
                            tcp_packet.ack_number,
                            conn.send_vars.next_sequence_num,
                            e
                        );
                    }
                    return Ok(());
                }
                if should_update_window(conn, tcp_packet) {
                    let current_window = conn.send_vars.get_scaled_send_window_size();
                    let new_window =
                        (tcp_packet.window_size << conn.send_vars.window_shift) as usize;
                    log::debug!(
                        "[{}] SND.WND updated. ({}->{} window_shift={} SEG.SEQ={} SEG.ACK={}).",
                        conn.print_log_prefix(socket_id),
                        current_window,
                        new_window,
                        conn.send_vars.window_shift,
                        tcp_packet.seq_number,
                        tcp_packet.ack_number
                    );
                    if current_window != new_window {
                        self.publish_event(TcpEvent {
                            socket_id: socket_id,
                            event: TcpEventType::SendMore,
                        });
                    }
                    conn.send_vars.window_size = tcp_packet.window_size;
                    conn.send_vars.max_window_size = max(current_window, new_window);
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                }
                // todo: use timestamp option
                if let (Some(rtt_start), Some(rtt_seq)) = (conn.rtt_start, conn.rtt_seq) {
                    if seq_greater_equal(tcp_packet.ack_number, rtt_seq) {
                        update_retransmission_param(
                            conn,
                            rtt_start.elapsed().as_millis() as usize,
                        )?;
                        let timer_param = &conn.timer.retransmission.timer_param;
                        log::debug!(
                            "[{}] Retransmission param updated. rtt={} rtt_smoothed={}({}) rtt_variance={}({}) shift={} delta={}",
                            conn.print_log_prefix(socket_id), timer_param.rtt, timer_param.rtt_smoothed, timer_param.rtt_smoothed >> TCP_SRTT_SHIFT,
                            timer_param.rtt_variance, timer_param.rtt_variance >> TCP_RTTVAR_SHIFT, timer_param.rexmt_shift, timer_param.delta
                        );
                        conn.rtt_start = None;
                        conn.rtt_seq = None;
                    }
                }
            }
            // Seventh, process the segment text: rfc9293
            if tcp_packet.payload.len() != 0 {
                let prev_payload = conn.recv_queue.complete_datagram.payload.len();
                if let Err(e) = conn
                    .recv_queue
                    .add(tcp_packet.seq_number as usize, &tcp_packet.payload)
                {
                    log::warn!("Failed to add a segment to the recv queue. Err: {:?}", e);
                } else {
                    let current_payload = conn.recv_queue.complete_datagram.payload.len();
                    let rcv_nxt_advance = current_payload - prev_payload;
                    let rcv_nxt_next = conn
                        .recv_queue
                        .get_real_begin_sequence_num()
                        .wrapping_add(current_payload as u32);
                    log::debug!(
                        "[{}] RCV.NXT advanced. ({}->{}).",
                        conn.print_log_prefix(socket_id),
                        conn.recv_vars.next_sequence_num,
                        rcv_nxt_next
                    );
                    conn.recv_vars.next_sequence_num = rcv_nxt_next;
                    conn.recv_vars.window_size = conn.get_recv_window_size();
                    if prev_payload != current_payload {
                        log::debug!(
                            "[{}] Datagram received {} bytes. (Received datagram length {}->{})",
                            conn.print_log_prefix(socket_id),
                            rcv_nxt_advance,
                            prev_payload,
                            current_payload
                        );
                        self.publish_event(TcpEvent {
                            socket_id: socket_id,
                            event: TcpEventType::DatagramReceived,
                        });
                    }
                }
                if !conn.timer.delayed_ack.timer_param.active
                    && conn.conn_flag.use_delayed_ack
                    && !conn.has_unsent_data()
                {
                    conn.send_flag.ack_delayed = true;
                    conn.timer.delayed_ack.fire();
                } else {
                    conn.send_flag.ack_now = true;
                }
            }
            // Enter the CLOSE-WAIT state. rfc9293
            if tcp_packet.flag.contains(TcpFlag::FIN) {
                conn.status = TcpStatus::CloseWait;
                log::debug!(
                    "[{}] Status changed from ESTABLISHED to CLOSED-WAIT. SEG.FLAG={:?}",
                    conn.print_log_prefix(socket_id),
                    tcp_packet.flag
                );
            }
            if let Err(e) = self.send_handler(conn) {
                log::warn!(
                    "[{}] Acked, but failed. SEG.ACK={} SND.NXT={} Err: {}",
                    conn.print_log_prefix(socket_id),
                    tcp_packet.ack_number,
                    conn.send_vars.next_sequence_num,
                    e
                );
            }
            if !conn.timer.retransmission.timer_param.active
                && conn.send_vars.unacknowledged != conn.send_vars.next_sequence_num
            {
                conn.timer.retransmission.fire_datagram();
                log::debug!(
                    "Enabled retransmission timer in recv_handler_established. shift={} SND.UNA={} SND.NXT={}",
                    conn.timer.retransmission.timer_param.rexmt_shift, conn.send_vars.unacknowledged, conn.send_vars.next_sequence_num
                );
            } else if conn.timer.retransmission.timer_param.active
                && conn.send_vars.unacknowledged == conn.send_vars.next_sequence_num
            {
                conn.timer.retransmission.timer_param.active = false;
                log::debug!(
                    "Disabled retransmission timer in recv_handler_established. shift={} SND.UNA=SND.NXT={}",
                    conn.timer.retransmission.timer_param.rexmt_shift, conn.send_vars.unacknowledged
                );
            }
            return Ok(());
        } else {
            anyhow::bail!("No socket (id={}).", socket_id);
        }
    }

    pub fn generate_initial_sequence(&self) -> u32 {
        100
    }
}

// true if min <= target <= max
pub fn seq_in_range(min: u32, max: u32, target: u32) -> bool {
    if seq_less_equal(min, max) {
        seq_less_equal(min, target) && seq_less_equal(target, max)
    } else {
        if seq_greater_than(min, max) {
            false
        } else {
            seq_less_equal(min, target) || seq_less_equal(target, max)
        }
    }
}

// true if seq1 < seq2
pub fn seq_less_than(seq1: u32, seq2: u32) -> bool {
    (seq1 < seq2 && seq2 - seq1 < (MAX_SEQ / 2)) || (seq1 > seq2 && seq1 - seq2 > (MAX_SEQ / 2))
}

// true if seq1 <= seq2
pub fn seq_less_equal(seq1: u32, seq2: u32) -> bool {
    seq1 == seq2 || seq_less_than(seq1, seq2)
}

// true if seq1 > seq2
pub fn seq_greater_than(seq1: u32, seq2: u32) -> bool {
    (seq1 > seq2 && seq1 - seq2 < (MAX_SEQ / 2)) || (seq1 < seq2 && seq2 - seq1 > (MAX_SEQ / 2))
}

// true if seq1 >= seq2
pub fn seq_greater_equal(seq1: u32, seq2: u32) -> bool {
    seq1 == seq2 || seq_greater_than(seq1, seq2)
}

// There are four cases for the acceptability test for an incoming segment: rfc9293
// Modify rfc9293 implementation based on https://datatracker.ietf.org/doc/html/draft-gont-tcpm-tcp-seq-validation-04
pub fn is_segment_acceptable(conn: &TcpConnection, tcp_packet: &TcpPacket) -> bool {
    if tcp_packet.payload.len() == 0 && tcp_packet.window_size << conn.send_vars.window_shift == 0 {
        // RCV.NXT-1 =< SEG.SEQ <= RCV.NXT
        if tcp_packet.seq_number == conn.recv_vars.next_sequence_num
            || tcp_packet.seq_number.wrapping_add(1) == conn.recv_vars.next_sequence_num
        {
            return true;
        }
    } else if tcp_packet.payload.len() == 0
        && tcp_packet.window_size << conn.send_vars.window_shift > 0
    {
        // RCV.NXT-1 =< SEG.SEQ < RCV.NXT+RCV.WND
        if seq_in_range(
            conn.recv_vars.next_sequence_num.wrapping_sub(1),
            conn.recv_vars
                .next_sequence_num
                .wrapping_add(conn.recv_vars.window_size as u32 - 1),
            tcp_packet.seq_number,
        ) {
            return true;
        }
    } else if tcp_packet.payload.len() > 0
        && tcp_packet.window_size << conn.send_vars.window_shift == 0
    {
        return false;
    } else if tcp_packet.payload.len() > 0
        && tcp_packet.window_size << conn.send_vars.window_shift > 0
    {
        // RCV.NXT - 1 =< SEG.SEQ < RCV.NXT+RCV.WND
        if seq_in_range(
            conn.recv_vars.next_sequence_num,
            conn.recv_vars
                .next_sequence_num
                .wrapping_add(conn.recv_vars.window_size as u32),
            tcp_packet.seq_number.wrapping_add(1), // RCV.NXT -1 =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        ) || seq_in_range(
            conn.recv_vars.next_sequence_num,
            conn.recv_vars
                .next_sequence_num
                 .wrapping_add(conn.recv_vars.window_size as u32),
            tcp_packet
                .seq_number
                .wrapping_add(tcp_packet.payload.len() as u32),
        ) {
            return true;
        }
    }
    false
}

// If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated. rfc9293
pub fn should_update_window(conn: &TcpConnection, tcp_packet: &TcpPacket) -> bool {
    if seq_in_range(
        conn.send_vars.unacknowledged,
        conn.send_vars.next_sequence_num,
        tcp_packet.ack_number,
    ) && (seq_greater_than(tcp_packet.seq_number, conn.send_vars.last_sequence_num)
        || (tcp_packet.seq_number == conn.send_vars.last_sequence_num
            && seq_greater_equal(tcp_packet.ack_number, conn.send_vars.last_acknowledge_num)))
    {
        true
    } else {
        false
    }
}

#[derive(Debug)]
pub struct ListenQueue {
    pub pending: VecDeque<usize>, // Received SYN but not replied SYN/ACK
    pub pending_acked: VecDeque<usize>, // Received SYN and replied SYN/ACK
    pub established_unconsumed: VecDeque<usize>, // Established but not used by accept call
    pub established_consumed: VecDeque<usize>, // Established and used by accept call
    pub accepted: usize,
}

#[derive(Debug)]
pub struct TcpConnection {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub status: TcpStatus,
    pub parent_id: Option<usize>,
    pub syn_replied: bool,
    pub send_vars: SendVariables,
    pub recv_vars: ReceiveVariables,
    pub send_queue: SendQueue,
    pub recv_queue: ReceiveQueue,
    pub timer: TcpTimer,
    pub rtt_start: Option<Instant>, // BSD: t_rtttime
    pub rtt_seq: Option<u32>,       // BSD: t_rtseq
    pub last_snd_ack: u32,          // BSD: last_ack_sent
    pub last_sent_window: usize, // window size recently notified to peer
    pub send_flag: TcpSendControlFlag,
    pub conn_flag: TcpConnectionFlag,
}

impl TcpConnection {
    pub fn new(src_addr: Ipv4Addr, local_port: u16, dst_addr: Ipv4Addr, remote_port: u16) -> Self {
        TcpConnection {
            src_addr,
            dst_addr,
            local_port,
            remote_port,
            status: TcpStatus::Closed,
            parent_id: None,
            syn_replied: false,
            send_vars: Default::default(),
            recv_vars: Default::default(),
            send_queue: SendQueue::new(),
            recv_queue: ReceiveQueue::new(),
            timer: TcpTimer::new(),
            rtt_start: None,
            rtt_seq: None,
            last_snd_ack: 0,
            last_sent_window: 0,
            send_flag: TcpSendControlFlag::new(),
            conn_flag: TcpConnectionFlag::new(),
        }
    }

    pub fn print_address(&self) -> String {
        format!(
            "local={}:{} remote={}:{}",
            self.src_addr, self.local_port, self.dst_addr, self.remote_port
        )
    }

    pub fn print_log_prefix(&self, id: usize) -> String {
        format!(
            "id={} status={} local={}:{} remote={}:{}",
            id, self.status, self.src_addr, self.local_port, self.dst_addr, self.remote_port
        )
    }

    pub fn get_recv_window_size(&self) -> usize {
        self.recv_queue.queue_length - self.recv_queue.complete_datagram.payload.len()
    }

    pub fn get_recv_window_for_pkt(&self) -> u16 {
        (self.get_recv_window_size() >> self.recv_vars.window_shift) as u16
    }

    pub fn update_snd_una(&mut self, new_snd_una: u32) -> Result<bool> {
        anyhow::ensure!(
            seq_less_equal(new_snd_una, self.send_vars.next_sequence_num),
            "New SND.UNA ({}) should be equal or smaller than SND.NXT ({}).",
            new_snd_una,
            self.send_vars.next_sequence_num
        );
        let different = new_snd_una != self.send_vars.unacknowledged;
        self.send_queue
            .payload
            .drain(..new_snd_una.wrapping_sub(self.send_vars.unacknowledged) as usize);
        self.send_vars.unacknowledged = new_snd_una;
        Ok(different)
    }

    pub fn has_unsent_data(&self) -> bool {
        let send_queue_tail = self
            .send_vars
            .unacknowledged
            .wrapping_add(self.send_queue.payload.len() as u32);
        send_queue_tail != self.send_vars.next_sequence_num
    }
}

// Control flag that used once for each segment send
#[derive(Debug, Default)]
pub struct TcpSendControlFlag {
    pub ack_now: bool,     // BSD: TF_ACKNOW
    pub ack_delayed: bool, // BSD: TF_DELACK
    pub snd_from_una: bool,
}

impl TcpSendControlFlag {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn init(&mut self) {
        self.ack_now = false;
        self.ack_delayed = false;
        self.snd_from_una = false;
    }
}

#[derive(Debug, Default)]
pub struct TcpConnectionFlag {
    pub use_delayed_ack: bool,
    pub use_no_delay: bool, // BSD: TF_NODELAY
}

impl TcpConnectionFlag {
    pub fn new() -> Self {
        Self {
            use_delayed_ack: TCP_DELAY_ACK,
            use_no_delay: TCP_NO_DELAY,
            ..Default::default()
        }
    }
}

//
//      1         2          3          4
// ----------|----------|----------|----------
//        SND.UNA    SND.NXT    SND.UNA
//                             +SND.WND
//
// 1 - old sequence numbers that have been acknowledged
// 2 - sequence numbers of unacknowledged data
// 3 - sequence numbers allowed for new data transmission
// 4 - future sequence numbers that are not yet allowed
//
//            Figure 3: Send Sequence Space (rfc9293)
#[derive(Debug, Default)]
pub struct SendVariables {
    pub unacknowledged: u32, // send unacknowledged (oldest unacknowledged sequence number) -> recv packet's ack (UNA)
    pub next_sequence_num: u32, // send next -> recv packet's ack, next send packet's seq (NXT)
    pub window_size: u16,    // send window received by packet (not scaled!)
    pub urgent_pointer: u16, // send urgent pointer
    pub last_sequence_num: u32, // segment sequence number used for last window update (WL1)
    pub last_acknowledge_num: u32, // segment acknowledgment number used for last window update (WL2)
    pub initial_sequence_num: u32, // initial send sequence number (ISS)
    pub send_mss: u16,             // Maximum Segment Size reported by remote peer
    pub window_shift: usize,       // received window scale option (Snd.Wind.Shift)
    pub max_window_size: usize,    // maximum windows size that has ever received (already scaled)
}

impl SendVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn get_scaled_send_window_size(&self) -> usize {
        (self.window_size << self.window_shift) as usize
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct SendQueue {
    pub payload: Vec<u8>,
    pub queue_length: usize,
}

impl SendQueue {
    pub fn new() -> Self {
        Self {
            queue_length: TCP_DEFAULT_SEND_QUEUE_LENGTH,
            ..Default::default()
        }
    }
}

//
//      1         2          3
// ----------|----------|----------
//        RCV.NXT    RCV.NXT
//                  +RCV.WND
//
// 1 - old sequence numbers that have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers that are not yet allowed
//
//        Figure 4: Receive Sequence Space (rfc9293)
#[derive(Debug, Default)]
pub struct ReceiveVariables {
    pub next_sequence_num: u32, // receive next -> recv packet's seq + data length, next send packet's ack (NXT)
    pub window_size: usize,     // receive window (already scaled, originaly u16)
    pub urgent_pointer: u16,    // receive urgent pointer
    pub initial_sequence_num: u32, // initial receive sequence number (IRS)
    pub window_shift: usize,    // received window scale option (Rcv.Wind.Shift)
    pub recv_mss: usize,        // mss report to remote peer
}

impl ReceiveVariables {
    pub fn new() -> Self {
        Self {
            window_size: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct ReceiveQueue {
    pub queue_length: usize,
    pub complete_datagram: ReceiveFragment,
    pub fragmented_datagram: Vec<ReceiveFragment>,
}

#[derive(Debug, Default, PartialEq)]
pub struct ReceiveFragment {
    pub sequence_num: usize, // Start SEQ of complete_datagram or RCV.NXT if complete_datagram dosen't exists.
    pub payload: Vec<u8>,
}

impl ReceiveFragment {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl ReceiveQueue {
    pub fn new() -> Self {
        Self {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            ..Default::default()
        }
    }

    pub fn convert_virtual_sequence_num(&self, seq: usize) -> Result<usize> {
        let begin = self.complete_datagram.sequence_num;
        if begin <= seq && seq <= begin + self.queue_length {
            Ok(seq)
        } else if begin <= seq + TCP_RECV_QUEUE_WRAP
            && seq + TCP_RECV_QUEUE_WRAP <= begin + self.queue_length
        {
            Ok(seq + TCP_RECV_QUEUE_WRAP)
        } else {
            anyhow::bail!("Unacceptable sequence number. SEG.SEQ: {} QUEUE.BEGIN: {} QUEUE.CURRENT_LEN: {} QUEUE.LENGTH: {}", seq, begin, self.complete_datagram.payload.len(), self.queue_length);
        }
    }

    pub fn get_real_begin_sequence_num(&self) -> u32 {
        let begin = self.complete_datagram.sequence_num;
        if begin >= TCP_RECV_QUEUE_WRAP {
            (begin - TCP_RECV_QUEUE_WRAP) as u32
        } else {
            begin as u32
        }
    }

    pub fn add(&mut self, seq: usize, payload: &Vec<u8>) -> Result<()> {
        log::trace!(
            "Adding SEQ={} (LEN: {}) to recv queue {}.",
            seq,
            payload.len(),
            self.get_current()
        );
        anyhow::ensure!(payload.len() > 0, "Cannot add an empty segment.");
        let virtual_seq = self
            .convert_virtual_sequence_num(seq)
            .context("Failed to add segment, possibly it is out of the receive queue.")?;
        let new_start = virtual_seq;
        let new_end = virtual_seq + payload.len() - 1;
        let complete_start = self.complete_datagram.sequence_num;
        let complete_end =
            self.complete_datagram.sequence_num + max(self.complete_datagram.payload.len(), 1) - 1;
        let complete_max = complete_start + self.queue_length - 1;
        let pending_start = max(complete_end + 1, new_start);
        anyhow::ensure!(
            complete_start <= new_start && new_end <= complete_max,
            "An invalid segment was added. SEG.SEQ={} SEG.LEN={} QUEUE.BEGIN_SEQ={} QUEUE.MAX_SEQ={}", new_start, payload.len(), complete_start, complete_end
        );
        if self.complete_datagram.payload.len() == 0 && complete_start == new_start {
            self.complete_datagram.payload = payload.clone();
            return Ok(());
        }
        if new_end <= complete_end {
            return Ok(());
        }
        let mut pending_new = Vec::new();
        let mut tmp_fragment: Option<ReceiveFragment> = None;
        let mut complete_marge: bool = false;
        for ReceiveFragment {
            sequence_num: current_seq,
            payload: current_payload,
        } in &self.fragmented_datagram
        {
            if complete_marge {
                pending_new.push(ReceiveFragment {
                    sequence_num: *current_seq,
                    payload: current_payload.clone(),
                });
                continue;
            }
            let current_start = *current_seq;
            let current_end = current_seq + current_payload.len() - 1;
            // with tmp_fragment
            if let Some(ReceiveFragment {
                sequence_num: tmp_seq,
                payload: ref tmp_payload,
            }) = tmp_fragment
            {
                let tmp_start = tmp_seq;
                let tmp_end = tmp_seq + tmp_payload.len() - 1;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <-O->
                // result   :   <-O->  <---O---> (add fragments)
                if tmp_end < current_start - 1 {
                    pending_new.push(ReceiveFragment {
                        sequence_num: tmp_seq,
                        payload: tmp_payload.to_vec(),
                    });
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <----O---->
                // result   :   <-------O------> (add marged fragment)
                } else if current_start - 1 <= tmp_end && tmp_end <= current_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut tmp_payload[..current_start - tmp_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    pending_new.push(ReceiveFragment {
                        sequence_num: tmp_start,
                        payload: fragment_marged,
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :            <-O->
                // result   :          <---O---> (add the current fragment as is)
                } else if tmp_start <= current_start && tmp_end <= current_end {
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <---------O--------->
                // result   :   <---------O---------> (add marged fragment as tmp)
                } else if tmp_start < current_start && current_end < tmp_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut tmp_payload[..current_start - tmp_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged
                        .append(&mut tmp_payload[1 + current_end - tmp_start..].to_vec());
                    tmp_fragment = Some(ReceiveFragment {
                        sequence_num: tmp_start,
                        payload: fragment_marged,
                    });
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :             <-----O---->
                // result   :          <-----O-------> (add marged fragment as tmp)
                } else if current_start <= tmp_start && tmp_start < current_end + 1 {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged
                        .append(&mut tmp_payload[1 + current_end - tmp_start..].to_vec());
                    tmp_fragment = Some(ReceiveFragment {
                        sequence_num: tmp_start,
                        payload: fragment_marged,
                    });
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :                     <-O->
                // result   :          <---O--->  <-O-> (leave tmp fragment as is)
                } else if current_end + 1 < tmp_start {
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    continue;
                }
                anyhow::bail!(
                    "Impossible range: tmp_start={} tmp_end={} current_start={} current_end={}",
                    tmp_start,
                    tmp_end,
                    current_start,
                    current_end
                );
            // without tmp_fragment
            } else {
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :   <-O->
                // result   :   <-O->  <---O---> (add fragments)
                if new_end < current_start - 1 {
                    pending_new.push(ReceiveFragment {
                        sequence_num: pending_start,
                        payload: payload[pending_start - new_start..].to_vec(),
                    });
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :     <----O---->
                // result   :     <------O-----> (add marged fragment)
                } else if current_start - 1 <= new_end && new_end <= current_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(
                        &mut payload
                            [max(pending_start - new_start, 1) - 1..current_start - new_start]
                            .to_vec(),
                    );
                    fragment_marged.append(&mut current_payload.to_vec());
                    pending_new.push(ReceiveFragment {
                        sequence_num: pending_start,
                        payload: fragment_marged,
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :            <-O->
                // result   :          <---O---> (add the current fragment as is)
                } else if pending_start <= current_start && new_end <= current_end {
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :       <-------O-------->
                // result   :       <--------O-------> (add marged fragment as tmp)
                } else if pending_start < current_start && current_end < new_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(
                        &mut payload[max(pending_start - new_start, 0)..current_start - new_start]
                            .to_vec(),
                    );
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut payload[1 + current_end - new_start..].to_vec());
                    tmp_fragment = Some(ReceiveFragment {
                        sequence_num: pending_start,
                        payload: fragment_marged,
                    });
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :             <-----O---->
                // result   :          <-----O-------> (add marged fragment as tmp)
                } else if current_start <= pending_start && pending_start <= current_end + 1 {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut payload[1 + current_end - new_start..].to_vec());
                    tmp_fragment = Some(ReceiveFragment {
                        sequence_num: current_start,
                        payload: fragment_marged,
                    });
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :                     <-O->
                // result   :          <---O--->  <-O-> (add last fragment as tmp)
                } else if current_end + 1 < pending_start {
                    pending_new.push(ReceiveFragment {
                        sequence_num: *current_seq,
                        payload: current_payload.clone(),
                    });
                    tmp_fragment = Some(ReceiveFragment {
                        sequence_num: new_start,
                        payload: payload.to_vec(),
                    });
                    continue;
                }
                anyhow::bail!(
                    "Impossible range: pending_start={} new_start={} new_end={} current_start={} current_end={}",
                    pending_start, new_start, new_end, current_start, current_end
                );
            }
        }
        if self.fragmented_datagram.len() == 0 {
            pending_new.push(ReceiveFragment {
                sequence_num: pending_start,
                payload: payload[pending_start - new_start..].to_vec(),
            });
        }
        if let Some(tmp) = tmp_fragment {
            if !complete_marge {
                pending_new.push(tmp);
            }
        }
        if let Some(first) = pending_new.first() {
            if first.sequence_num == complete_end + 1 {
                self.complete_datagram
                    .payload
                    .append(&mut first.payload.clone());
                pending_new.remove(0);
            }
        }
        self.fragmented_datagram = pending_new;
        Ok(())
    }

    // After read from recv queue, we need to update RCV.WND.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let old_begin = self.complete_datagram.sequence_num;
        let old_len = self.complete_datagram.payload.len();
        let copy_len = min(buf.len(), self.complete_datagram.payload.len());
        buf[..copy_len].copy_from_slice(&self.complete_datagram.payload[..copy_len]);
        self.complete_datagram.payload.drain(..copy_len);

        let new_begin = self.complete_datagram.sequence_num + copy_len;
        if new_begin >= TCP_RECV_QUEUE_WRAP {
            self.complete_datagram.sequence_num = new_begin - TCP_RECV_QUEUE_WRAP;
            self.fragmented_datagram.iter_mut().for_each(|frag| {
                frag.sequence_num -= TCP_RECV_QUEUE_WRAP;
            });
        } else {
            self.complete_datagram.sequence_num = new_begin;
        }
        log::trace!(
            "Read {} bytes from recv queue. (head: {} -> {} len: {} -> {})",
            copy_len,
            old_begin,
            new_begin,
            old_len,
            self.complete_datagram.payload.len()
        );
        Ok(copy_len)
    }

    pub fn get_current(&self) -> String {
        let complete_str = if self.complete_datagram.payload.is_empty() {
            self.complete_datagram.sequence_num.to_string()
        } else {
            format!(
                "{} (LEN:{})",
                self.complete_datagram.sequence_num,
                self.complete_datagram.payload.len()
            )
        };

        let fragments_str = self
            .fragmented_datagram
            .iter()
            .map(|frag| format!("{} (LEN:{})", frag.sequence_num, frag.payload.len()))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "QUEUE.LEN={} COMPLETE: {} FRAGMENT: {}",
            self.queue_length,
            complete_str,
            if fragments_str.is_empty() {
                "None".to_string()
            } else {
                fragments_str
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcpEventType {
    InitialState,
    SocketAccepted,
    SynReceived,
    Established,
    Closed,
    Refused,
    DatagramReceived,
    SendMore,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpEvent {
    pub socket_id: usize,
    pub event: TcpEventType,
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        13,
        vec![9; 4],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        15,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        16,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 16,
                payload: vec![9, 9]
            },
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        18,
        vec![9; 4],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![9, 9, 6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        20,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        20,
        vec![9; 5],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8, 9, 9]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        18,
        vec![9; 14],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![9, 9, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        23,
        vec![9; 7],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        23,
        vec![9; 13],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4, 9, 9]
            }
        ]
    )]
    #[case(
        25,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![9, 9]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        37,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            },
            ReceiveFragment {
                sequence_num: 37,
                payload: vec![9, 9]
            }
        ]
    )]
    #[case(
        15,
        vec![9; 5],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9, 9, 9, 9, 6, 7, 8]
        },
        vec![
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ]
    )]
    #[case(
        15,
        vec![9; 15],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9, 9, 9, 9, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4]
        },
        vec![]
    )]
    #[case(
        13,
        vec![9; 22],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9, 9, 9, 9, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4, 9]
        },
        vec![]
    )]
    fn test_receive_queue_add_2_pending(
        #[case] new_fragment_seq: usize,
        #[case] new_fragment_payload: Vec<u8>,
        #[case] expected_complete: ReceiveFragment,
        #[case] expected_pending: Vec<ReceiveFragment>,
    ) {
        let initial_complete = ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5],
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8],
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4],
            },
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending,
        };
        let result = queue
            .add(new_fragment_seq, &new_fragment_payload)
            .expect("Failed to add fragment to queue.");

        assert_eq!(queue.complete_datagram, expected_complete);
        assert_eq!(queue.fragmented_datagram, expected_pending);
        assert_eq!(result, ());
    }

    #[rstest]
    #[case(
        23,
        vec![9; 8],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 23,
                payload: vec![9, 9, 2, 3, 4, 5, 9, 9]
            },
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5]
            }
        ]
    )]
    #[case(
        23,
        vec![9; 9],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 23,
                payload: vec![9, 9, 2, 3, 4, 5, 9, 9, 9, 8, 7, 6, 5]
            }
        ]
    )]
    #[case(
        23,
        vec![9; 14],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 23,
                payload: vec![9, 9, 2, 3, 4, 5, 9, 9, 9, 8, 7, 6, 5, 9]
            }
        ]
    )]
    #[case(
        30,
        vec![9; 1],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![9]
            },
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5]
            }
        ]
    )]
    #[case(
        30,
        vec![9; 4],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5]
        },
        vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![9, 9, 8, 7, 6, 5]
            }
        ]
    )]
    #[case(
        13,
        vec![9; 18],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9, 9, 6, 7, 8, 6, 9, 9, 9, 2, 3, 4, 5, 9, 9]
        },
        vec![
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5]
            }
        ]
    )]
    #[case(
        15,
        vec![9; 16],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5, 9, 9, 9, 6, 7, 8, 6, 9, 9, 9, 2, 3, 4, 5, 9, 9]
        },
        vec![
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5]
            }
        ]
    )]
    fn test_receive_queue_add_3_pending(
        #[case] new_fragment_seq: usize,
        #[case] new_fragment_payload: Vec<u8>,
        #[case] expected_complete: ReceiveFragment,
        #[case] expected_pending: Vec<ReceiveFragment>,
    ) {
        let initial_complete = ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 4, 5],
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6],
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5],
            },
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5],
            },
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending,
        };
        let result = queue
            .add(new_fragment_seq, &new_fragment_payload)
            .expect("Failed to add fragment to queue.");

        assert_eq!(queue.complete_datagram, expected_complete);
        assert_eq!(queue.fragmented_datagram, expected_pending);
        assert_eq!(result, ());
    }

    #[rstest]
    #[case(
        13,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![]
        },
        vec![
            ReceiveFragment {
                sequence_num: 13,
                payload: vec![9, 9]
            },
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            }
        ]
    )]
    #[case(
        13,
        vec![9; 5],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![]
        },
        vec![
            ReceiveFragment {
                sequence_num: 13,
                payload: vec![9, 9, 9, 9, 9, 6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            }
        ]
    )]
    fn test_receive_queue_add_no_complete(
        #[case] new_fragment_seq: usize,
        #[case] new_fragment_payload: Vec<u8>,
        #[case] expected_complete: ReceiveFragment,
        #[case] expected_pending: Vec<ReceiveFragment>,
    ) {
        let initial_complete = ReceiveFragment {
            sequence_num: 10,
            payload: vec![],
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6],
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5],
            },
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending,
        };
        let result = queue
            .add(new_fragment_seq, &new_fragment_payload)
            .expect("Failed to add fragment to queue.");

        assert_eq!(queue.complete_datagram, expected_complete);
        assert_eq!(queue.fragmented_datagram, expected_pending);
        assert_eq!(result, ());
    }

    #[rstest]
    #[case(
        13,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 9, 9]
        },
        vec![]
    )]
    #[case(
        11,
        vec![9; 4],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3, 9, 9]
        },
        vec![]
    )]
    fn test_receive_queue_add_simple(
        #[case] new_fragment_seq: usize,
        #[case] new_fragment_payload: Vec<u8>,
        #[case] expected_complete: ReceiveFragment,
        #[case] expected_pending: Vec<ReceiveFragment>,
    ) {
        let initial_complete = ReceiveFragment {
            sequence_num: 10,
            payload: vec![1, 2, 3],
        };
        let initial_pending = vec![];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending,
        };
        let result = queue
            .add(new_fragment_seq, &new_fragment_payload)
            .expect("Failed to add fragment to queue.");

        assert_eq!(queue.complete_datagram, expected_complete);
        assert_eq!(queue.fragmented_datagram, expected_pending);
        assert_eq!(result, ());
    }

    #[rstest]
    #[case(
        10,
        vec![9; 2],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![9, 9]
        },
        vec![]
    )]
    #[case(
        10,
        vec![9; 1],
        ReceiveFragment {
            sequence_num: 10,
            payload: vec![9]
        },
        vec![]
    )]
    fn test_receive_queue_add_to_empty(
        #[case] new_fragment_seq: usize,
        #[case] new_fragment_payload: Vec<u8>,
        #[case] expected_complete: ReceiveFragment,
        #[case] expected_pending: Vec<ReceiveFragment>,
    ) {
        let initial_complete = ReceiveFragment {
            sequence_num: 10,
            payload: vec![],
        };
        let initial_pending = vec![];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending,
        };
        let result = queue
            .add(new_fragment_seq, &new_fragment_payload)
            .expect("Failed to add fragment to queue.");

        assert_eq!(queue.complete_datagram, expected_complete);
        assert_eq!(queue.fragmented_datagram, expected_pending);
        assert_eq!(result, ());
    }

    #[rstest]
    #[case(
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 10,
                payload: vec![1, 2, 3, 4, 5]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 18,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 25,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 15,
                payload: vec![]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 18,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 25,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        5,
        vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0]
    )]
    #[case(
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 5,
                payload: vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 18,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 25,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 15,
                payload: vec![1]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 18,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 25,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        10,
        vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5]
    )]
    fn test_receive_queue_read_10(
        #[case] mut queue: ReceiveQueue,
        #[case] expected_after_queue: ReceiveQueue,
        #[case] expected_data_len: usize,
        #[case] expected_buf_after: Vec<u8>,
    ) {
        let mut buf = [0; 10];
        let data_len = queue.read(&mut buf).unwrap();

        assert_eq!(buf, expected_buf_after[..10]);
        assert_eq!(data_len, expected_data_len);
        assert_eq!(queue, expected_after_queue);
    }

    #[rstest]
    #[case(
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: TCP_RECV_QUEUE_WRAP - 3,
                payload: vec![1, 2, 3, 4, 5, 6, 7]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: TCP_RECV_QUEUE_WRAP + 7,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: TCP_RECV_QUEUE_WRAP + 14,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 2,
                payload: vec![6, 7]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 7,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 14,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        5,
        vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0]
    )]
    #[case(
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: TCP_RECV_QUEUE_WRAP - 3,
                payload: vec![1, 2, 3, 4]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: TCP_RECV_QUEUE_WRAP + 7,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: TCP_RECV_QUEUE_WRAP + 14,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: ReceiveFragment {
                sequence_num: 1,
                payload: vec![]
            },
            fragmented_datagram: vec![
                ReceiveFragment {
                    sequence_num: 7,
                    payload: vec![6, 7, 8, 6]
                },
                ReceiveFragment {
                    sequence_num: 14,
                    payload: vec![2, 3, 4, 5]
                }
            ]
        },
        4,
        vec![1, 2, 3, 4, 0, 0, 0, 0, 0, 0]
    )]
    fn test_receive_queue_read_5_wrapped(
        #[case] mut queue: ReceiveQueue,
        #[case] expected_after_queue: ReceiveQueue,
        #[case] expected_data_len: usize,
        #[case] expected_buf_after: Vec<u8>,
    ) {
        let mut buf = [0; 5];
        let data_len = queue.read(&mut buf).unwrap();

        assert_eq!(buf, expected_buf_after[..5]);
        assert_eq!(data_len, expected_data_len);
        assert_eq!(queue, expected_after_queue);
    }

    #[rstest]
    #[case(1, 3, 2, true)]
    #[case(MAX_SEQ - 1, 2, 1, true)]
    #[case(MAX_SEQ - 1, 2, 2, true)]
    #[case(MAX_SEQ - 1, 2, MAX_SEQ, true)]
    #[case(MAX_SEQ - 1, 2, MAX_SEQ - 1, true)]
    #[case(MAX_SEQ - 1, 2, MAX_SEQ - 2, false)]
    #[case(MAX_SEQ - 1, 2, 3, false)]
    #[case(12, 10, 9, false)]
    #[case(12, 10, 10, false)]
    #[case(12, 10, 11, false)]
    #[case(12, 10, 12, false)]
    #[case(11, 10, 9, false)]
    #[case(11, 10, 10, false)]
    #[case(11, 10, 11, false)]
    #[case(11, 10, 12, false)]
    #[case(11, 11, 11, true)]
    fn test_seq_in_range(
        #[case] min: u32,
        #[case] max: u32,
        #[case] target: u32,
        #[case] expected_result: bool,
    ) {
        assert_eq!(seq_in_range(min, max, target), expected_result)
    }
}
