use crate::{
    l2_l3::{defs::Ipv4Type, ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration}},
    tcp::{defs::{TcpStatus, TcpError}, packet::{TcpPacket, TcpFlag}, timer::TcpTimer}
};
use anyhow::{Context, Result};
use log;
use pnet::packet::tcp::Tcp;
use std::{cmp::{max, min}, collections::{HashMap, VecDeque}, sync::MutexGuard, time::Duration};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc::channel};
use std::thread::{self, JoinHandle};
use std::time::{Instant};

const MAX_SEQ: u32 = u32::MAX;

const TCP_MAX_SOCKET: usize = 100;
// "the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535 (never assigned)" rfc6335
const TCP_EPHEMERAL_PORT_RANGE: Range<u16> = 49152..65535;
// "The present global default is five minutes." rfc9293
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_MAX_CONCURRENT_SESSION: usize = 10;
const TCP_MAX_LISTEN_QUEUE: usize = TCP_MAX_CONCURRENT_SESSION * 3 / 2;
const TCP_DEFAULT_SEND_QUEUE_LENGTH: usize = 4096;
const TCP_DEFAULT_RECV_QUEUE_LENGTH: usize = 4096;
const TCP_RECV_QUEUE_WRAP: usize = 1 << 32;
const TCP_NO_DELAY: bool = true;

static TCP_STACK_GLOBAL: OnceLock<Arc<TcpStack>> = OnceLock::new();

pub fn get_global_tcpstack(config: NetworkConfiguration) -> Result<&'static Arc<TcpStack>> {
    Ok(TCP_STACK_GLOBAL.get_or_init(|| TcpStack::new(config).unwrap()))
}

pub struct TcpStack {
    pub config: NetworkConfiguration,
    pub connections: Mutex<HashMap<usize, Option<TcpConnection>>>,
    pub listen_queue: Mutex<HashMap<usize, ListenQueue>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    event_condvar: (Mutex<TcpEvent>, Condvar)
}

impl TcpStack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let tcp = Arc::new(Self {
            config: config,
            connections: Mutex::new(HashMap::new()),
            listen_queue: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            event_condvar: (Mutex::new(TcpEvent {socket_id: 0, event: TcpEventType::InitialState}), Condvar::new())
        });

        let tcp_recv = tcp.clone();
        let handle_recv = thread::spawn(move || {
            tcp_recv.receive_thread().unwrap();
        });
        tcp.threads.lock().unwrap().push(handle_recv);

        let tcp_timer = tcp.clone();
        let handle_timer = thread::spawn(move || {
            tcp_timer.timer_thread().unwrap();
        });
        tcp.threads.lock().unwrap().push(handle_timer);

        Ok(tcp)
    }

    pub fn generate_socket(&self) -> Result<usize> {
        let mut conns = self.connections.lock().unwrap();
        for id in 1..=TCP_MAX_SOCKET {
            if conns.contains_key(&id) {
                continue;
            } else {
                conns.insert(id, None);
                log::info!("Generated socket. id={}", id);
                return Ok(id);
            }
        }
        anyhow::bail!("Failed to generate a new tcp socket because no available id. TCP_MAX_SOCKET={}", TCP_MAX_SOCKET)
    }

    pub fn release_socket(&self, socket_id: usize) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        conns.remove(&socket_id);
        let mut listen_queue = self.listen_queue.lock().unwrap();
        if let Some(queue) = listen_queue.get_mut(&socket_id) {
            queue.pending.retain(|&x| x != socket_id);
            queue.pending_acked.retain(|&x| x != socket_id);
            queue.established_unconsumed.retain(|&x| x != socket_id);
            queue.established_consumed.retain(|&x| x != socket_id);
        }
        listen_queue.remove(&socket_id);
        Ok(())
    }

    pub fn bind(&self, socket_id: usize, addr: SocketAddrV4) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        let used_ports: Vec<u16> = conns.values()
            .filter_map(|conn| conn.as_ref().map(|c| c.local_port))
            .collect();
        if let Some(conn_wrap) = conns.get_mut(&socket_id) {
            if let Some(conn) = conn_wrap {
                anyhow::bail!("Tcp socket (id={}) has already bound to {}:{}.", socket_id, conn.src_addr, conn.local_port);
            } else {
                // assign ephemeral port
                if addr.port() == 0 {
                    for port in TCP_EPHEMERAL_PORT_RANGE {
                        if !used_ports.contains(&port) {
                            let new_conn = TcpConnection::new(
                                *addr.ip(), port, Ipv4Addr::UNSPECIFIED, 0
                            );
                            conns.insert(socket_id, Some(new_conn));
                            log::info!("Tcp socket (id={}) bind to the ephemeral port {}:{}.", socket_id, *addr.ip(), port);
                            return Ok(());
                        }
                    }
                    anyhow::bail!("Failed to bind tcp socket. No available ephemeral port.");
                } else {
                    if !used_ports.contains(&addr.port()) {
                        let new_conn = TcpConnection::new(
                            *addr.ip(), addr.port(), Ipv4Addr::UNSPECIFIED, 0
                        );
                        conns.insert(socket_id, Some(new_conn));
                        log::info!("Tcp socket (id={}) bind to the specified port {}:{}.", socket_id, *addr.ip(), addr.port());
                    } else {
                        anyhow::bail!("Failed to bind tcp socket. Port {} is already used.", addr.port());
                    }
                }
                Ok(())
            }
        } else {
            anyhow::bail!("No tcp socket for id={}.", socket_id);
        }
    }

    pub fn listen(&self, socket_id: usize) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if conn.status == TcpStatus::Closed {
                conn.status = TcpStatus::Listen;
                let mut listen_queue = self.listen_queue.lock().unwrap();
                listen_queue.insert(
                    socket_id,
                    ListenQueue {
                        pending: VecDeque::new(), pending_acked: VecDeque::new(),
                        established_unconsumed: VecDeque::new(), established_consumed: VecDeque::new(),
                        accepted: 0
                    }
                );
                Ok(())
            } else {
                anyhow::bail!("Only a Closed socket can transit to Listen. Current: {}", conn.status);
            }
        } else {
            anyhow::bail!("Cannot listen Socket (id={}) which is not bound.", socket_id);
        }
    }

    pub fn accept(&self, socket_id: usize) -> Result<(usize, SocketAddrV4)> {
        let mut conns = self.connections.lock().unwrap();
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if conn.status == TcpStatus::Listen {
                let mut listen_queue = self.listen_queue.lock().unwrap();
                if let Some(queue) = listen_queue.get_mut(&socket_id) {
                    queue.accepted += 1;
                    if let Some(id) = queue.established_unconsumed.pop_front() {
                        if let Some(Some(conn_est)) = conns.get(&id) {
                            return Ok((id, SocketAddrV4::new(conn_est.dst_addr, conn_est.remote_port)));
                        } else {
                            log::error!("Established connection (id={}) dose not exist in TcpConnections", id);
                        }
                    }
                } else {
                    anyhow::bail!("No listen queue for the socket (id={}).", socket_id);
                }
                drop(conns);
                drop(listen_queue);
                loop {
                    let mut conns = self.connections.lock().unwrap();
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    if let Some(ref mut queue) = listen_queue.get_mut(&socket_id) {
                        if let Some(established_id) = queue.established_unconsumed.pop_front() {
                            if let Some(Some(conn)) = conns.get(&established_id) {
                                queue.established_consumed.push_back(established_id);
                                queue.accepted -= 1;
                                log::info!("Established socket (id={}) is conusmed by accept call. {}", established_id, conn.print_address());
                                return Ok((established_id, SocketAddrV4::new(conn.dst_addr, conn.remote_port)));
                            } else {
                                log::error!("Established connection (id={}) dose not exist in TcpConnections", established_id);
                                continue;
                            }
                        }
                        // there is a already pending connection which received syn but not yet replied syn-ack.
                        if let Some(syn_recv_id) = queue.pending.pop_front() {
                            // reply syn-ack
                            if let Some(Some(conn)) = conns.get_mut(&syn_recv_id) {
                                if conn.status != TcpStatus::SynRcvd { continue; }
                                let mut syn_ack = TcpPacket::new_syn_rcvd(conn)?;
                                syn_ack.option.mss = Some((self.config.mtu - 40) as u16);
                                if let Err(e) = self.send_tcp_packet(syn_ack) {
                                    log::warn!("Sending syn-ack failed. Err: {}", e);
                                    continue;
                                } else {
                                    log::debug!(
                                        "Accepted socket (id={}) reply syn-ack to {}:{}. SEQ={} ACK={}",
                                        syn_recv_id, conn.dst_addr, conn.remote_port,
                                        conn.send_vars.next_sequence_num, conn.recv_vars.next_sequence_num,
                                    );
                                    conn.syn_replied = true;
                                    queue.pending_acked.push_back(syn_recv_id);
                                }
                            }
                            drop(conns);
                            drop(listen_queue);
                            loop {
                                // Current TcpStatus is SynRcvd
                                if let (_valid, Some(event)) = self.wait_events_with_timeout(
                                    vec![
                                        TcpEvent { socket_id: syn_recv_id, event: TcpEventType::Established },
                                        TcpEvent { socket_id: syn_recv_id, event: TcpEventType::Refused },
                                        TcpEvent { socket_id: syn_recv_id, event: TcpEventType::Closed }
                                    ],
                                    Duration::from_millis(100)
                                ) {
                                    match event.event {
                                        TcpEventType::Established => {
                                            // event received, expected that syn_recv_id's state is established.
                                            let mut conns = self.connections.lock().unwrap();
                                            let mut listen_queue = self.listen_queue.lock().unwrap();
                                            if let (Some(Some(conn)), Some(queue)) = (
                                                conns.get_mut(&syn_recv_id),
                                                listen_queue.get_mut(&socket_id)
                                            ) {
                                                if conn.status == TcpStatus::Established {
                                                    queue.established_consumed.push_back(syn_recv_id);
                                                    queue.accepted -= 1;
                                                    log::info!("Accepted socket (id={}) connection established. {}", syn_recv_id, conn.print_address());
                                                    return Ok((syn_recv_id, SocketAddrV4::new(conn.dst_addr, conn.remote_port)));
                                                } else {
                                                    break;
                                                }
                                            } else {
                                                anyhow::bail!("TcpConnection or ListenQueue is not found for socket {}.", socket_id);
                                            }
                                        }
                                        TcpEventType::Refused => {
                                            log::debug!("While waiting for the socket (id={} parent={}) connection establishment, the connection refused.", syn_recv_id, socket_id);
                                            break;
                                        }
                                        TcpEventType::Closed => {
                                            log::debug!("While waiting for the socket (id={} parent={}) connection establishment, the connection closed.", syn_recv_id, socket_id);
                                            break;
                                        }
                                        other => {
                                            anyhow::bail!("Wake up from unexpected event ({:?}). Expected Established/Refused/Closed.", other);
                                        }
                                    }
                                } else {
                                    // timeout occured
                                    let mut conns = self.connections.lock().unwrap();
                                    if let Some(Some(conn)) = conns.get_mut(&syn_recv_id) {
                                        if conn.status == TcpStatus::SynRcvd { continue; }
                                    }
                                    // SYN-RECIEVED socket may be removed in a situation like "Recovery from Old Duplicate SYN".
                                    // In that case, we come to here and start from outer loop again
                                    break;
                                }
                            }
                        // Currently there is no pending connection, so wait until SynReceived...
                        } else {
                            drop(conns);
                            drop(listen_queue);
                            loop {
                                if self.wait_event_with_timeout(
                                    TcpEvent { socket_id: socket_id, event: TcpEventType::SynReceived },
                                    Duration::from_millis(100)
                                ) {
                                    log::debug!("Wake up that accepted LISTEN socket (id={}) spawn SYN-RECEIVED client socket.", socket_id);
                                    break;
                                } else {
                                    let listen_queue = self.listen_queue.lock().unwrap();
                                    if let Some(queue) = listen_queue.get(&socket_id) {
                                        if queue.established_unconsumed.len() > 0 {
                                            break;
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                    } else {
                        anyhow::bail!("No listen queue for the socket (id={}).", socket_id);
                    }
                }
            } else {
                anyhow::bail!("Cannot accept a socket which status is not Listen. Current: {}", conn.status);
            }
        } else {
            anyhow::bail!("Cannot accept the socket (id={}) which is not bound.", socket_id);
        }
    }

    pub fn connect(&self, socket_id: usize, addr: SocketAddrV4) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            let seq = self.generate_initial_sequence();
            conn.dst_addr = *addr.ip();
            conn.remote_port = addr.port();
            conn.status = TcpStatus::SynSent;
            conn.parent_id = None;
            conn.send_vars.initial_sequence_num = seq;
            conn.send_vars.unacknowledged = seq;
            conn.send_vars.next_sequence_num = seq.wrapping_add(1);
            conn.recv_vars.window_size = conn.get_recv_window_size();
            conn.recv_vars.recv_mss = self.config.mtu - 40;
            if let Err(e) = self.send_handler(conn) {
                log::warn!("Failed to send SYN. (1st time) Err: {:?}", e);
            }
            conn.timer.retransmission.fire_syn();
            log::debug!("Socket (id={}) status changed from CLOSED to SYN-SENT. Sent syn to {}:{}. SEG.SEQ={}", socket_id, addr.ip(), addr.port(), seq);
        } else {
            anyhow::bail!("Socket (id={}) is not bound.", socket_id);
        }
        drop(conns);
        loop {
            if let (_valid, Some(event)) = self.wait_events_with_timeout(
                vec![
                    TcpEvent { socket_id: socket_id, event: TcpEventType::Established },
                    TcpEvent { socket_id: socket_id, event: TcpEventType::Refused },
                    TcpEvent { socket_id: socket_id, event: TcpEventType::Closed }
                ],
                Duration::from_millis(100)
            ) {
                match event.event {
                    TcpEventType::Established => {
                        let conns = self.connections.lock().unwrap();
                        if let Some(Some(conn)) = conns.get(&socket_id) {
                            if conn.status == TcpStatus::Established {
                                return Ok(());
                            } else {
                                anyhow::bail!("Wake up mismatch. Expecting socket (id={}) becomes ESTABLISHED but currently {}.", socket_id, conn.status);
                            }
                        } else {
                            anyhow::bail!("Socket (id={}) is not bound.", socket_id);
                        }
                    }
                    TcpEventType::Refused => {
                        anyhow::bail!(TcpError::RefusedError { id: socket_id, addr: addr })
                    }
                    TcpEventType::Closed => {
                        anyhow::bail!(TcpError::ClosedError { id: socket_id, addr: addr })
                    }
                    other => {
                        anyhow::bail!("Wake up from unexpected event ({:?}). Expected Established/Refused.", other);
                    }
                }
            // timeout occured, so wait again
            } else {
                continue;
            }
        }
    }

    pub fn write(
        &self,
        socket_id: usize,
        payload: &[u8]
    ) -> Result<usize> {
        let mut current_offset: usize = 0;
        let payload_len = payload.len();
        loop {
            let mut conns = self.connections.lock().unwrap();
            if let Some(Some(conn)) = conns.get_mut(&socket_id) {
                let current_queue_free = conn.send_queue.queue_length - conn.send_queue.payload.len();
                if current_queue_free == 0 {
                    // Unix system returns EAGAIN in this situation.
                    anyhow::bail!("No free space in send queue. length: {}", conn.send_queue.queue_length);
                }
                if (payload_len - current_offset) <= current_queue_free {
                    conn.send_queue.payload.extend_from_slice(&payload[current_offset..]);
                    current_offset += payload_len;
                } else {
                    conn.send_queue.payload.extend_from_slice(&payload[current_offset..current_offset+current_queue_free]);
                    current_offset += current_queue_free
                }
                if let Err(e) = self.send_handler(conn) {
                    log::warn!("Failed to send datagram. Err: {e:?}");
                }
            } else {
                anyhow::bail!("Cannot find the socket (id={}).", socket_id);
            }
            if current_offset == payload_len {
                return Ok(current_offset);
            } else {
                drop(conns);
                if let (_valid, Some(event)) = self.wait_events_with_timeout(
                    vec![
                        TcpEvent { socket_id: socket_id, event: TcpEventType::DatagramReceived },
                        TcpEvent { socket_id: socket_id, event: TcpEventType::Refused },
                        TcpEvent { socket_id: socket_id, event: TcpEventType::Closed }
                    ],
                    Duration::from_millis(100)
                ) {
                    match event.event {
                        TcpEventType::DatagramReceived => {
                            continue;
                        }
                        TcpEventType::Refused => {
                            log::warn!("While waiting for the socket (id={}) sending datagram, the connection refused.", socket_id);
                        }
                        TcpEventType::Closed => {
                            log::warn!("While waiting for the socket (id={}) sending datagram, the connection closed.", socket_id);
                        }
                        other => {
                            anyhow::bail!("Wake up from unexpected event ({:?}). Expected Established/Refused/Closed.", other);
                        }
                    }
                }
            }
        }
    }

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
        let mut syn_packet = TcpPacket::new_out_packet(conn)?;
        syn_packet.option.mss = Some(conn.recv_vars.recv_mss as u16);
        self.send_tcp_packet(syn_packet)?;
        Ok(0)
    }

    pub fn send_handler_syn_rcvd(
        &self,
        conn: &mut TcpConnection
    ) -> Result<usize> {
        let syn_ack_packet = TcpPacket::new_out_packet(conn)?;
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
        if !TCP_NO_DELAY && send_una != send_nxt && ((new_data as u16) < send_mss || send_wnd < send_mss as usize) && !conn.ack_now {
            log::debug!(
                "We won't send a datagram here based on Nagle's algo. SND.UNA={} SND.NXT={} SND.WND={} SND.MSS={} PENDING_DATAGRAM_LENGTH={}",
                send_una, send_nxt, send_wnd, send_mss, new_data
            );
            Ok(0)
        } else {
            while next_send_nxt != conn.send_vars.next_sequence_num {
                let datagram = TcpPacket::new_out_packet(conn).context("Failed to create a datagram packet.")?;
                let datagram_size = datagram.payload.len() as u32;
                self.send_tcp_packet_safe(datagram)?;
                if conn.rtt_start.is_none() {
                    conn.rtt_start = Some(Instant::now());
                }
                conn.send_vars.next_sequence_num = conn.send_vars.next_sequence_num.wrapping_add(datagram_size);
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
    fn receive_thread(&self) -> Result<()> {
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
            &tcp_packet.remote_port
        )?;
        if let Some(id) = socket_id {
            if let Some(Some(conn)) = conns.get(&id) {
                log::trace!("Handling packet for {} socket (id={} {}).", conn.status, id, conn.print_address());
                match &conn.status {
                    TcpStatus::Listen => { self.recv_handler_listen(id, tcp_packet, conns).context("listen_handler failed.")?; }
                    TcpStatus::SynSent => { self.recv_handler_syn_sent(id, tcp_packet, conns).context("syn_sent_handler failed.")?; }
                    TcpStatus::SynRcvd => { self.recv_handler_syn_rcvd(id, tcp_packet, conns).context("syn_rcvd_handler failed.")?; }
                    TcpStatus::Established => { self.recv_handler_established(id, tcp_packet, conns).context("established_handler failed.")?; }
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
                log::debug!("No socket bound for the packet to {}:{}, send back rst packet.", dst_addr, tcp_packet.remote_port);
            // "An incoming segment containing a RST is discarded." rfc9293
            } else {
                log::debug!("No socket bound for the rst packet to {}:{}, ignored it.", dst_addr, tcp_packet.remote_port);
            }
            Ok(())
        }
    }

    pub fn get_socket_id(
        &self,
        src_addr: &Ipv4Addr,
        dst_addr: &Ipv4Addr,
        local_port: &u16,
        remote_port: &u16,
    ) -> Result<(Option<usize>, MutexGuard<HashMap<usize, Option<TcpConnection>>>)> {
        let conns = self.connections.lock().unwrap();
        let mut listen_ids = Vec::new();
        let mut ids = Vec::new();
        for (id, connection_info) in conns.iter() {
            // The order of matching is important because there can be multiple connections with
            // the same src_addr and local_port in the listen_queue.
            if let Some(TcpConnection {
                src_addr: s_addr,
                dst_addr: d_addr,
                local_port: l_port,
                remote_port: r_port,
                status: _status,
                parent_id: _parent_id,
                syn_replied: _syn_replied,
                send_vars: _send_vars,
                recv_vars: _recv_vars,
                send_queue: _send_buffer,
                recv_queue: _recv_buffer,
                timer: _timer,
                rtt_start: _rtt_start,
                ack_now: _ack_now,
            }) = connection_info {
                if s_addr == dst_addr && d_addr == src_addr && l_port == remote_port && r_port == local_port {
                    ids.push(*id);
                } else if s_addr == dst_addr && *d_addr == Ipv4Addr::UNSPECIFIED && l_port == remote_port && *r_port == 0 {
                    listen_ids.push(*id);
                } else {
                    continue;
                }
            }
        }
        if listen_ids.len() == 0 && ids.len() == 0 {
            log::debug!("There is no tcp socket for the packet (src={}:{} dst={}:{}).", src_addr, local_port, dst_addr, remote_port);
            Ok((None, conns))
        } else if (listen_ids.len() == 1 || listen_ids.len() == 0) && ids.len() == 1 {
            Ok((ids.pop(), conns))
        } else if listen_ids.len() == 1 && ids.len() == 0 {
            Ok((listen_ids.pop(), conns))
        } else {
            log::error!(
                "Panic because duplicate socket detected. src={}:{} dst={}:{}",
                dst_addr, remote_port, src_addr, local_port
            );
            panic!();
        }
    }

    // 3.10.7.2 LISTEN STATE rfc9293
    pub fn recv_handler_listen(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>
    ) -> Result<()> {
        if tcp_packet.flag.contains(TcpFlag::RST) {
            log::debug!(
                "LISTEN socket (id={}) ignores any rst packet. remote={}:{}",
                socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
            );
            return Ok(());
        };
        if tcp_packet.flag.contains(TcpFlag::ACK) {
            self.send_back_rst_ack(tcp_packet)?;
            log::debug!(
                "LISTEN socket (id={}) rejects any ack packet and send back rst. remote={}:{}",
                socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
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
            let len_established = queue.established_unconsumed.len() + queue.established_consumed.len();
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
                        send_vars.window_shift = scale as usize;
                        send_vars.window_size = tcp_packet.windows_size >> scale;
                    } else {
                        send_vars.window_size = tcp_packet.windows_size;
                    }
                    let mut recv_vars = ReceiveVariables::new();
                    let mut recv_queue = ReceiveQueue::new();
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
                        ack_now: false,
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
                        self.send_tcp_packet(syn_ack).context("Failed to send SYN/ACK.")?;
                        log::debug!(
                            "Accepted socket (id={}) reply SYN/ACK to {}:{} in listen_handler. SEQ={} ACK={}",
                            id, dst_addr, tcp_packet.local_port, seq, ack
                        );
                        self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::SynReceived });
                    } else {
                        conns.insert(id, Some(new_conn));
                        queue.pending.push_back(id);
                    }
                    return Ok(());
                }
            }
            anyhow::bail!("Failed to generate a new tcp socket because there is no available id. TCP_MAX_SOCKET={}", TCP_MAX_SOCKET)
        } else {
            anyhow::bail!("No listen queue for socket id {} which status is Listen.", socket_id);
        }
    }

    // 3.10.7.3 SYN-SENT STATE rfc9293
    pub fn recv_handler_syn_sent(
        &self,
        socket_id: usize,
        tcp_packet: &TcpPacket,
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if tcp_packet.flag.contains(TcpFlag::ACK) {
                // This case includes "Recovery from Old Duplicate SYN" rfc9293
                if tcp_packet.ack_number <= conn.recv_vars.initial_sequence_num || tcp_packet.ack_number > conn.send_vars.next_sequence_num {
                    self.send_back_rst_ack(tcp_packet)?;
                    log::debug!(
                        "SYN-SENT socket rejects an unacceptable ack packet and send back rst. socket_id={} {} Expected ACK={} but received ACK={}",
                        socket_id, conn.print_address(), conn.send_vars.next_sequence_num, tcp_packet.ack_number
                    );
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                if tcp_packet.ack_number == conn.send_vars.next_sequence_num {
                    log::debug!(
                        "Socket (id={}) status changed from SYN-SENT to CLOSED. Received acceptable RST. {} ACK={})",
                        socket_id, conn.print_address(), tcp_packet.ack_number
                    );
                    conn.status = TcpStatus::Closed;
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Closed });
                    return Ok(());
                } else {
                    log::debug!(
                        "SYN-SENT socket ignores rst packet with unacceptable ACK. socket_id={} remote={}:{} Expected ACK={} but received ACK={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, conn.recv_vars.next_sequence_num, tcp_packet.ack_number
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
                    ack_packet.windows_size = conn.get_recv_window_for_pkt();
                    self.send_tcp_packet(ack_packet).context("Failed to reply ACK.")?;
                    if let Some(mss) = tcp_packet.option.mss {
                        conn.send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        conn.send_vars.send_mss = 536;
                    }
                    if let Some(scale) = tcp_packet.option.window_scale {
                        conn.send_vars.window_shift = scale as usize;
                        conn.send_vars.window_size = tcp_packet.windows_size >> scale;
                    } else {
                        conn.send_vars.window_size = tcp_packet.windows_size;
                    }
                    conn.send_vars.unacknowledged = next_seq;
                    conn.send_vars.next_sequence_num = next_seq; // change nothing.
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    conn.send_vars.max_window_size = conn.send_vars.get_scaled_send_window_size();
                    conn.recv_vars.initial_sequence_num = tcp_packet.seq_number;
                    conn.recv_vars.next_sequence_num = next_ack;
                    conn.recv_queue.complete_datagram.sequence_num = next_ack as usize;
                    conn.status = TcpStatus::Established;
                    conn.timer.retransmission.init();
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Established });
                    // SYN-SENT socket is always active open, so we don't need to push it to listen_queue.
                    log::debug!(
                        "Socket (id={}) status changed from SYN-SENT to ESTABLISHED. remote={}:{} NEXT send-SEQ={} recv-SEQ={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, next_ack, next_seq
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
                        conn.send_vars.window_shift = scale as usize;
                        conn.send_vars.window_size = tcp_packet.windows_size >> scale;
                    } else {
                        conn.send_vars.window_size = tcp_packet.windows_size;
                    }
                    conn.syn_replied = true;
                    conn.send_vars.unacknowledged = next_seq;
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    conn.send_vars.max_window_size = conn.send_vars.window_size as usize;
                    conn.recv_vars.next_sequence_num = next_ack;
                    conn.recv_queue.complete_datagram.sequence_num = next_ack as usize;
                    conn.status = TcpStatus::SynRcvd;
                    self.send_handler(conn)?;
                    log::debug!(
                        "Socket (id={}) status changed from SYN-SENT to SYN-RECEIVED. This is a Simultaneous Connection situation. remote={}:{}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
                    );
                    return Ok(());
                }
            }
            log::debug!(
                "SYN-SENT socket ignores packet. socket_id={} remote={}:{} flag={:?}",
                socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, tcp_packet.flag
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
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if !conn.syn_replied {
                log::debug!(
                    "SYN-RECEIVED socket (id={}) ignores every packet because syn_replied is false. In fact, this condition is not SYN-RECVED but is classified as such for convenience.",
                    socket_id
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
                        "SYN-RECEIVED socket (id={}) received unacceptable non-RST packet from {}:{} and just send back ACK. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={} SEG.flag={:?}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size, tcp_packet.flag
                    );
                } else {
                    log::debug!(
                        "SYN-RECEIVED socket (id={}) received unacceptable RST packet from {}:{} and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                }
                return Ok(());
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                // 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment. rfc9293
                if !(conn.recv_vars.next_sequence_num <= tcp_packet.seq_number && tcp_packet.seq_number < conn.recv_vars.next_sequence_num + conn.recv_vars.window_size as u32) {
                    log::debug!(
                        "SYN-RECEIVED socket (id={}) received RST packet from {}:{} that is outside of receive window and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
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
                            "SYN-RECEIVED socket (id={} parent={} passive open) is removed because of RST packet from {}:{}.",
                            socket_id, parent, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
                        );
                    // active open don't have a parent socket.
                    } else {
                        listen_queue.remove(&socket_id);
                        log::debug!(
                            "SYN-RECEIVED socket (id={} active open) is removed because of RST packet from {}:{}.",
                            socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
                        );
                    }
                    conns.remove(&socket_id);
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Refused });
                    return Ok(());
                // 3) If the RST bit is set and the sequence number does not exactly match the next expected sequence value, ... rfc9293
                } else {
                    // It's a challenge ACK situation, but I don't implement this now.
                    return Ok(());
                }
            }
            // If the connection was initiated with a passive OPEN, then return this connection to the LISTEN state and return. rfc9293
            if tcp_packet.flag.contains(TcpFlag::SYN) {
                if  let Some(parent) = conn.parent_id {
                    conns.remove(&socket_id);
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    if let Some(queue) = listen_queue.get_mut(&parent) {
                        queue.pending.retain(|&x| x != socket_id);
                        queue.pending_acked.retain(|&x| x != socket_id);
                    }
                    log::debug!(
                        "SYN-RECEIVED socket (id={} parent={} passive open) is removed because of SYN packet from {}:{}.",
                        socket_id, parent, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
                    );
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Refused });
                    return Ok(());
                }
            }
            // if the ACK bit is off, drop the segment and return rfc9293
            if !tcp_packet.flag.contains(TcpFlag::ACK) && !tcp_packet.flag.contains(TcpFlag::FIN) {
                log::debug!(
                    "SYN-RECEIVED socket (id={}) received a packet from {}:{} with SEG.FLAG={:?} and ignored.",
                    socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, tcp_packet.flag
                );
                return Ok(());
            } else if tcp_packet.flag.contains(TcpFlag::ACK) {
                // If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state... rfc9293
                if conn.send_vars.unacknowledged < tcp_packet.ack_number && tcp_packet.ack_number <= conn.send_vars.next_sequence_num {
                    if let Some(mss) = tcp_packet.option.mss {
                        conn.send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        conn.send_vars.send_mss = 536;
                    }
                    if let Some(scale) = tcp_packet.option.window_scale {
                        conn.send_vars.window_shift = scale as usize;
                        conn.send_vars.window_size = tcp_packet.windows_size >> scale;
                    } else {
                        conn.send_vars.window_size = tcp_packet.windows_size;
                    }
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    conn.send_vars.max_window_size = conn.send_vars.get_scaled_send_window_size();
                    conn.status = TcpStatus::Established;
                    conn.timer.retransmission.init();
                    let parent_id = conn.parent_id;
                    let mut listen_queue: MutexGuard<HashMap<usize, ListenQueue>> = self.listen_queue.lock().unwrap();
                    // If this socket is passive open, update listenQueue.
                    if let Some(parent) = parent_id {
                        if let Some(queue) = listen_queue.get_mut(&parent) {
                            queue.pending_acked.retain(|&x| x != socket_id);
                            queue.established_unconsumed.push_back(socket_id);
                        }
                    }
                    log::debug!(
                        "Socket (id={}) status changed from SYN-RECEIVED to ESTABLISHED. remote={}:{} SEG.FLAG={:?}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, tcp_packet.flag
                    );
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Established });
                    return Ok(());
                // If the segment acknowledgment is not acceptable, form a reset segment rfc9293
                } else {
                    self.send_back_rst_ack(tcp_packet)?;
                    log::debug!(
                        "SYN-RECEIVED socket (id={}) rejects unacceptable ack packet and send back rst. remote={}:{} ACK={} SND.UNA={} SND.NXT={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.ack_number, conn.send_vars.unacknowledged, conn.send_vars.next_sequence_num
                    );
                    return Ok(());
                }
            }
            if tcp_packet.flag.contains(TcpFlag::FIN) {
                conn.status = TcpStatus::CloseWait;
                log::debug!(
                    "Socket (id={}) status changed from SYN-RECEIVED to CLOSE-WAIT. remote={}:{} SEG.FLAG={:?}",
                    socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port, tcp_packet.flag
                );
                self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Closed });
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
        mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            // check if a segment is acceptable
            if !is_segment_acceptable(conn, tcp_packet) {
                if !tcp_packet.flag.contains(TcpFlag::RST) {
                    let mut ack = tcp_packet.create_reply_base();
                    ack.seq_number = conn.send_vars.next_sequence_num;
                    ack.ack_number = conn.recv_vars.next_sequence_num;
                    ack.flag = TcpFlag::ACK;
                    self.send_tcp_packet(ack).context("Failed to send ACK.")?;
                    log::debug!(
                        "ESTABLISHED socket (id={}) received unacceptable non-RST packet from {}:{} and just send back ACK. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                } else {
                    log::debug!(
                        "ESTABLISHED socket (id={}) received unacceptable RST packet from {}:{} and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
                    );
                }
                return Ok(());
            }
            if tcp_packet.flag.contains(TcpFlag::RST) {
                // 1) If the RST bit is set and the sequence number is outside the current receive window, silently drop the segment. rfc9293
                if !(conn.recv_vars.next_sequence_num <= tcp_packet.seq_number && tcp_packet.seq_number < conn.recv_vars.next_sequence_num + conn.recv_vars.window_size as u32) {
                    log::debug!(
                        "ESTABLISHED socket (id={}) received RST packet from {}:{} that is outside of receive window and ignored. SEG.SEQ={} SEG.LEN={} RCV.NXT={} RCV.WND={}",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port,
                        tcp_packet.seq_number, tcp_packet.payload.len(), conn.recv_vars.next_sequence_num, conn.recv_vars.window_size
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
                    log::debug!(
                        "ESTABLISHED socket (id={}) is removed because of RST packet from {}:{}.",
                        socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
                    );
                    conns.remove(&socket_id);
                    self.publish_event(TcpEvent { socket_id: socket_id, event: TcpEventType::Closed });
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
                    conn.send_vars.unacknowledged.wrapping_sub(conn.send_vars.max_window_size as u32),
                    conn.send_vars.next_sequence_num,
                    tcp_packet.ack_number
                ) {
                    // It's a challenge ACK situation too, but I don't implement this now.
                    return Ok(());
                }
                // If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. ... rfc9293
                if seq_in_range(
                    conn.send_vars.unacknowledged.wrapping_add(1),
                    conn.send_vars.next_sequence_num,
                    tcp_packet.ack_number
                ) {
                    log::debug!(
                        "SND.UNA advanced ({}->{} SND.NXT={}) for the ESTABLISHED socket (id={} {}).",
                        conn.send_vars.unacknowledged, tcp_packet.ack_number, conn.send_vars.next_sequence_num, socket_id, conn.print_address()
                    );
                    conn.update_snd_una(tcp_packet.ack_number)?;
                } else if seq_less_equal(tcp_packet.ack_number, conn.send_vars.unacknowledged) {
                    // If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored. rfc9293
                    log::debug!(
                        "ESTABLISHED socket (id={}) ignored duplicate ack. {} SND.UNA={} SEG.ACK={}",
                        socket_id, conn.print_address(), conn.send_vars.unacknowledged, tcp_packet.ack_number
                    );
                } else if seq_greater_than(tcp_packet.ack_number, conn.send_vars.next_sequence_num) {
                    // If the ACK acks something not yet sent (SEG.ACK > SND.NXT),
                    // then send an ACK, drop the segment, and return. rfc9293
                    conn.ack_now = true;
                    if let Err(e) = self.send_handler(conn) {
                        log::debug!(
                            "ESTABLISHED socket (id={} {}) acked, but failed. SEG.ACK={} SND.NXT={} Err: {:?}",
                            socket_id, conn.print_address(), tcp_packet.ack_number, conn.send_vars.next_sequence_num, e
                        );
                    }
                    conn.ack_now = false;
                    return Ok(());
                }
                if should_update_window(conn, tcp_packet) {
                    log::debug!(
                        "RCV.WND updated ({}->{} shift={} SEG.SEQ={} SEG.ACK={}) for the ESTABLISHED socket (id={} {}).",
                        conn.send_vars.window_size << conn.send_vars.window_shift , tcp_packet.windows_size << conn.send_vars.window_shift,
                        conn.send_vars.window_shift, tcp_packet.seq_number, tcp_packet.ack_number, socket_id, conn.print_address()
                    );
                    conn.send_vars.window_size = tcp_packet.windows_size;
                    conn.send_vars.last_sequence_num = tcp_packet.seq_number;
                    conn.send_vars.last_acknowledge_num = tcp_packet.ack_number;
                }
            }
            // Seventh, process the segment text: rfc9293
            if tcp_packet.payload.len() != 0 {
                conn.recv_queue.add(tcp_packet.seq_number as usize, &tcp_packet.payload)?;
                let rcv_nxt_advance = conn.recv_queue.complete_datagram.payload.len();
                let rcv_nxt_next = conn.recv_queue.get_real_begin_sequence_num().wrapping_add(rcv_nxt_advance as u32);
                log::debug!(
                    "RCV.NXT advanced ({}->{}) for the ESTABLISHED socket (id={} {}).",
                    conn.recv_vars.next_sequence_num, rcv_nxt_next, socket_id, conn.print_address()
                );
                conn.recv_vars.next_sequence_num = rcv_nxt_next;
                conn.recv_vars.window_size = conn.get_recv_window_size();
            }
            // Enter the CLOSE-WAIT state. rfc9293
            if tcp_packet.flag.contains(TcpFlag::FIN) {
                conn.status = TcpStatus::CloseWait;
                log::debug!(
                    "Socket (id={}) status changed from ESTABLISHED to CLOSED-WAIT. {} SEG.FLAG={:?}",
                    socket_id, conn.print_address(), tcp_packet.flag
                );
            }
            conn.ack_now = true;
            if let Err(e) = self.send_handler(conn) {
                log::debug!(
                    "ESTABLISHED socket (id={}) acked, but failed. SEG.ACK={} SND.NXT={} Err: {}",
                    socket_id, tcp_packet.ack_number, conn.send_vars.next_sequence_num, e
                );
            }
            conn.ack_now = false;
            return Ok(());
        } else {
            anyhow::bail!("No socket (id={}).", socket_id);
        }
    }

    fn generate_initial_sequence(&self) -> u32 {
        100
    }

    fn wait_event_with_timeout(&self, wait_event: TcpEvent, timeout: Duration) -> bool {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if *event == wait_event {
                *event = TcpEvent { socket_id: 0, event: TcpEventType::InitialState };
                return true;
            }
            let elapsed = start_time.elapsed();
            if elapsed >= timeout {
                return false; // Timeout expired
            }
            let remaining_time = timeout - elapsed;
            let (new_event, timeout_result) = condvar.wait_timeout(event, remaining_time).unwrap();
            event = new_event;
            if timeout_result.timed_out() {
                return false; // Timeout occurred
            }
        }
    }

    fn wait_events_with_timeout(&self, wait_events: Vec<TcpEvent>, timeout: Duration) -> (bool, Option<TcpEvent>) {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if wait_events.contains(&event) {
                let ret_event = Some(event.clone());
                *event = TcpEvent { socket_id: 0, event: TcpEventType::InitialState };
                return (true, ret_event);
            }
            let elapsed = start_time.elapsed();
            if elapsed >= timeout {
                return (false, None); // Timeout expired
            }
            let remaining_time = timeout - elapsed;
            let (new_event, timeout_result) = condvar.wait_timeout(event, remaining_time).unwrap();
            event = new_event;
            if timeout_result.timed_out() {
                return (false, None); // Timeout occurred
            }
        }
    }

    pub fn publish_event(&self, event: TcpEvent) {
        log::trace!("Publishing TcpEvent. {:?}", event);
        let (lock, condvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = event;
        condvar.notify_all();
    }
}

pub fn calc_window_size(conn: &TcpConnection) -> usize {
    // todo: need to adjust window size to avoid silly window syndrome
    conn.recv_queue.queue_length - conn.recv_queue.complete_datagram.payload.len()
}

// true if min <= target <= max
pub fn seq_in_range(min: u32, max: u32, target: u32) -> bool {
    if seq_less_equal(min, max) {
        seq_less_equal(min, target) && seq_less_equal(target, max)
    } else {
        seq_less_equal(min, target) || seq_less_equal(target, max)
    }
}

// true if seq1 < seq2
fn seq_less_than(seq1: u32, seq2: u32) -> bool {
    (seq1 < seq2 && seq2 - seq1 < (MAX_SEQ / 2)) ||
    (seq1 > seq2 && seq1 - seq2 > (MAX_SEQ / 2))
}

// true if seq1 <= seq2
fn seq_less_equal(seq1: u32, seq2: u32) -> bool {
    seq1 == seq2 || seq_less_than(seq1, seq2)
}

// true if seq1 > seq2
fn seq_greater_than(seq1: u32, seq2: u32) -> bool {
    (seq1 > seq2 && seq1 - seq2 < (MAX_SEQ / 2)) ||
    (seq1 < seq2 && seq2 - seq1 > (MAX_SEQ / 2))
}

// true if seq1 >= seq2
fn seq_greater_equal(seq1: u32, seq2: u32) -> bool {
    seq1 == seq2 || seq_greater_than(seq1, seq2)
}

// There are four cases for the acceptability test for an incoming segment: rfc9293
pub fn is_segment_acceptable(conn: &TcpConnection, tcp_packet: &TcpPacket) -> bool {
    if tcp_packet.payload.len() == 0 && tcp_packet.windows_size << conn.send_vars.window_shift == 0 {
        if tcp_packet.seq_number == conn.recv_vars.next_sequence_num {
            return true;
        }
    } else if tcp_packet.payload.len() == 0 && tcp_packet.windows_size << conn.send_vars.window_shift > 0 {
        if seq_in_range(
            conn.recv_vars.next_sequence_num,
            conn.recv_vars.next_sequence_num.wrapping_add(conn.recv_vars.window_size as u32 - 1),
            tcp_packet.seq_number
        ) {
            return true;
        }
    } else if tcp_packet.payload.len() > 0 && tcp_packet.windows_size << conn.send_vars.window_shift == 0 {
        return false;
    } else if tcp_packet.payload.len() > 0 && tcp_packet.windows_size << conn.send_vars.window_shift > 0 {
        if seq_in_range(
            conn.recv_vars.next_sequence_num,
            conn.recv_vars.next_sequence_num.wrapping_add(conn.recv_vars.window_size as u32 - 1),
            tcp_packet.seq_number
        ) || seq_in_range(
            conn.recv_vars.next_sequence_num,
            conn.recv_vars.next_sequence_num.wrapping_add(conn.recv_vars.window_size as u32 - 1),
            tcp_packet.seq_number.wrapping_add(tcp_packet.payload.len() as u32 - 1)
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
        tcp_packet.ack_number
    ) && (
        seq_greater_than(tcp_packet.seq_number, conn.send_vars.last_sequence_num) ||
        (
            tcp_packet.seq_number == conn.send_vars.last_sequence_num &&
            seq_greater_equal(tcp_packet.ack_number, conn.send_vars.last_acknowledge_num)
        )
    ) {
        true
    } else {
        false
    }
}

#[derive(Debug)]
pub struct ListenQueue {
    pub pending: VecDeque<usize>,                 // Received SYN but not replied SYN/ACK
    pub pending_acked: VecDeque<usize>,           // Received SYN and replied SYN/ACK
    pub established_unconsumed: VecDeque<usize>,  // Established but not used by accept call
    pub established_consumed: VecDeque<usize>,    // Established and used by accept call
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
    pub rtt_start: Option<Instant>,
    pub ack_now: bool,
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
            ack_now: false,
        }
    }

    pub fn print_address(&self) -> String {
        format!("local={}:{} remote={}:{}", self.src_addr, self.local_port, self.dst_addr, self.remote_port)
    }

    pub fn get_recv_window_size(&self) -> usize {
        // todo: need to adjust window size to avoid silly window syndrome
        self.recv_queue.queue_length - self.recv_queue.complete_datagram.payload.len()
    }

    pub fn get_recv_window_for_pkt(&self) -> u16 {
        (self.get_recv_window_size() << self.recv_vars.window_shift) as u16
    }

    pub fn update_snd_una(&mut self, new_snd_una: u32) -> Result<()> {
        anyhow::ensure!(
            seq_less_equal(new_snd_una, self.send_vars.next_sequence_num),
            "New SND.UNA ({}) should be equal or smaller than SND.NXT ({}).",
            new_snd_una, self.send_vars.next_sequence_num
        );
        self.send_queue.payload.drain(..new_snd_una.wrapping_sub(self.send_vars.unacknowledged) as usize);
        self.send_vars.unacknowledged = new_snd_una;
        Ok(())
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
    pub unacknowledged: u32,       // send unacknowledged (oldest unacknowledged sequence number) -> recv packet's ack (UNA)
    pub next_sequence_num: u32,    // send next -> recv packet's ack, next send packet's seq (NXT)
    pub window_size: u16,          // send window received by packet (not scaled!)
    pub urgent_pointer: u16,       // send urgent pointer
    pub last_sequence_num: u32,    // segment sequence number used for last window update (WL1)
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
    pub queue_length: usize
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
    pub next_sequence_num: u32,    // receive next -> recv packet's seq + data length, next send packet's ack (NXT)
    pub window_size: usize,        // receive window (already scaled, originaly u16)
    pub urgent_pointer: u16,       // receive urgent pointer
    pub initial_sequence_num: u32, // initial receive sequence number (IRS)
    pub window_shift: usize,       // received window scale option (Rcv.Wind.Shift)
    pub recv_mss: usize,           // mss report to remote peer
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
        } else if begin <= seq + TCP_RECV_QUEUE_WRAP && seq + TCP_RECV_QUEUE_WRAP <= begin + self.queue_length {
            Ok(seq + TCP_RECV_QUEUE_WRAP)
        } else {
            anyhow::bail!("Unacceptable sequence number. SEQ: {} QUEUE.BEGIN: {} QUEUE.LENGTH: {}", seq, begin, self.queue_length);
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
        anyhow::ensure!(payload.len() > 0, "Cannot add an empty segment.");
        let virtual_seq = self.convert_virtual_sequence_num(seq).context("Failed to add segment, possibly it is out of the receive queue.")?;
        let new_start = virtual_seq;
        let new_end = virtual_seq + payload.len() -1;
        let complete_start = self.complete_datagram.sequence_num;
        let complete_end = self.complete_datagram.sequence_num + max(self.complete_datagram.payload.len(), 1) - 1;
        let complete_max = complete_start + self.queue_length - 1;
        let pending_start = max(complete_end + 1, new_start);
        anyhow::ensure!(
            complete_start <= new_start && new_end <= complete_max,
            "An invalid segment was added. SEG.SEQ={} SEG.LEN = {} QUEUE.BEGIN_SEQ={} QUEUE.MAX_SEQ={}", new_start, payload.len(), complete_start, complete_end
        );
        if new_end <= complete_end {
            return Ok(());
        }
        if self.complete_datagram.payload.len() == 0 && complete_start == new_start{
            self.complete_datagram.payload = payload.clone();
            return Ok(());
        }
        let mut pending_new = Vec::new();
        let mut tmp_fragment: Option<ReceiveFragment> = None;
        let mut complete_marge: bool = false;
        for ReceiveFragment { sequence_num: current_seq, payload: current_payload } in &self.fragmented_datagram {
            if complete_marge {
                pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                continue;
            }
            let current_start = *current_seq;
            let current_end = current_seq + current_payload.len() - 1;
            // with tmp_fragment
            if let Some(ReceiveFragment { sequence_num: tmp_seq, payload: ref tmp_payload }) = tmp_fragment {
                let tmp_start = tmp_seq;
                let tmp_end = tmp_seq + tmp_payload.len() - 1;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <-O->
                // result   :   <-O->  <---O---> (add fragments)
                if tmp_end < current_start - 1 {
                    pending_new.push(ReceiveFragment { sequence_num: tmp_seq, payload: tmp_payload.to_vec() });
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <----O---->
                // result   :   <-------O------> (add marged fragment)
                } else if current_start - 1 <= tmp_end && tmp_end <= current_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut tmp_payload[..current_start-tmp_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    pending_new.push( ReceiveFragment {sequence_num: tmp_start, payload: fragment_marged} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :            <-O->
                // result   :          <---O---> (add the current fragment as is)
                } else if tmp_start <= current_start && tmp_end <= current_end {
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :   <---------O--------->
                // result   :   <---------O---------> (add marged fragment as tmp)
                } else if tmp_start < current_start && current_end < tmp_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut tmp_payload[..current_start-tmp_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut tmp_payload[1+current_end-tmp_start..].to_vec());
                    tmp_fragment = Some( ReceiveFragment {sequence_num: tmp_start, payload: fragment_marged} );
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :             <-----O---->
                // result   :          <-----O-------> (add marged fragment as tmp)
                } else if current_start <= tmp_start && tmp_start < current_end + 1 {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut tmp_payload[1+current_end-tmp_start..].to_vec());
                    tmp_fragment = Some( ReceiveFragment {sequence_num: tmp_start, payload: fragment_marged} );
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // tmp      :                     <-O->
                // result   :          <---O--->  <-O-> (leave tmp fragment as is)
                } else if current_end + 1 < tmp_start {
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    continue;
                }
                anyhow::bail!(
                    "Impossible range: tmp_start={} tmp_end={} current_start={} current_end={}",
                    tmp_start, tmp_end, current_start, current_end
                );
            // without tmp_fragment
            } else {
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :   <-O->
                // result   :   <-O->  <---O---> (add fragments)
                if new_end < current_start - 1 {
                    pending_new.push( ReceiveFragment {sequence_num: pending_start, payload: payload[pending_start-new_start..].to_vec()} );
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :     <----O---->
                // result   :     <------O-----> (add marged fragment)
                } else if current_start - 1 <= new_end && new_end <= current_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut payload[max(pending_start-new_start, 1)-1..current_start-new_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    pending_new.push( ReceiveFragment {sequence_num: pending_start, payload: fragment_marged} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :            <-O->
                // result   :          <---O---> (add the current fragment as is)
                } else if pending_start <= current_start && new_end <= current_end {
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    complete_marge = true;
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :       <-------O-------->
                // result   :       <--------O-------> (add marged fragment as tmp)
                } else if pending_start < current_start && current_end < new_end {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut payload[max(pending_start-new_start, 0)..current_start-new_start].to_vec());
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut payload[1+current_end-new_start..].to_vec());
                    tmp_fragment = Some( ReceiveFragment {sequence_num: pending_start, payload: fragment_marged} );
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :             <-----O---->
                // result   :          <-----O-------> (add marged fragment as tmp)
                } else if current_start <= pending_start && pending_start <= current_end + 1 {
                    let mut fragment_marged = Vec::new();
                    fragment_marged.append(&mut current_payload.to_vec());
                    fragment_marged.append(&mut payload[1+current_end-new_start..].to_vec());
                    tmp_fragment = Some( ReceiveFragment {sequence_num: current_start, payload: fragment_marged} );
                    continue;
                //                      current
                //                         |
                // fragment : <---X---><---O---><---X---><---O--->
                // new      :                     <-O->
                // result   :          <---O--->  <-O-> (add last fragment as tmp)
                } else if current_end + 1 < pending_start {
                    pending_new.push( ReceiveFragment {sequence_num: *current_seq, payload: current_payload.clone()} );
                    tmp_fragment = Some( ReceiveFragment {sequence_num: new_start, payload: payload.to_vec()} );
                    continue;
                }
                anyhow::bail!(
                    "Impossible range: pending_start={} new_start={} new_end={} current_start={} current_end={}",
                    pending_start, new_start, new_end, current_start, current_end
                );
            }
        }
        if let Some(tmp) = tmp_fragment {
            if !complete_marge {
                pending_new.push(tmp);
            }
        }
        if let Some(first) = pending_new.first() {
            if first.sequence_num == complete_end + 1 {
                self.complete_datagram.payload.append(&mut first.payload.clone());
                pending_new.remove(0);
            }
        }
        self.fragmented_datagram = pending_new;
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
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
        Ok(copy_len)
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpEvent {
    pub socket_id: usize,
    pub event: TcpEventType
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
            payload: vec![1, 2, 3, 4, 5]
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 20,
                payload: vec![6, 7, 8]
            },
            ReceiveFragment {
                sequence_num: 30,
                payload: vec![1, 2, 3, 4]
            }
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending
        };
        let result = queue.add(new_fragment_seq, &new_fragment_payload).expect("Failed to add fragment to queue.");

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
            payload: vec![1, 2, 3, 4, 5]
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            },
            ReceiveFragment {
                sequence_num: 32,
                payload: vec![8, 7, 6, 5]
            }
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending
        };
        let result = queue.add(new_fragment_seq, &new_fragment_payload).expect("Failed to add fragment to queue.");

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
            payload: vec![]
        };
        let initial_pending = vec![
            ReceiveFragment {
                sequence_num: 18,
                payload: vec![6, 7, 8, 6]
            },
            ReceiveFragment {
                sequence_num: 25,
                payload: vec![2, 3, 4, 5]
            }
        ];
        let mut queue = ReceiveQueue {
            queue_length: TCP_DEFAULT_RECV_QUEUE_LENGTH,
            complete_datagram: initial_complete,
            fragmented_datagram: initial_pending
        };
        let result = queue.add(new_fragment_seq, &new_fragment_payload).expect("Failed to add fragment to queue.");

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
        #[case] expected_buf_after: Vec<u8>
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
    )]    fn test_receive_queue_read_5_wrapped(
        #[case] mut queue: ReceiveQueue,
        #[case] expected_after_queue: ReceiveQueue,
        #[case] expected_data_len: usize,
        #[case] expected_buf_after: Vec<u8>
     ) {
        let mut buf = [0; 5];
        let data_len = queue.read(&mut buf).unwrap();

        assert_eq!(buf, expected_buf_after[..5]);
        assert_eq!(data_len, expected_data_len);
        assert_eq!(queue, expected_after_queue);
    }
}