use crate::{
    l2_l3::{
        defs::Ipv4Type,
        ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration},
    },
    tcp::{
        self,
        defs::{TcpError, TcpStatus},
        input::{ListenQueue, TcpConnection, TcpEvent, TcpEventType},
        output,
        packet::{TcpFlag, TcpPacket, TCP_DEFAULT_WINDOW_SCALE},
        timer::{update_retransmission_param, TcpTimer, TCP_RTTVAR_SHIFT, TCP_SRTT_SHIFT},
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

pub const TCP_MAX_SOCKET: usize = 100;
// "the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535 (never assigned)" rfc6335
const TCP_EPHEMERAL_PORT_RANGE: Range<u16> = 49152..65535;

static TCP_STACK_GLOBAL: OnceLock<Arc<TcpStack>> = OnceLock::new();

pub fn get_global_tcpstack(config: NetworkConfiguration) -> Result<&'static Arc<TcpStack>> {
    Ok(TCP_STACK_GLOBAL.get_or_init(|| TcpStack::new(config).unwrap()))
}

pub struct TcpStack {
    pub config: NetworkConfiguration,
    pub connections: Mutex<HashMap<usize, Option<TcpConnection>>>,
    pub listen_queue: Mutex<HashMap<usize, ListenQueue>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
    event_condvar: (Mutex<TcpEvent>, Condvar),
}

impl TcpStack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let tcp = Arc::new(Self {
            config: config,
            connections: Mutex::new(HashMap::new()),
            listen_queue: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            event_condvar: (
                Mutex::new(TcpEvent {
                    socket_id: 0,
                    event: TcpEventType::InitialState,
                }),
                Condvar::new(),
            ),
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
        anyhow::bail!(
            "Failed to generate a new tcp socket because no available id. TCP_MAX_SOCKET={}",
            TCP_MAX_SOCKET
        )
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
        let used_ports: Vec<u16> = conns
            .values()
            .filter_map(|conn| conn.as_ref().map(|c| c.local_port))
            .collect();
        if let Some(conn_wrap) = conns.get_mut(&socket_id) {
            if let Some(conn) = conn_wrap {
                anyhow::bail!(
                    "Tcp socket (id={}) has already bound to {}:{}.",
                    socket_id,
                    conn.src_addr,
                    conn.local_port
                );
            } else {
                // assign ephemeral port
                if addr.port() == 0 {
                    for port in TCP_EPHEMERAL_PORT_RANGE {
                        if !used_ports.contains(&port) {
                            let new_conn =
                                TcpConnection::new(*addr.ip(), port, Ipv4Addr::UNSPECIFIED, 0);
                            conns.insert(socket_id, Some(new_conn));
                            log::info!(
                                "Tcp socket (id={}) bind to the ephemeral port {}:{}.",
                                socket_id,
                                *addr.ip(),
                                port
                            );
                            return Ok(());
                        }
                    }
                    anyhow::bail!("Failed to bind tcp socket. No available ephemeral port.");
                } else {
                    if !used_ports.contains(&addr.port()) {
                        let new_conn =
                            TcpConnection::new(*addr.ip(), addr.port(), Ipv4Addr::UNSPECIFIED, 0);
                        conns.insert(socket_id, Some(new_conn));
                        log::info!(
                            "Tcp socket (id={}) bind to the specified port {}:{}.",
                            socket_id,
                            *addr.ip(),
                            addr.port()
                        );
                    } else {
                        anyhow::bail!(
                            "Failed to bind tcp socket. Port {} is already used.",
                            addr.port()
                        );
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
                        pending: VecDeque::new(),
                        pending_acked: VecDeque::new(),
                        established_unconsumed: VecDeque::new(),
                        established_consumed: VecDeque::new(),
                        accepted: 0,
                    },
                );
                Ok(())
            } else {
                anyhow::bail!(
                    "Only a Closed socket can transit to Listen. Current: {}",
                    conn.status
                );
            }
        } else {
            anyhow::bail!(
                "Cannot listen Socket (id={}) which is not bound.",
                socket_id
            );
        }
    }

    pub fn accept(&self, socket_id: usize) -> Result<(usize, SocketAddrV4)> {
        log::trace!("ACCEPT CALL: id={}", socket_id);
        let mut conns = self.connections.lock().unwrap();
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if conn.status == TcpStatus::Listen {
                let mut listen_queue = self.listen_queue.lock().unwrap();
                if let Some(queue) = listen_queue.get_mut(&socket_id) {
                    queue.accepted += 1;
                    if let Some(id) = queue.established_unconsumed.pop_front() {
                        if let Some(Some(conn_est)) = conns.get(&id) {
                            return Ok((
                                id,
                                SocketAddrV4::new(conn_est.dst_addr, conn_est.remote_port),
                            ));
                        } else {
                            log::error!("An Established connection (id={}) dose not exist in TcpConnections", id);
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
                                log::info!(
                                    "An Established socket (id={} {}) is conusmed by accept call.",
                                    established_id,
                                    conn.print_address()
                                );
                                return Ok((
                                    established_id,
                                    SocketAddrV4::new(conn.dst_addr, conn.remote_port),
                                ));
                            } else {
                                log::error!("An Established connection (id={}) does not exist in TcpConnections", established_id);
                                continue;
                            }
                        }
                        // there is a already pending connection which received syn but not yet replied syn-ack.
                        if let Some(syn_recv_id) = queue.pending.pop_front() {
                            // reply syn-ack
                            if let Some(Some(conn)) = conns.get_mut(&syn_recv_id) {
                                if conn.status != TcpStatus::SynRcvd {
                                    continue;
                                }
                                let mut syn_ack = TcpPacket::new_syn_rcvd(conn)?;
                                syn_ack.option.mss = Some((self.config.mtu - 40) as u16);
                                if let Err(e) = self.send_tcp_packet(syn_ack) {
                                    log::warn!("Sending SYN/ACK failed. Err: {}", e);
                                    continue;
                                } else {
                                    log::debug!(
                                        "Accepted socket (id={}) replies SYN/ACK to {}:{}. SEQ={} ACK={}",
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
                                        TcpEvent {
                                            socket_id: syn_recv_id,
                                            event: TcpEventType::Established,
                                        },
                                        TcpEvent {
                                            socket_id: syn_recv_id,
                                            event: TcpEventType::Refused,
                                        },
                                        TcpEvent {
                                            socket_id: syn_recv_id,
                                            event: TcpEventType::Closed,
                                        },
                                    ],
                                    Duration::from_millis(100),
                                ) {
                                    match event.event {
                                        TcpEventType::Established => {
                                            // event received, expected that syn_recv_id's state is established.
                                            let mut conns = self.connections.lock().unwrap();
                                            let mut listen_queue =
                                                self.listen_queue.lock().unwrap();
                                            if let (Some(Some(conn)), Some(queue)) = (
                                                conns.get_mut(&syn_recv_id),
                                                listen_queue.get_mut(&socket_id),
                                            ) {
                                                if conn.status == TcpStatus::Established {
                                                    queue
                                                        .established_consumed
                                                        .push_back(syn_recv_id);
                                                    queue.accepted -= 1;
                                                    log::info!("Accepted socket (id={}) connection established. {}", syn_recv_id, conn.print_address());
                                                    return Ok((
                                                        syn_recv_id,
                                                        SocketAddrV4::new(
                                                            conn.dst_addr,
                                                            conn.remote_port,
                                                        ),
                                                    ));
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
                                        if conn.status == TcpStatus::SynRcvd {
                                            continue;
                                        }
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
                                    TcpEvent {
                                        socket_id: socket_id,
                                        event: TcpEventType::SynReceived,
                                    },
                                    Duration::from_millis(100),
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
                anyhow::bail!(
                    "Cannot accept a socket which status is not Listen. Current: {}",
                    conn.status
                );
            }
        } else {
            anyhow::bail!(
                "Cannot accept the socket (id={}) which is not bound.",
                socket_id
            );
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
            log::debug!(
                "[{}] Status changed from CLOSED to SYN-SENT. ISS={}.",
                conn.print_log_prefix(socket_id),
                seq
            );
        } else {
            anyhow::bail!("Socket (id={}) is not bound.", socket_id);
        }
        drop(conns);
        loop {
            if let (_valid, Some(event)) = self.wait_events_with_timeout(
                vec![
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Established,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Refused,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    },
                ],
                Duration::from_millis(100),
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
                        anyhow::bail!(TcpError::RefusedError { id: socket_id })
                    }
                    TcpEventType::Closed => {
                        anyhow::bail!(TcpError::ClosedError { id: socket_id })
                    }
                    other => {
                        anyhow::bail!(
                            "Wake up from unexpected event ({:?}). Expected Established/Refused.",
                            other
                        );
                    }
                }
            // timeout occured, so wait again
            } else {
                continue;
            }
        }
    }

    pub fn write(&self, socket_id: usize, payload: &[u8]) -> Result<usize> {
        let mut current_offset: usize = 0;
        let payload_len = payload.len();
        log::trace!("WRITE CALL: id={} len={}", socket_id, payload_len);
        loop {
            let mut conns = self.connections.lock().unwrap();
            if let Some(Some(conn)) = conns.get_mut(&socket_id) {
                let current_queue_free =
                    conn.send_queue.queue_length - conn.send_queue.payload.len();
                let remain = payload_len - current_offset;
                let wrote_bytes: usize;
                if remain <= current_queue_free {
                    conn.send_queue
                        .payload
                        .extend_from_slice(&payload[current_offset..]);
                    current_offset = payload_len;
                    log::trace!(
                        "[{}] Wrote remaining all the data ({} bytes) to send queue. SND.UNA={} CURRENT_QUEUE_LENGTH={}",
                        conn.print_log_prefix(socket_id),
                        remain,
                        conn.send_vars.unacknowledged,
                        conn.send_queue.payload.len()
                    );
                    wrote_bytes = remain;
                } else {
                    conn.send_queue.payload.extend_from_slice(
                        &payload[current_offset..(current_offset + current_queue_free)],
                    );
                    current_offset += current_queue_free;
                    if current_queue_free != 0 {
                        log::trace!(
                            "[{}] Wrote partial data ({} bytes) to send queue. SND.UNA={} CURRENT_QUEUE_LENGTH={}",
                            conn.print_log_prefix(socket_id),
                            current_queue_free,
                            conn.send_vars.unacknowledged,
                            conn.send_queue.payload.len()
                        );
                    }
                    wrote_bytes = current_queue_free;
                }
                if wrote_bytes != 0 {
                    if let Err(e) = self.send_handler(conn) {
                        log::warn!("Failed to send a datagram. Err: {e:?}");
                    }
                }
                if current_offset == payload_len {
                    if !conn.timer.retransmission.timer_param.active
                        && conn.send_vars.unacknowledged != conn.send_vars.next_sequence_num
                    {
                        conn.timer.retransmission.fire_datagram();
                    }
                    return Ok(current_offset);
                }
            } else {
                anyhow::bail!("Cannot find the socket (id={}).", socket_id);
            }
            drop(conns);
            if let (_valid, Some(event)) = self.wait_events_with_timeout(
                vec![
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::SendMore,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Refused,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    },
                ],
                Duration::from_millis(100),
            ) {
                match event.event {
                    TcpEventType::SendMore => {
                        continue;
                    }
                    TcpEventType::Refused => {
                        log::warn!("While waiting for the socket (id={}) sending datagram, the connection refused.", socket_id);
                    }
                    TcpEventType::Closed => {
                        log::warn!("While waiting for the socket (id={}) sending datagram, the connection closed.", socket_id);
                    }
                    other => {
                        anyhow::bail!("Wake up from unexpected event ({:?}). Expected SendMore/Refused/Closed.", other);
                    }
                }
            }
        }
    }

    pub fn read(&self, socket_id: usize, payload: &mut [u8]) -> Result<usize> {
        log::trace!("READ CALL: id={}", socket_id);
        loop {
            let mut conns = self.connections.lock().unwrap();
            if let Some(Some(conn)) = conns.get_mut(&socket_id) {
                if conn.recv_queue.complete_datagram.payload.len() != 0 {
                    let read_size = conn.recv_queue.read(payload)?;
                    if read_size != 0 {
                        conn.recv_vars.window_size = conn.recv_queue.queue_length
                            - conn.recv_queue.complete_datagram.payload.len();
                        conn.send_flag.ack_now = true;
                        if let Err(e) = self.send_handler(conn) {
                            log::warn!("Failed to ack after READ Call. Err: {:?}", e);
                        }
                        return Ok(read_size);
                    }
                }
            } else {
                anyhow::bail!("Cannot find the socket (id={}).", socket_id);
            }
            drop(conns);
            if let (_valid, Some(event)) = self.wait_events_with_timeout(
                vec![
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::DatagramReceived,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Refused,
                    },
                    TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    },
                ],
                Duration::from_millis(100),
            ) {
                match event.event {
                    TcpEventType::DatagramReceived => {
                        continue;
                    }
                    TcpEventType::Refused => {
                        log::warn!("While waiting for the socket (id={}) sending datagram, the connection refused.", socket_id);
                        anyhow::bail!(TcpError::RefusedError { id: socket_id })
                    }
                    TcpEventType::Closed => {
                        log::warn!("While waiting for the socket (id={}) sending datagram, the connection closed.", socket_id);
                        anyhow::bail!(TcpError::ClosedError { id: socket_id })
                    }
                    other => {
                        anyhow::bail!("Wake up from unexpected event ({:?}). Expected DatagramReceived/Refused/Closed.", other);
                    }
                }
            }
        }
    }

    pub fn shutdown(&self, socket_id: usize) -> Result<()> {
        // wip: just flushing queue
        log::trace!("SHUTDOWN CALL: id={}", socket_id);
        loop {
            let mut conns = self.connections.lock().unwrap();
            if let Some(Some(conn)) = conns.get_mut(&socket_id) {
                if conn.send_queue.payload.len() == 0
                    && conn.recv_vars.next_sequence_num == conn.last_snd_ack
                {
                    break;
                }
            } else {
                anyhow::bail!("Cannot find the socket (id={}).", socket_id);
            }
            // thread::sleep(Duration::from_millis(10));
        }
        log::trace!("Shutting down. id={}", socket_id);
        Ok(())
    }

    pub fn get_socket_id(
        &self,
        src_addr: &Ipv4Addr,
        dst_addr: &Ipv4Addr,
        local_port: &u16,
        remote_port: &u16,
    ) -> Result<(
        Option<usize>,
        MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    )> {
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
                rtt_seq: _rtt_seq,
                last_snd_ack: _last_snd_ack,
                last_sent_window: _last_sent_window,
                fin_seq: _fin_sent,
                send_flag: _send_flag,
                conn_flag: _conn_flag,
            }) = connection_info
            {
                if s_addr == dst_addr
                    && d_addr == src_addr
                    && l_port == remote_port
                    && r_port == local_port
                {
                    ids.push(*id);
                } else if s_addr == dst_addr
                    && *d_addr == Ipv4Addr::UNSPECIFIED
                    && l_port == remote_port
                    && *r_port == 0
                {
                    listen_ids.push(*id);
                } else {
                    continue;
                }
            }
        }
        if listen_ids.len() == 0 && ids.len() == 0 {
            log::debug!(
                "There is no tcp socket for the packet (src={}:{} dst={}:{}).",
                src_addr,
                local_port,
                dst_addr,
                remote_port
            );
            Ok((None, conns))
        } else if (listen_ids.len() == 1 || listen_ids.len() == 0) && ids.len() == 1 {
            Ok((ids.pop(), conns))
        } else if listen_ids.len() == 1 && ids.len() == 0 {
            Ok((listen_ids.pop(), conns))
        } else {
            log::error!(
                "Panic because duplicate socket detected. src={}:{} dst={}:{}",
                dst_addr,
                remote_port,
                src_addr,
                local_port
            );
            panic!();
        }
    }

    fn wait_event_with_timeout(&self, wait_event: TcpEvent, timeout: Duration) -> bool {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if *event == wait_event {
                *event = TcpEvent {
                    socket_id: 0,
                    event: TcpEventType::InitialState,
                };
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

    fn wait_events_with_timeout(
        &self,
        wait_events: Vec<TcpEvent>,
        timeout: Duration,
    ) -> (bool, Option<TcpEvent>) {
        let (lock, condvar) = &self.event_condvar;
        let start_time = Instant::now();
        let mut event = lock.lock().unwrap();
        loop {
            if wait_events.contains(&event) {
                let ret_event = Some(event.clone());
                *event = TcpEvent {
                    socket_id: 0,
                    event: TcpEventType::InitialState,
                };
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
