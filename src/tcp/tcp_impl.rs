use crate::{
    l2_l3::{defs::Ipv4Type, ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration}},
    tcp::{defs::TcpStatus, packet::TcpPacket}
};
use anyhow::{Context, Result};
use log;
use std::{collections::{HashMap, VecDeque}, sync::MutexGuard, time::Duration};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc::channel};
use std::thread::{self, JoinHandle};
use std::time::{Instant};

const TCP_MAX_SOCKET: usize = 100;
// "the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535 (never assigned)" rfc6335
const TCP_EPHEMERAL_PORT_RANGE: Range<u16> = 49152..65535;
// "The present global default is five minutes." rfc9293
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_MAX_CONCURRENT_SESSION: usize = 10;
const TCP_MAX_LISTEN_QUEUE: usize = TCP_MAX_CONCURRENT_SESSION * 3 / 2;
const TCP_RECV_QUEUE_LENGTH: usize = 4096;

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
            event_condvar: (Mutex::new(TcpEvent {socket_id: 0, event: TcpEventType::InitailState}), Condvar::new())
        });

        let tcp_recv = tcp.clone();
        let handle_recv = thread::spawn(move || {
            tcp_recv.receive_thread().unwrap();
        });
        tcp.threads.lock().unwrap().push(handle_recv);

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

        Ok(())
    }

    pub fn bind(&self, socket_id: usize, addr: SocketAddrV4) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        let used_ports: Vec<u16> = conns.values()
            .filter_map(|conn| conn.as_ref().map(|c| c.local_port))
            .collect();
        if let Some(conn_wrap) = conns.get_mut(&socket_id) {
            if let Some(conn) = conn_wrap {
                anyhow::bail!("Tcp socket (id={}) is already bound to {}:{}.", socket_id, conn.src_addr, conn.local_port);
            } else {
                // assign ephemeral port
                if addr.port() == 0 {
                    for port in TCP_EPHEMERAL_PORT_RANGE {
                        if !used_ports.contains(&port) {
                            let new_conn = TcpConnection {
                                src_addr: *addr.ip(),
                                dst_addr: Ipv4Addr::UNSPECIFIED,
                                local_port: port,
                                remote_port: 0,
                                status: TcpStatus::Closed,
                                send_vars: Default::default(),
                                recv_vars: Default::default()
                            };
                            conns.insert(socket_id, Some(new_conn));
                        }
                    }
                    anyhow::bail!("Failed to bind tcp socket. No available ephemeral port.");
                } else {
                    if !used_ports.contains(&addr.port()) {
                        let new_conn = TcpConnection {
                            src_addr: *addr.ip(),
                            dst_addr: Ipv4Addr::UNSPECIFIED,
                            local_port: addr.port(),
                            remote_port: 0,
                            status: TcpStatus::Closed,
                            send_vars: Default::default(),
                            recv_vars: Default::default()
                        };
                        conns.insert(socket_id, Some(new_conn));
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
                        pending: VecDeque::new(), established_unconsumed: VecDeque::new(), established_consumed: VecDeque::new(), accepted: 0
                    });
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
                    let conns = self.connections.lock().unwrap();
                    let mut listen_queue = self.listen_queue.lock().unwrap();
                    if let Some(ref mut queue) = listen_queue.get_mut(&socket_id) {
                        if let Some(established_id) = queue.established_unconsumed.pop_front() {
                            if let Some(Some(conn)) = conns.get(&established_id) {
                                queue.established_consumed.push_back(established_id);
                                queue.accepted -= 1;
                                return Ok((established_id, SocketAddrV4::new(conn.dst_addr, conn.remote_port)));
                            } else {
                                log::error!("Established connection (id={}) dose not exist in TcpConnections", established_id);
                                continue;
                            }
                        }
                        // there is a already pending connection which received syn but not yet replied syn-ack.
                        if let Some(syn_recv_id) = queue.pending.pop_front() {
                            // reply syn-ack
                            let conns = self.connections.lock().unwrap();
                            if let Some(Some(conn)) = conns.get(&syn_recv_id) {
                                if conn.status != TcpStatus::SynRcvd { continue; }
                                let mut syn_ack = TcpPacket::new();
                                syn_ack.src_addr = conn.src_addr.octets();
                                syn_ack.dst_addr = conn.dst_addr.octets();
                                syn_ack.protocol = u8::from(Ipv4Type::TCP);
                                syn_ack.local_port = conn.local_port;
                                syn_ack.remote_port = conn.remote_port;
                                syn_ack.seq_number = conn.send_vars.next_sequence_num;
                                syn_ack.ack_number = conn.recv_vars.next_sequence_num;
                                syn_ack.flag_syn = true;
                                syn_ack.flag_ack = true;
                                syn_ack.windows_size = conn.recv_vars.window_size;
                                syn_ack.option.mss = Some((self.config.mtu - 40) as u16);
                                if let Err(e) = self.send_tcp_packet(syn_ack) {
                                    log::warn!("Sending syn-ack failed. Err: {}", e);
                                    continue;
                                } else {
                                    log::debug!(
                                        "Accepted socket(id={}) reply syn-ack to {}:{}. SEQ={} ACK={}",
                                        syn_recv_id, conn.dst_addr, conn.remote_port,
                                        conn.send_vars.next_sequence_num, conn.recv_vars.next_sequence_num,
                                    );
                                }
                            }
                            drop(conns);
                            drop(listen_queue);
                            loop {
                                if self.wait_event_with_timeout(
                                    TcpEvent { socket_id: syn_recv_id, event: TcpEventType::Established },
                                    Duration::from_millis(100)
                                ) {
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
                                            return Ok((syn_recv_id, SocketAddrV4::new(conn.dst_addr, conn.remote_port)));
                                        } else {
                                            break;
                                        }
                                    } else {
                                        anyhow::bail!("TcpConnection or ListenQueue is not found for socket {}.", socket_id);
                                    }
                                } else {
                                    // timeout occured
                                    let mut conns = self.connections.lock().unwrap();
                                    if let Some(Some(conn)) = conns.get_mut(&syn_recv_id) {
                                        if conn.status == TcpStatus::SynRcvd { continue; }
                                    }
                                    // continue from outer loop again
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
                                    log::trace!("Wake up that accepted LISTEN socket (id={}) spawn SYN-RECEIVED client socket.", socket_id);
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
            let mut tcp_packet = TcpPacket::new();
            let seq = self.generate_initial_sequence();
            tcp_packet.src_addr = conn.src_addr.octets();
            tcp_packet.dst_addr = addr.ip().octets();
            tcp_packet.protocol = u8::from(Ipv4Type::TCP);
            tcp_packet.local_port = conn.local_port;
            tcp_packet.remote_port = addr.port();
            tcp_packet.seq_number = seq;
            tcp_packet.windows_size = 4096; // todo: adjust
            tcp_packet.option.mss = Some(1460); // todo: adjust
            self.send_tcp_packet(tcp_packet)?;
            conn.dst_addr = *addr.ip();
            conn.remote_port = addr.port();
            conn.status = TcpStatus::SynSent;
            conn.recv_vars.next_sequence_num = seq.wrapping_add(1);
            conn.recv_vars.window_size = 4096; // todo: adjust
            log::debug!("Socket (id={}) sent syn to {}:{}. SEQ={}", socket_id, addr.ip(), addr.port(), seq);
            Ok(())
        } else {
            anyhow::bail!("Socket (id={}) is not bound.", socket_id);
        }
    }

    pub fn send(
        &self,
        socket_id: usize,
        payload: Vec<u8>,
        dst: Option<(Ipv4Addr, u16)>, // ip, port
        conns: Option<&MutexGuard<HashMap<usize, TcpConnection>>>
    ) -> Result<()> {
        let mut tcp_packet = TcpPacket::new();
        if let Some(conns_inherit) = conns {
        } else {
        }
        Ok(())
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

    pub fn send_back_rst(&self, original_packet: &TcpPacket) -> Result<()> {
        let rst_packet = original_packet.create_rst();
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
                    log::warn!("Failed to read tcp packet. Err: {}", e);
                    continue;
                }
                Ok(valid) => {
                    if !valid {
                        log::warn!("Discarding invalid tcp packet.");
                        continue;
                    }
                }
            }
            match self.tcp_packet_handler(&tcp_packet) {
                Err(e) => {
                    log::warn!("Failed to handle tcp packet. Err: {}", e);
                    continue;
                }
                Ok(_) => {}
            }
        }
    }

    pub fn get_socket_id(
        &self,
        src_addr: &Ipv4Addr,
        dst_addr: &Ipv4Addr,
        local_port: &u16,
        remote_port: &u16
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
                send_vars: _send_vars,
                recv_vars: _recv_vars
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
        } else if listen_ids.len() == 1 && ids.len() == 1 {
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

    pub fn tcp_packet_handler(&self, tcp_packet: &TcpPacket) -> Result<()> {
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
                log::trace!(
                    "Handling packet for {} socket (id={} local={}:{} remote={}:{}).",
                    conn.status, id, dst_addr, tcp_packet.remote_port, src_addr, tcp_packet.local_port
                );
                match &conn.status {
                    TcpStatus::Listen => { self.listen_handler(id, tcp_packet, conns)?; }
                    other => {
                        anyhow::bail!("Handler for TcpStatus {} is not implemented.", other);
                    }
                }
                return Ok(());
            } else {
                anyhow::bail!("No TcpConnection Data for socket id {}. This should be impossible if locking logic is correct.", id);
            }
        } else {
            log::debug!("No socket bound for the packet dst {}:{}, send back rst packet.", dst_addr, tcp_packet.remote_port);
            self.send_back_rst(tcp_packet)?;
            Ok(())
        }
    }

    pub fn listen_handler(&self, socket_id: usize, tcp_packet: &TcpPacket, mut conns: MutexGuard<HashMap<usize, Option<TcpConnection>>>) -> Result<()> {
        if !tcp_packet.is_syn() {
            log::debug!(
                "Reject not a syn packet from {}:{} by the LISTEN socket (id={}), send back rst packet.",
                socket_id, Ipv4Addr::from(tcp_packet.src_addr), tcp_packet.local_port
            );
            self.send_back_rst(tcp_packet)?;
            return Ok(());
        }
        let mut listen_queue = self.listen_queue.lock().unwrap();
        if let Some(queue) = listen_queue.get_mut(&socket_id) {
            let len_established = queue.established_unconsumed.len() + queue.established_consumed.len();
            let len_all = queue.pending.len() + len_established;
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
                    send_vars.next_sequence_num = self.generate_initial_sequence();
                    send_vars.window_size = tcp_packet.windows_size;
                    send_vars.last_sequence_num = tcp_packet.seq_number;
                    send_vars.last_acknowledge_num = tcp_packet.ack_number;
                    send_vars.initial_sequence_num = send_vars.next_sequence_num;
                    if let Some(mss) = tcp_packet.option.mss {
                        send_vars.send_mss = mss;
                    } else {
                        // "SendMSS is... or the default 536 for IPv4 or 1220 for IPv6, if no MSS Option is received." rfc9293
                        send_vars.send_mss = 536;
                    }
                    let mut recv_vars = ReceiveVariables::new();
                    recv_vars.next_sequence_num = tcp_packet.seq_number.wrapping_add(1);
                    recv_vars.window_size = 4096; // todo: adjust window size
                    recv_vars.initial_sequence_num = tcp_packet.seq_number;
                    let src_addr = Ipv4Addr::from(tcp_packet.dst_addr);
                    let dst_addr = Ipv4Addr::from(tcp_packet.src_addr);
                    let new_conn = TcpConnection {
                        src_addr: src_addr,
                        dst_addr: dst_addr,
                        local_port: tcp_packet.remote_port,
                        remote_port: tcp_packet.local_port,
                        status: TcpStatus::SynRcvd,
                        send_vars: send_vars,
                        recv_vars: recv_vars
                    };
                    if queue.accepted > 0 {
                        // socket is already accepted and waiting for new established connection.
                        let mut syn_ack = tcp_packet.create_reply_base();
                        let seq = new_conn.send_vars.next_sequence_num;
                        let ack = new_conn.recv_vars.next_sequence_num;
                        syn_ack.seq_number = seq;
                        syn_ack.ack_number = ack;
                        syn_ack.flag_syn = true;
                        syn_ack.flag_ack = true;
                        syn_ack.windows_size = new_conn.recv_vars.window_size;
                        // 40 = ip header size (20) + tcp header size (20)
                        syn_ack.option.mss = Some((self.config.mtu - 40) as u16);
                        conns.insert(id, Some(new_conn));
                        log::debug!(
                            "Generated SYN-RECEIVED socket (id={} local={}:{} remote={}:{}) from LISTEN socket (id={}).",
                            id, src_addr, tcp_packet.remote_port, dst_addr, tcp_packet.local_port, socket_id
                        );
                        queue.pending.push_back(id);
                        self.send_tcp_packet(syn_ack)?;
                        log::debug!(
                            "Acctepted socket (id={}) reply syn-ack to {}:{} in listen_handler. SEQ={} ACK={}",
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
            anyhow::bail!("Failed to generate a new tcp socket because no available id. TCP_MAX_SOCKET={}", TCP_MAX_SOCKET)
        } else {
            anyhow::bail!("No listen queue for socket id {} which status is Listen.", socket_id);
        }
    }

    pub fn syn_sent_handler(&self) -> Result<()> {
        Ok(())
    }

    pub fn syn_recv_handler(&self) -> Result<()> {
        Ok(())
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

    fn publish_event(&self, event: TcpEvent) {
        let (lock, condvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = event;
        condvar.notify_all();
    }
}

pub struct ListenQueue {
    pub pending: VecDeque<usize>,
    pub established_unconsumed: VecDeque<usize>,
    pub established_consumed: VecDeque<usize>,
    pub accepted: usize,
}

#[derive(Debug)]
pub struct TcpConnection {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub status: TcpStatus,
    pub send_vars: SendVariables,
    pub recv_vars: ReceiveVariables,
}

//
// 1         2          3          4
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
    pub unacknowledged: u32,       // send unacknowledged (oldest unacknowledged sequence number)
    pub next_sequence_num: u32,    // send next (next sequence number to be sent), basically prev packet's ack
    pub window_size: u16,          // send window
    pub urgent_pointer: u16,       // send urgent pointer
    pub last_sequence_num: u32,    // segment sequence number used for last window update
    pub last_acknowledge_num: u32, // segment acknowledgment number used for last window update
    pub initial_sequence_num: u32, // initial send sequence number (ISS)
    pub send_mss: u16,             // Maximum Segment Size
}

impl SendVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

//
// 1         2          3
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
    pub next_sequence_num: u32,    // receive next, basically prev packet's syn + 1
    pub window_size: u16,          // receive window
    pub urgent_pointer: u16,       // receive urgent pointer
    pub initial_sequence_num: u32  // initial receive sequence number (IRS)
}

impl ReceiveVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcpEventType {
    InitailState,
    SocketAccepted,
    SynReceived,
    Established,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpEvent {
    socket_id: usize,
    event: TcpEventType
}