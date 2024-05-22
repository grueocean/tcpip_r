use crate::{
    l2_l3::{defs::Ipv4Type, ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration}},
    tcp::{defs::TcpStatus, packet::TcpPacket}
};
use anyhow::{Context, Result};
use pnet::packet::tcp::Tcp;
use std::{collections::HashMap, default, sync::MutexGuard, time::Duration};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc::channel};
use std::thread::{self, JoinHandle};

const TCP_MAX_SOCKET: usize = 100;
// "the Dynamic Ports, also known as the Private or Ephemeral Ports, from 49152-65535 (never assigned)" rfc6335
const TCP_EPHEMERAL_PORT_RANGE: Range<u16> = 49152..65535;
// "The present global default is five minutes." rfc9293
const TCP_OPEN_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_MAX_CONCURRENT_SESSION: usize = 10;
const TCP_MAX_LISTEN_QUEUE: usize = TCP_MAX_CONCURRENT_SESSION * 3 / 2;

static TCP_STACK_GLOBAL: OnceLock<Arc<TcpStack>> = OnceLock::new();

pub fn get_global_tcpstack(config: NetworkConfiguration) -> Result<&'static Arc<TcpStack>> {
    Ok(TCP_STACK_GLOBAL.get_or_init(|| TcpStack::new(config).unwrap()))
}

pub struct TcpStack {
    pub config: NetworkConfiguration,
    pub connections: Mutex<HashMap<usize, Option<TcpConnection>>>,
    pub listen_queue: Mutex<HashMap<usize, ListenQueue>>,
    pub threads: Mutex<Vec<JoinHandle<()>>>,
}

impl TcpStack {
    pub fn new(config: NetworkConfiguration) -> Result<Arc<Self>> {
        let tcp = Arc::new(Self {
            config: config,
            connections: Mutex::new(HashMap::new()),
            listen_queue: Mutex::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
        });
        Ok(tcp)
    }

    pub fn generate_socket(&self) -> Result<usize> {
        let mut conns = self.connections.lock().unwrap();
        for id in 1..TCP_MAX_SOCKET {
            if conns.contains_key(&id) {
                continue;
            } else {
                conns.insert(id, None);
                return Ok(id);
            }
        }

        anyhow::bail!("Failed to generate new tcp socket because no available id. TCP_MAX_SOCKET={}", TCP_MAX_SOCKET)
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
                anyhow::bail!("Tcp socket({}) is already bound to {}:{}.", socket_id, conn.src_addr, conn.local_port);
            } else {
                // assign ephemeral port
                if addr.port() == 0 {
                    for port in TCP_EPHEMERAL_PORT_RANGE {
                        if !used_ports.contains(&port) {
                            let new_conn = TcpConnection {
                                src_addr: *addr.ip(),
                                dst_addr: None,
                                local_port: port,
                                remote_port: None,
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
                            dst_addr: None,
                            local_port: addr.port(),
                            remote_port: None,
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
                listen_queue.insert(socket_id, ListenQueue {pending: Vec::new(), established: Vec::new()});
                Ok(())
            } else {
                anyhow::bail!("Only Closed socket can transit to Listen. Current: {}", conn.status);
            }
        } else {
            anyhow::bail!("Cannot listen Socket({}) which is not bound.", socket_id);
        }
    }

    // pub fn connect(&self, socket_id: usize, addr: SocketAddrV4) -> Result<()> {
    //     let mut conns = self.connections.lock().unwrap();
    //     if let Some(Some(conn)) = conns.get_mut(&socket_id) {
    //         let mut tcp_packet = TcpPacket::new();
    //     } else {
    //         anyhow::bail!("Socket({}) is not bound.", socket_id);
    //     }
    // }

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

    pub fn send_raw(&self, mut tcp_packet: TcpPacket) -> Result<()> {
        let mut ipv4_packet = Ipv4Packet::new();
        ipv4_packet.protocol = u8::from(Ipv4Type::TCP);
        ipv4_packet.dst_addr = tcp_packet.dst_addr;
        ipv4_packet.payload = tcp_packet.create_packet();
        let l3 = get_global_l3stack(self.config.clone())?;
        l3.l3interface.send(ipv4_packet)?;

        Ok(())
    }

    pub fn receive_thread(&self) -> Result<()> {
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
                Ok(_) => {}
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
        let mut socket_id = None;
        let conns = self.connections.lock().unwrap();
        for (id, connection_info) in conns.iter() {
            if let Some(TcpConnection {
                src_addr: s_addr,
                dst_addr: Some(d_addr),
                local_port: l_port,
                remote_port: Some(r_port),
                status: _status,
                send_vars: _send_vars,
                recv_vars: _recv_vars
            }) = connection_info {
                if s_addr == dst_addr && d_addr == src_addr && l_port == remote_port && r_port == local_port {
                    socket_id = Some(*id);
                } else {
                    continue;
                }
            }
            if let Some(TcpConnection {
                src_addr: s_addr,
                dst_addr: None,
                local_port: l_port,
                remote_port: None,
                status: _status,
                send_vars: _send_vars,
                recv_vars: _recv_vars
            }) = connection_info {
                if s_addr == dst_addr && l_port == remote_port {
                    socket_id = Some(*id);
                } else {
                    continue;
                }
            }
        }
        if socket_id.is_none() {
            log::debug!("There is tcp socket for the packet (src={}:{} dst={}:{}).", src_addr, local_port, dst_addr, remote_port);
        }
        Ok((socket_id, conns))
    }

    pub fn tcp_packet_handler(&self, tcp_packet: &TcpPacket) -> Result<()> {
        let (socket_id, conns) = self.get_socket_id(
            &Ipv4Addr::from(tcp_packet.src_addr),
            &Ipv4Addr::from(tcp_packet.dst_addr),
            &tcp_packet.local_port,
            &tcp_packet.remote_port
        )?;
        if let Some(id) = socket_id {
            if let Some(Some(conn)) = conns.get(&id) {
                match &conn.status {
                    TcpStatus::Listen => {}
                    other => {
                        anyhow::bail!("Handler for TcpStatus {} is not implemented.", other);
                    }
                }
            } else {
                anyhow::bail!("No TcpConnection Data for socket id {}. This should be impossible if locking logic is correct.", id);
            }
        } else {
        }
        drop(conns);
        Ok(())
    }

    pub fn listen_handler(&self) -> Result<()> {
        Ok(())
    }

    pub fn syn_sent_handler(&self) -> Result<()> {
        Ok(())
    }

    pub fn syn_recv_handler(&self) -> Result<()> {
        Ok(())
    }

    fn generate_initial_sequence() -> u32 {
        100
    }
}

pub struct ListenQueue {
    pub pending: Vec<usize>,
    pub established: Vec<usize>,
}

pub struct TcpConnection {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Option<Ipv4Addr>,
    pub local_port: u16,
    pub remote_port: Option<u16>,
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
#[derive(Default)]
pub struct SendVariables {
    pub unacknowledged: u32,       // send unacknowledged (oldest unacknowledged sequence number)
    pub next_sequence_num: u32,    // send next (next sequence number to be sent)
    pub window_size: u16,          // send window
    pub urgent_pointer: u16,       // send urgent pointer
    pub last_sequence_num: u32,    // segment sequence number used for last window update
    pub last_acknowledge_num: u32, // segment acknowledgment number used for last window update
    pub initial_sequence_num: u32  // initial send sequence number (ISS)
}

//
// 1          2          3
// ----------|----------|----------
//        RCV.NXT    RCV.NXT
//                  +RCV.WND
//
// 1 - old sequence numbers that have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers that are not yet allowed
//
//        Figure 4: Receive Sequence Space (rfc9293)
#[derive(Default)]
pub struct ReceiveVariables {
    pub next_sequence_num: u32,    // receive next
    pub window_size: u16,          // receive window
    pub urgent_pointer: u16,       // receive urgent pointer
    pub initial_sequence_num: u32  // initial receive sequence number (IRS)
}