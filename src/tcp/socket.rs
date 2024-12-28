use crate::{
    l2_l3::{
        defs::Ipv4Type,
        ip::{get_global_l3stack, Ipv4Packet, L3Stack, NetworkConfiguration},
    },
    tcp::{defs, packet::TcpPacket, usrreq},
};
use anyhow::{Context, Result};
use std::sync::{mpsc::channel, Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs},
    sync::MutexGuard,
};

use super::usrreq::get_global_tcpstack;

pub struct TcpListener {
    config: NetworkConfiguration,
    socket_id: usize,
}

impl TcpListener {
    pub fn new(config: NetworkConfiguration) -> Result<Self> {
        let tcp = get_global_tcpstack(config.clone())?;
        let id = tcp.generate_socket()?;
        Ok(Self {
            config: config.clone(),
            socket_id: id,
        })
    }

    pub fn bind<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        match addr.to_socket_addrs()?.next() {
            Some(addr) => match addr.ip() {
                IpAddr::V4(v4_addr) => {
                    let ip = SocketAddrV4::new(v4_addr, addr.port());
                    let tcp = get_global_tcpstack(self.config.clone())?;
                    tcp.bind(self.socket_id, ip)?;
                    tcp.listen(self.socket_id)?;
                    Ok(())
                }
                IpAddr::V6(_) => {
                    anyhow::bail!("Ipv6 is not supported.")
                }
            },
            None => {
                anyhow::bail!("Address may be invalid.")
            }
        }
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddrV4)> {
        let tcp = get_global_tcpstack(self.config.clone())?;
        let (id, addr) = tcp.accept(self.socket_id)?;
        return Ok((
            TcpStream {
                socket_id: id,
                config: self.config.clone(),
            },
            addr,
        ));
    }

    pub fn close(&self) {}
}

#[derive(Clone)]
pub struct TcpStream {
    config: NetworkConfiguration,
    socket_id: usize,
}

impl TcpStream {
    pub fn new(config: NetworkConfiguration) -> Result<Self> {
        let tcp = get_global_tcpstack(config.clone())?;
        let id = tcp.generate_socket()?;
        Ok(Self {
            config: config.clone(),
            socket_id: id,
        })
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        self.connect_with_bind(addr, 0)?;
        Ok(())
    }

    // Original TcpStrem dosen't have an interface to specify the local port, but I add this for debugging purposes.
    pub fn connect_with_bind<A: ToSocketAddrs>(&self, addr: A, local_port: u16) -> Result<()> {
        match addr.to_socket_addrs()?.next() {
            Some(addr) => match addr.ip() {
                IpAddr::V4(v4_addr) => {
                    let tcp = get_global_tcpstack(self.config.clone())?;
                    tcp.bind(
                        self.socket_id,
                        SocketAddrV4::new(self.config.ip.address, local_port),
                    )?;
                    tcp.connect(self.socket_id, SocketAddrV4::new(v4_addr, addr.port()))?;
                    Ok(())
                }
                IpAddr::V6(_) => {
                    anyhow::bail!("Ipv6 is not supported.")
                }
            },
            None => {
                anyhow::bail!("Address may be invalid.")
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let tcp = get_global_tcpstack(self.config.clone())?;
        Ok(tcp.write(self.socket_id, buf)?)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let tcp = get_global_tcpstack(self.config.clone())?;
        Ok(tcp.read(self.socket_id, buf)?)
    }

    pub fn shutdown(&self) -> Result<()> {
        let tcp = get_global_tcpstack(self.config.clone())?;
        Ok(tcp.shutdown(self.socket_id)?)
    }
}
