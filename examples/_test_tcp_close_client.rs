use anyhow::Result;
use clap::Parser;
use eui48::MacAddress;
use hex;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::from_utf8;
use std::thread;
use tcpip_r::{
    l2_l3::ip::{generate_network_config, Ipv4Config},
    tcp::{
        socket::{TcpListener, TcpStream},
        usrreq::Shutdown,
    },
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(
    after_help = "EXAMPLES: ./_test_tcp_close_client -i d0 -n 172.20.10.100/24 -g 172.20.10.1 -p 300"
)]
struct Args {
    #[arg(long, short = 'i', help = "Interface name, e.g., eth0")]
    iface: String,

    #[arg(long, help = "Mac address for interface, e.g., 11:22:33:44:55:66", default_value_t = MacAddress::new([0, 0, 0, 0, 0, 0]))]
    mac: MacAddress,

    #[arg(long, help = "Mtu for interface, e.g., 1500", default_value_t = 1500)]
    mtu: usize,

    #[arg(
        long,
        short = 'n',
        help = "CIDR IPv4 address for interface, e.g., 172.20.10.100/24"
    )]
    network: Ipv4Config,

    #[arg(long, short = 'g', help = "Gateway Ipv4 Address, e.g., 172.20.10.1")]
    gateway: Ipv4Addr,

    #[arg(
        long,
        short = 'd',
        help = "Destination Ipv4 Address, e.g., 172.20.10.1"
    )]
    dst: Ipv4Addr,

    #[arg(long, short = 'p', help = "Destination port, e.g., 300")]
    port: u16,

    #[arg(long, help = "Local port, e.g., 300", default_value_t = 0)]
    lport: u16,
}

fn main() -> Result<()> {
    if let Some(binary_name) = std::env::args().next() {
        eprintln!("name: {}", binary_name);
    }
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp_millis()
        .init();
    let args = Args::parse();
    let config =
        generate_network_config(args.iface, args.mac, args.mtu, args.network, args.gateway)?;
    let tcp = TcpStream::new(config)?;
    tcp.connect_with_bind(SocketAddrV4::new(args.dst, args.port), args.lport)?;
    println!("Socket connected!");
    tcp.shutdown(Shutdown::Both)?;
    tcp.wait(None)?;
    println!("Socket shutdown.");
    Ok(())
}
