use anyhow::Result;
use clap::Parser;
use eui48::MacAddress;
use hex;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::from_utf8;
use tcpip_r::udp::udp_impl::UdpNetworkInfo;
use tcpip_r::{
    l2_l3::ip::{generate_network_config, Ipv4Config},
    udp::udp_impl::UdpSocket,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(
    after_help = "EXAMPLES: ./udp_echo_client -i d1 -n 172.20.10.101/24 -g 172.20.10.1 -d 172.20.10.100 -p 300"
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
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config =
        generate_network_config(args.iface, args.mac, args.mtu, args.network, args.gateway)?;
    let mut udp = UdpSocket::new(config)?;
    udp.bind(SocketAddrV4::new(args.network.address, 0 as u16))?;
    if let Some(info) = udp.info {
        println!("Udp socket bind to {}.", info.local);
    }
    udp.connect(SocketAddrV4::new(args.dst, args.port))?;
    if let Some(UdpNetworkInfo {
        local: _,
        remote: Some(remote),
    }) = udp.info
    {
        println!("Udp socket connect to {}.", remote);
    }
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        udp.send(input.as_bytes())?;

        let mut buf = [0; 1024];
        let amt = udp.recv(&mut buf)?;
        let data = &buf[..amt];
        let ascii = from_utf8(data)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| String::from("Data contains non-ASCII characters"));
        let hex = hex::encode(data);
        println!("Udp reply received ({} bytes).", amt);
        println!("hex: {} ascii: {}", hex, ascii);
    }
}