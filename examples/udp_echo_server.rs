use anyhow::Result;
use clap::Parser;
use eui48::MacAddress;
use hex;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::from_utf8;
use tcpip_r::{
    l2_l3::ip::{generate_network_config, Ipv4Config},
    udp::udp_impl::UdpSocket,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(
    after_help = "EXAMPLES: ./udp_echo_server -i d0 -n 172.20.10.100/24 -g 172.20.10.1 -p 300"
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
        short = 'p',
        help = "Port for this udp server (0 if assign ephemeral port), e.g., 300",
        default_value_t = 0
    )]
    port: u16,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config =
        generate_network_config(args.iface, args.mac, args.mtu, args.network, args.gateway)?;
    let mut udp = UdpSocket::new(config)?;
    udp.bind(SocketAddrV4::new(args.network.address, args.port))?;
    if let Some(info) = udp.info {
        println!("Udp socket bind to {}.", info.local);
    }
    let reply = format!("Ack from udp server {}", udp.info.unwrap().local);
    loop {
        let mut buf = [0; 1024];
        match udp.recv_from(&mut buf) {
            Ok((amt, src)) => {
                let data = &buf[..amt];
                let ascii = from_utf8(data)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| String::from("Data contains non-ASCII characters"));
                let hex = hex::encode(data);
                println!("Udp packet received from {} ({} bytes).", src, amt);
                println!("hex: {} ascii: {}", hex, ascii);
                udp.send_to(reply.as_bytes(), src)?;
            }
            Err(e) => {
                println!("Udp recv error. Err: {}", e);
            }
        }
    }
}