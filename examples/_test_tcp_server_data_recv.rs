use anyhow::{Context, Result};
use clap::Parser;
use eui48::MacAddress;
use hex;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::Duration;
use tcpip_r::{
    l2_l3::ip::{generate_network_config, Ipv4Config},
    tcp::socket::{TcpListener, TcpStream},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(after_help = "EXAMPLES: ./tcp_server -i d0 -n 172.20.10.100/24 -g 172.20.10.1 -p 300")]
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
        help = "Port for this tcp server (0 if assign ephemeral port), e.g., 300",
        default_value_t = 0
    )]
    port: u16,

    #[arg(long, help = "File to be rcvd")]
    file: String,

    #[arg(long, help = "Transfer size")]
    size: usize,
}

fn main() -> Result<()> {
    eprintln!("_test_tcp_server_data_recv started");
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp_millis()
        .init();
    let args = Args::parse();
    let config =
        generate_network_config(args.iface, args.mac, args.mtu, args.network, args.gateway)?;
    let tcp = TcpListener::new(config)?;
    tcp.bind(SocketAddrV4::new(args.network.address, args.port))?;
    let (stream, _addr) = tcp.accept()?;
    println!("Socket accepted!");
    let mut total_bytes: usize = 0;
    let mut buffer = [0u8; 1024];
    let mut rcvd_data = Vec::new();
    loop {
        let bytes_read = stream.read(&mut buffer)?;
        total_bytes += bytes_read;
        rcvd_data.extend_from_slice(&buffer[..bytes_read]);
        if bytes_read == 0 || total_bytes == args.size {
            break;
        }
    }
    stream.shutdown()?;
    let file_data = fs::read(args.file)?;
    if rcvd_data == file_data {
        Ok(())
    } else {
        eprintln!("Received data is incorrect.");
        anyhow::bail!("Received data is incorrect.")
    }
}
