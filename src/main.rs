mod arp;
use arp::L2Stack;
mod ethernet;
mod ip;
mod types;
use env_logger;
use eui48::MacAddress;
use std::net::Ipv4Addr;

fn main() {
    env_logger::init();
    let mac = MacAddress::new([0x5a, 0x9f, 0x4a, 0x65, 0xc4, 0x1f]);
    let ip = (Ipv4Addr::new(172, 20, 10, 10), 24);
    let l2 = L2Stack::new("d0".to_string(), mac, ip);
    loop {
    }
}