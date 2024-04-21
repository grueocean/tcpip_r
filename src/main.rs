mod arp;
use arp::L2Stack;
mod ethernet;
mod ip;
use ip::Ipv4Config;
mod types;
mod udp;
use env_logger;
use eui48::MacAddress;
use std::{hash::Hash, net::Ipv4Addr};

use crate::ip::L3Interface;

fn main() {
    env_logger::init();
    let mac = MacAddress::new([0x5a, 0x9f, 0x4a, 0x65, 0xc4, 0x1f]);
    let ip = Ipv4Config {
        address: Ipv4Addr::new(172, 20, 10, 100),
        netmask: 24,
        broadcast_address: Ipv4Addr::new(172, 20, 10, 255),
        network_address: Ipv4Addr::new(172, 20, 10, 0)
    };
    use hex::decode;
    use ip::Ipv4Packet;
    use std::collections::HashMap;
    let gateway = HashMap::new();
    let l3 = L3Interface::new("d0".to_string(), mac, 1500, ip, gateway).unwrap();
    let test = "45000054bee5400040010ec9ac140a64ac140a6e08007f8c0f3a00012c5b1e660000000056a4090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
    let mut packet = Ipv4Packet::new();
    packet.read(&decode(test).unwrap());
    println!("packet: {:?}", packet);
    l3.send(packet);
    loop {
        // use hex::decode;
        // let test = "45000054bee5400040010ec9ac140a64ac140a6e08007f8c0f3a00012c5b1e660000000056a4090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
        // l2.send(&decode(test).unwrap());
    }
}