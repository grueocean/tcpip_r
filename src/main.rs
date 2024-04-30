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

use crate::ip::{NetworkConfiguration, Ipv4Network, Route, L3Interface};
use crate::udp::{UdpStack, UdpNetworkInfo};

fn main() {
    env_logger::init();
    let mac = MacAddress::new([0x5a, 0x9f, 0x4a, 0x65, 0xc4, 0x1f]);
    let ip = Ipv4Config {
        address: Ipv4Addr::new(172, 20, 10, 100),
        netmask: 24,
        broadcast_address: Ipv4Addr::new(172, 20, 10, 255),
        network_address: Ipv4Addr::new(172, 20, 10, 0)
    };
    let route = vec![(Ipv4Network { address: Ipv4Addr::new(192, 168, 1, 0), netmask: 24 }, Route { gateway_addr: Ipv4Addr::new(192, 168, 1, 1), rank: 10 })];
    let config = NetworkConfiguration {
        interface_name: "d0".to_string(),
        mac: mac,
        mtu: 1500,
        ip: ip,
        gateway: route.into_iter().collect()
    };
    let udp = UdpStack::new(config).unwrap();
    let socket = udp.generate_socket().unwrap();
    let udp_info = UdpNetworkInfo {
        local_addr: Ipv4Addr::new(172, 20, 10, 100),
        remote_addr: None,
        local_port: 200 as u16,
        remote_port: None
    };
    // use hex::decode;
    // use ip::Ipv4Packet;
    // use std::collections::HashMap;
    // let gateway = HashMap::new();
    // let l3 = L3Interface::new("d0".to_string(), mac, 1500, ip, gateway).unwrap();
    // let test = "45000054bee5400040010ec9ac140a64ac140a6e08007f8c0f3a00012c5b1e660000000056a4090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
    // let mut packet = Ipv4Packet::new();
    // packet.read(&decode(test).unwrap());
    // println!("packet: {:?}", packet);
    // l3.send(packet);

    loop {
        udp.bind(socket, udp_info).unwrap();
        let (info, packet) = udp.recv(socket).unwrap();
        dbg!(info);
        dbg!(packet);
        // use hex::decode;
        // let test = "45000054bee5400040010ec9ac140a64ac140a6e08007f8c0f3a00012c5b1e660000000056a4090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
        // l2.send(&decode(test).unwrap());
    }
}