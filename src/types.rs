use thiserror::Error;
use std::net::Ipv4Addr;

// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#[derive(Debug, PartialEq)]
pub enum EtherType {
    // 16 bit
    IPv4 = 0x0800,
    ARP = 0x0806,
    Reserved = 0xffff,
    Unknown
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            v if v == EtherType::IPv4 as u16 => EtherType::IPv4,
            v if v == EtherType::ARP as u16 => EtherType::ARP,
            v if v == EtherType::Reserved as u16 => EtherType::Reserved,
            _ => EtherType::Unknown
        }
    }
}

impl From<EtherType> for u16 {
    fn from(e: EtherType) -> Self {
        e as u16
    }
}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#[derive(Debug, PartialEq)]
pub enum Ipv4Type {
    // 8 bit
    ICMP = 0x1,
    TCP = 0x6,
    UDP = 0x11,
    Unknown
}

impl From<u8> for Ipv4Type {
    fn from(value: u8) -> Self {
        match value {
            v if v == Ipv4Type::ICMP as u8 => Ipv4Type::ICMP,
            v if v == Ipv4Type::TCP as u8 => Ipv4Type::TCP,
            v if v == Ipv4Type::UDP as u8 => Ipv4Type::UDP,
            _ => Ipv4Type::Unknown
        }
    }
}

impl From<Ipv4Type> for u8 {
    fn from(e: Ipv4Type) -> Self {
        e as u8
    }
}

#[derive(Error, Debug)]
pub enum L2Error {
    #[error("Failed to resolve IP {target_ip} after {retries} attempts.")]
    ResolveError {
        target_ip: Ipv4Addr,
        retries: usize,
    },
}

#[derive(Error, Debug)]
pub enum L3Error {
    #[error("Cannot send packet to netowrk address {target_ip}. l2Stack netwrok is {l2_ip}/{l2_netmask}.")]
    AddressError {
        target_ip: Ipv4Addr,
        l2_ip: Ipv4Addr,
        l2_netmask: usize
    },
    #[error("Destination {target_ip} within local network is unreachable.")]
    LocalUnreachableError {
        target_ip: Ipv4Addr
    },
    #[error("Gateway {target_ip} is unreachable.")]
    GatewayUnreachableError {
        target_ip: Ipv4Addr
    },
}