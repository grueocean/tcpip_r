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
    UDP = 0x11
}