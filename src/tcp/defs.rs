// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
#[repr(u8)]
pub enum TcpOptionKind {
    // 8 bit
    EndOption = 0x00u8,       // mandatory
    NoOperation = 0x01u8,     // mandatory, used for word boundary allign
    MaxSegmentSize = 0x02u8,  // mandatory
    WindowScale = 0x3u8,      // https://datatracker.ietf.org/doc/html/rfc7323#section-2
    SackPermission = 0x04u8,  // rfc2018, rfc2883
    SackOption = 0x05u8,      // rfc2018, rfc2883
    Timestamp = 0x08u8,       // https://datatracker.ietf.org/doc/html/rfc7323#section-3
    Unknown
}

impl From<u8> for TcpOptionKind {
    fn from(value: u8) -> Self {
        match value {
            v if v == TcpOptionKind::EndOption as u8 => TcpOptionKind::EndOption,
            v if v == TcpOptionKind::NoOperation as u8 => TcpOptionKind::NoOperation,
            v if v == TcpOptionKind::MaxSegmentSize as u8 => TcpOptionKind::MaxSegmentSize,
            v if v == TcpOptionKind::WindowScale as u8 => TcpOptionKind::WindowScale,
            v if v == TcpOptionKind::SackPermission as u8 => TcpOptionKind::SackPermission,
            v if v == TcpOptionKind::SackOption as u8 => TcpOptionKind::SackOption,
            v if v == TcpOptionKind::Timestamp as u8 => TcpOptionKind::Timestamp,
            _ => TcpOptionKind::Unknown
        }
    }
}

impl From<TcpOptionKind> for u8 {
    fn from(t: TcpOptionKind) -> Self {
        t as u8
    }
}