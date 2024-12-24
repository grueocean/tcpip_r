use thiserror::Error;
use std::fmt::{self, Display};
use std::net::{SocketAddrV4};

// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
pub enum TcpOptionKind {
    // 8 bit
    EndOption = 0x00,       // mandatory
    NoOperation = 0x01,     // mandatory, used for word boundary align
    MaxSegmentSize = 0x02,  // mandatory
    WindowScale = 0x3,      // https://datatracker.ietf.org/doc/html/rfc7323#section-2
    SackPermission = 0x04,  // rfc2018, rfc2883
    SackOption = 0x05,      // rfc2018, rfc2883
    Timestamp = 0x08,       // https://datatracker.ietf.org/doc/html/rfc7323#section-3
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


#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TcpStatus {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

impl Display for TcpStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TcpStatus::Listen => write!(f, "LISTEN"),
            TcpStatus::SynSent => write!(f, "SYN-SENT"),
            TcpStatus::SynRcvd => write!(f, "SYN-RCVD"),
            TcpStatus::Established => write!(f, "ESTABLISHED"),
            TcpStatus::FinWait1 => write!(f, "FIN-WAIT-1"),
            TcpStatus::FinWait2 => write!(f, "FIN-WAIT-2"),
            TcpStatus::TimeWait => write!(f, "TIME-WAIT"),
            TcpStatus::CloseWait => write!(f, "CLOSE-WAIT"),
            TcpStatus::LastAck => write!(f, "LAST-ACK"),
            TcpStatus::Closed => write!(f, "CLOSED"),
        }
    }
}

#[derive(Error, Debug)]
pub enum TcpError {
    #[error("Connection refused. socket id: {id} remote addr: {addr}")]
    RefusedError {
        id: usize,
        addr: SocketAddrV4
    },
    #[error("Connection closed. socket id: {id} remote addr: {addr}")]
    ClosedError {
        id: usize,
        addr: SocketAddrV4
    },
}