use crate::tcp::{
    defs::TcpStatus, tcp_impl::{TcpStack, TcpConnection, TcpEvent, TcpEventType}, packet::TcpPacket
};
use anyhow::{Context, Result};
use std::{collections::{HashMap, VecDeque}, sync::MutexGuard, time::{Duration, Instant}};

// From FreeBSD 14.1.0 implementation.
const TCP_MAXRXTSHIFT: usize = 5;
const TCP_MAXRXTSHIFT_DEFAULT: usize = 12;
const TCP_BACKOFF: [usize; TCP_MAXRXTSHIFT_DEFAULT] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 512, 512
];
// TCP_REXMT_*** are all msec.
const TCP_REXMT_INIT: usize = 1_000;  // BSD: tcp_rexmit_initial
const TCP_REXMT_SLOP: usize = 20;     // BSD: tcp_rexmit_slop
const TCP_REXMT_MIN: usize = 30;      // BSD: tcp_rexmit_min
const TCP_REXMT_MAX: usize = 64_000;  // BSD: TCPTV_REXMTMAX

impl TcpStack {
    pub fn timer_thread(&self) -> Result<()> {
        log::info!("Starting TcpStack timer_thread.");
        loop {
            match self.timer_handler() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Failed to handle TcpTimer. Err: {:?}", e);
                }
            }
        }
    }

    pub fn timer_handler(&self) -> Result<()> {
        let mut conns = self.connections.lock().unwrap();
        let statusmap: HashMap<usize, TcpStatus> = conns
            .iter()
            .filter_map(|(&id, conn_option)| {
                conn_option.as_ref().map(|conn| (id, conn.status.clone()))
            })
            .collect();
        for (socket_id, status) in statusmap {
            match status {
                TcpStatus::SynSent => { self.timer_handler_syn(socket_id, &mut conns).context("timer_handler_syn failed. (state=SYN-SENT)")?; }
                TcpStatus::SynRcvd => { self.timer_handler_syn(socket_id, &mut conns).context("timer_handler_syn failed. (state=SYN-RCVD)")?; }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn timer_handler_syn(&self, socket_id: usize, conns: &mut MutexGuard<HashMap<usize, Option<TcpConnection>>>) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if conn.timer.retransmission.timer_param.rexmt_shift == 0 { return Ok(() ); };
            if conn.timer.retransmission.is_expired()? {
                if let Err(e) = self.send_handler(&[0; 0], conn) {
                    conn.timer.retransmission.next_syn();
                    log::debug!(
                        "Failed to retransmit SYN packet. socket_id={} {} next shift={} next delta={} Err: {:?}",
                        socket_id, conn.print_address(), e,
                        conn.timer.retransmission.timer_param.rexmt_shift, conn.timer.retransmission.timer_param.delta
                    );
                } else {
                    conn.timer.retransmission.next_syn();
                    log::debug!(
                        "Retransmitted SYN packet. socket_id={} local={}:{} remote={}:{} next shift={} next delta={}",
                        socket_id, conn.src_addr, conn.local_port, conn.dst_addr, conn.remote_port,
                        conn.timer.retransmission.timer_param.rexmt_shift, conn.timer.retransmission.timer_param.delta
                    );
                }
                if conn.timer.retransmission.is_finished() {
                    log::debug!(
                        "Gave up retransmitting SYN packet and closing the socket (id={}). local={}:{} remote={}:{}",
                        socket_id, conn.src_addr, conn.local_port, conn.dst_addr, conn.remote_port
                    );
                    self.publish_event(TcpEvent {socket_id: socket_id, event: TcpEventType::Closed});
                }
            }
        } else {
            anyhow::bail!("Cannot find socket (id={}).", socket_id);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum TcpTimerType {
    Retransmission
}

#[derive(Debug, Default)]
pub struct RetransmissionVariables {
    pub rexmt_shift: usize,
    pub rtt: usize,
    pub rtt_smoothed: usize,
    pub rtt_variance: usize,
    pub delta: usize
}

impl RetransmissionVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct RetransmissionTimer {
    pub timer_type: TcpTimerType,
    pub timer_param: RetransmissionVariables,
    pub timer_count: Instant
}

impl RetransmissionTimer {
    pub fn new() -> Self {
        Self {
            timer_type: TcpTimerType::Retransmission,
            timer_param: RetransmissionVariables::new(),
            timer_count: Instant::now()
        }
    }

    pub fn init(&mut self) {
        self.timer_param.rexmt_shift = 0;
        self.timer_param.rtt = 0;
        self.timer_param.rtt_smoothed = 0;
        self.timer_param.rtt_variance = 0;
    }

    pub fn fire_syn(&mut self) {
        self.timer_param.rexmt_shift = 0;
        self.next_syn();
        log::debug!(
            "Retransmission timer for SYN packet is fired. MAX={} initial delta={}",
            TCP_MAXRXTSHIFT, self.timer_param.delta
        );
    }

    pub fn next_syn(&mut self) {
        self.timer_count = Instant::now();
        let next_shift = self.timer_param.rexmt_shift + 1;
        self.timer_param.rexmt_shift = next_shift;
        let calc_delta = TCP_REXMT_INIT * TCP_BACKOFF[next_shift - 1];
        let delta: usize;
        if calc_delta < TCP_REXMT_MIN {
            delta = TCP_REXMT_MIN + TCP_REXMT_SLOP;
        } else if calc_delta > TCP_REXMT_MAX {
            delta = TCP_REXMT_MAX + TCP_REXMT_SLOP;
        } else {
            delta = calc_delta + TCP_REXMT_SLOP;
        }
        self.timer_param.delta = delta;
    }

    pub fn is_expired(&mut self) -> Result<bool> {
        let current = self.timer_param.rexmt_shift;
        anyhow::ensure!(
            current != 0 && current <= TCP_MAXRXTSHIFT,
            "Retransmission counter is {} should be 1~{}.", current, TCP_MAXRXTSHIFT
        );
        if self.timer_count.elapsed() > Duration::from_millis(self.timer_param.delta as u64) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn is_finished(&mut self) -> bool {
        if self.timer_param.rexmt_shift >= TCP_MAXRXTSHIFT + 1 {
            self.init();
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct TcpTimer {
    pub retransmission: RetransmissionTimer,
}

impl TcpTimer {
    pub fn new() -> Self {
        Self {
            retransmission: RetransmissionTimer::new()
        }
    }
}