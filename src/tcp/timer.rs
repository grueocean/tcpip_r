use crate::tcp::{
    defs::TcpStatus,
    input::{TcpConnection, TcpEvent, TcpEventType},
    packet::TcpPacket,
    usrreq::TcpStack,
};
use anyhow::{Context, Result};
use std::{
    cmp::max,
    collections::{HashMap, VecDeque},
    sync::MutexGuard,
    thread,
    time::{Duration, Instant},
};

// From FreeBSD 14.1.0 implementation.
const TCP_MAXRXTSHIFT: usize = 12;
const TCP_MAXRXTSHIFT_DEFAULT: usize = 12;
const TCP_RTT_INVALIDATE: usize = TCP_MAXRXTSHIFT_DEFAULT / 4;
// 1 (i=0) is not used for the actual retransmission.
const TCP_BACKOFF: [usize; TCP_MAXRXTSHIFT_DEFAULT + 2] =
    [1, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 512, 512, 0];
// TCP_REXMT_*** are all msec.
const TCP_REXMT_INIT: usize = 1_000; // BSD: tcp_rexmit_initial
const TCP_REXMT_SLOP: usize = 20; // BSD: tcp_rexmit_slop
const TCP_REXMT_MIN: usize = 30; // BSD: tcp_rexmit_min
const TCP_REXMT_MAX: usize = 64_000; // BSD: TCPTV_REXMTMAX
const TCP_REXMT_RTTVAR_INIT: usize = 400;
// A: srtt  M: rtt  D: rttvar
const TCP_REXMT_GAIN_SHIFT: usize = 3; // α = 1/8 : A <- (1-α)A + α*M
const TCP_REXMT_MEAN_SHIFT: usize = 2; // β = 1/4 : D <- D + β*(|M-A|-D)
pub const TCP_SRTT_SHIFT: usize = 5; // srtt is scaled by 32 (2^5).
pub const TCP_RTTVAR_SHIFT: usize = 4; // rttvar is scaled by 16 (2^4).
const TCP_DELAY_ACK: usize = 40; // BSD: tcp_delacktime
const TCP_2MSL: usize = 10_000;

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
                TcpStatus::SynSent => {
                    self.timer_handler_syn(socket_id, &mut conns)
                        .context("timer_handler_syn failed. (state=SYN-SENT)")?;
                }
                TcpStatus::SynRcvd => {
                    self.timer_handler_syn(socket_id, &mut conns)
                        .context("timer_handler_syn failed. (state=SYN-RCVD)")?;
                }
                TcpStatus::Established => {
                    self.timer_handler_datagram(socket_id, &mut conns)
                        .context("timer_handler_datagram failed. (state=ESTABLISHED)")?;
                }
                TcpStatus::TimeWait => self
                    .timer_handler_timewait(socket_id, &mut conns)
                    .context("timer_handler_timewait failed. (state=TIME-WAIT)")?,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn timer_handler_syn(
        &self,
        socket_id: usize,
        conns: &mut MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if !conn.timer.retransmission.timer_param.active {
                return Ok(());
            };
            if conn.timer.retransmission.is_expired()? {
                if let Err(e) = self.send_handler(conn) {
                    conn.timer.retransmission.next_syn();
                    log::warn!(
                        "[{}] Failed to retransmit a SYN packet. next shift={} next delta={} Err: {:?}",
                        conn.print_log_prefix(socket_id), conn.timer.retransmission.timer_param.rexmt_shift, conn.timer.retransmission.timer_param.delta, e
                    );
                } else {
                    conn.timer.retransmission.next_syn();
                    log::debug!(
                        "[{}] Retransmitted a SYN packet. next shift={} next delta={}",
                        conn.print_log_prefix(socket_id),
                        conn.timer.retransmission.timer_param.rexmt_shift,
                        conn.timer.retransmission.timer_param.delta
                    );
                }
                if conn.timer.retransmission.is_finished() {
                    log::debug!(
                        "[{}] Gave up retransmitting a SYN packet and closing the socket.",
                        conn.print_log_prefix(socket_id),
                    );
                    conn.timer.retransmission.timer_param.active = false;
                    self.publish_event(TcpEvent {
                        socket_id: socket_id,
                        event: TcpEventType::Closed,
                    });
                }
            }
        } else {
            anyhow::bail!("Cannot find socket (id={}).", socket_id);
        }
        Ok(())
    }

    pub fn timer_handler_datagram(
        &self,
        socket_id: usize,
        conns: &mut MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            self.timer_handler_datagram_retransmission(socket_id, conn)?;
            self.timer_handler_datagram_delayed_ack(socket_id, conn)?;
        } else {
            anyhow::bail!("Cannot find socket (id={}).", socket_id);
        }
        Ok(())
    }

    fn timer_handler_datagram_retransmission(
        &self,
        socket_id: usize,
        conn: &mut TcpConnection,
    ) -> Result<()> {
        if !conn.timer.retransmission.timer_param.active {
            return Ok(());
        };
        if conn.timer.retransmission.is_expired()? {
            log::trace!(
                "[{}] Retransmission timer is sending packets. shift={} delta={}",
                conn.print_log_prefix(socket_id),
                conn.timer.retransmission.timer_param.rexmt_shift,
                conn.timer.retransmission.timer_param.delta,
            );
            conn.send_flag.ack_now = true;
            conn.send_flag.snd_from_una = true;
            if let Err(e) = self.send_handler(conn) {
                conn.timer.retransmission.next_datagram();
                log::warn!(
                    "[{}] Failed to retransmit a datagram packet. next shift={} next delta={} Err: {:?}",
                    conn.print_log_prefix(socket_id), conn.timer.retransmission.timer_param.rexmt_shift, conn.timer.retransmission.timer_param.delta, e
                );
            } else {
                conn.timer.retransmission.next_datagram();
                log::debug!(
                    "[{}] Retransmitted a datagram packet. next shift={} next delta={}",
                    conn.print_log_prefix(socket_id),
                    conn.timer.retransmission.timer_param.rexmt_shift,
                    conn.timer.retransmission.timer_param.delta
                );
            }
            // Based on Karn Algo, we won't mesure rtt during retransmission.
            conn.rtt_start = None;
            if conn.timer.retransmission.is_finished() {
                conn.timer.retransmission.init();
                log::debug!(
                    "[{}] Gave up retransmitting a datagram packet and closing the socket.",
                    conn.print_log_prefix(socket_id),
                );
                conn.status = TcpStatus::Closed;
                self.publish_event(TcpEvent {
                    socket_id: socket_id,
                    event: TcpEventType::Closed,
                });
            }
        }
        Ok(())
    }

    fn timer_handler_datagram_delayed_ack(
        &self,
        socket_id: usize,
        conn: &mut TcpConnection,
    ) -> Result<()> {
        if !conn.timer.delayed_ack.timer_param.active {
            return Ok(());
        };
        if conn.timer.delayed_ack.is_expired()? {
            conn.send_flag.ack_now = true;
            if let Err(e) = self.send_handler(conn) {
                log::warn!(
                    "[{}] Failed to delayed ack. Err: {:?}",
                    conn.print_log_prefix(socket_id),
                    e
                );
            } else {
                log::debug!(
                    "[{}] Delayed Ack Completed.",
                    conn.print_log_prefix(socket_id)
                );
            }
            conn.timer.delayed_ack.init();
        }
        Ok(())
    }

    pub fn timer_handler_timewait(
        &self,
        socket_id: usize,
        conns: &mut MutexGuard<HashMap<usize, Option<TcpConnection>>>,
    ) -> Result<()> {
        if let Some(Some(conn)) = conns.get_mut(&socket_id) {
            if self.timer_handler_2msl(socket_id, conn)? {
                conns.remove(&socket_id);
            }
        } else {
            anyhow::bail!("Cannot find socket (id={}).", socket_id);
        }
        Ok(())
    }

    fn timer_handler_2msl(&self, socket_id: usize, conn: &mut TcpConnection) -> Result<bool> {
        if !conn.timer.two_msl.timer_param.active {
            return Ok(false);
        };
        if conn.timer.two_msl.is_expired()? {
            conn.status = TcpStatus::Closed;
            conn.timer.two_msl.init();
            log::debug!(
                "[{}] 2MSL timer closed a TIMEWAIT socket.",
                conn.print_log_prefix(socket_id)
            );
            return Ok(true);
        }
        Ok(false)
    }
}

pub fn update_retransmission_param(conn: &mut TcpConnection, rtt: usize) -> Result<()> {
    let timer_param = &mut conn.timer.retransmission.timer_param;
    // (2.3) When a subsequent RTT measurement R' is made, a host MUST set rfc6298
    if timer_param.rtt_smoothed != 0 && timer_param.rexmt_shift <= TCP_RTT_INVALIDATE {
        // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| rfc6298
        timer_param.rtt_variance = timer_param.rtt_variance
            - (timer_param.rtt_variance >> TCP_REXMT_MEAN_SHIFT)
            + ((rtt << TCP_SRTT_SHIFT).abs_diff(timer_param.rtt_smoothed)
                >> (TCP_SRTT_SHIFT - TCP_RTTVAR_SHIFT + TCP_REXMT_MEAN_SHIFT));
        // SRTT <- (1 - alpha) * SRTT + alpha * R' rfc6298
        timer_param.rtt_smoothed = (rtt << (TCP_SRTT_SHIFT - TCP_REXMT_GAIN_SHIFT))
            + timer_param.rtt_smoothed
            - (timer_param.rtt_smoothed >> TCP_REXMT_GAIN_SHIFT);
    // (2.2) When the first RTT measurement R is made, the host MUST set rfc6298
    } else {
        timer_param.rtt_smoothed = rtt << TCP_SRTT_SHIFT;
        timer_param.rtt_variance = (rtt / 2) << TCP_RTTVAR_SHIFT;
    }
    timer_param.rtt = rtt;
    timer_param.rexmt_shift = 0;
    timer_param.active = false;
    conn.timer.retransmission.set_delta(false);
    Ok(())
}

#[derive(Debug)]
pub enum TcpTimerType {
    Retransmission,
    DelayedAck,
    TwoMSL,
}

#[derive(Debug, Default)]
pub struct RetransmissionVariables {
    pub active: bool,
    pub rexmt_shift: usize,
    pub rtt: usize,          // msec
    pub rtt_smoothed: usize, // msec
    pub rtt_variance: usize, // msec
    pub delta: usize,        // msec
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
    pub timer_count: Instant,
}

impl RetransmissionTimer {
    pub fn new() -> Self {
        Self {
            timer_type: TcpTimerType::Retransmission,
            timer_param: RetransmissionVariables::new(),
            timer_count: Instant::now(),
        }
    }

    pub fn init(&mut self) {
        self.timer_param.active = false;
        self.timer_param.rexmt_shift = 0;
        self.timer_param.rtt = 0;
        self.timer_param.rtt_smoothed = 0;
        self.timer_param.rtt_variance = TCP_REXMT_RTTVAR_INIT;
    }

    pub fn fire_syn(&mut self) {
        self.timer_param.active = true;
        self.timer_param.rexmt_shift = 0;
        self.next_syn();
        log::debug!(
            "Retransmission timer for a SYN packet is fired. MAX={} initial delta={}",
            TCP_MAXRXTSHIFT,
            self.timer_param.delta
        );
    }

    pub fn next_syn(&mut self) {
        self.timer_count = Instant::now();
        self.timer_param.rexmt_shift += 1;
        self.set_delta(true);
    }

    pub fn fire_datagram(&mut self) {
        self.timer_param.active = true;
        self.next_datagram();
        log::debug!(
            "Retransmission timer for a Datagram packet is fired. MAX={} shift={} initial delta={}",
            TCP_MAXRXTSHIFT,
            self.timer_param.rexmt_shift,
            self.timer_param.delta
        );
    }

    pub fn next_datagram(&mut self) {
        self.timer_count = Instant::now();
        self.timer_param.rexmt_shift += 1;
        self.set_delta(false);
    }

    pub fn set_delta(&mut self, syn: bool) {
        let shift = self.timer_param.rexmt_shift;
        if syn {
            let calc_delta = TCP_REXMT_INIT * TCP_BACKOFF[shift];
            self.timer_param.delta = adjust_delta(calc_delta);
        } else {
            let calc_delta = ((self.timer_param.rtt_smoothed >> TCP_SRTT_SHIFT)
                + (self.timer_param.rtt_variance >> TCP_RTTVAR_SHIFT) * 4)
                * TCP_BACKOFF[shift];
            self.timer_param.delta = adjust_delta(calc_delta);
        }
    }

    pub fn is_expired(&mut self) -> Result<bool> {
        let current = self.timer_param.rexmt_shift;
        anyhow::ensure!(
            current != 0 && current <= TCP_MAXRXTSHIFT,
            "Retransmission counter is {} should be 1~{}.",
            current,
            TCP_MAXRXTSHIFT
        );
        if self.timer_count.elapsed() > Duration::from_millis(self.timer_param.delta as u64) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn is_finished(&mut self) -> bool {
        if self.timer_param.rexmt_shift >= TCP_MAXRXTSHIFT + 1 {
            true
        } else {
            false
        }
    }
}

fn adjust_delta(calc_delta: usize) -> usize {
    if calc_delta + TCP_REXMT_SLOP <= TCP_REXMT_MIN {
        TCP_REXMT_MIN
    } else if calc_delta + TCP_REXMT_SLOP >= TCP_REXMT_MAX {
        TCP_REXMT_MAX
    } else {
        calc_delta + TCP_REXMT_SLOP
    }
}

#[derive(Debug, Default)]
pub struct DelayedAckVariables {
    pub active: bool,
}

impl DelayedAckVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct DelayedAckTimer {
    pub timer_type: TcpTimerType,
    pub timer_param: DelayedAckVariables,
    pub timer_count: Instant,
}

impl DelayedAckTimer {
    pub fn new() -> Self {
        Self {
            timer_type: TcpTimerType::DelayedAck,
            timer_param: DelayedAckVariables::new(),
            timer_count: Instant::now(),
        }
    }

    pub fn init(&mut self) {
        self.timer_param.active = false;
    }

    pub fn fire(&mut self) {
        self.timer_param.active = true;
        self.timer_count = Instant::now();
        log::debug!("Delayed ack timer is fired. interval={}", TCP_DELAY_ACK);
    }

    pub fn is_expired(&self) -> Result<bool> {
        if self.timer_count.elapsed() > Duration::from_millis(TCP_DELAY_ACK as u64) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Default)]
pub struct TwoMSLVariables {
    pub active: bool,
}

impl TwoMSLVariables {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct TwoMSLTimer {
    pub timer_type: TcpTimerType,
    pub timer_param: TwoMSLVariables,
    pub timer_count: Instant,
}

impl TwoMSLTimer {
    pub fn new() -> Self {
        Self {
            timer_type: TcpTimerType::TwoMSL,
            timer_param: TwoMSLVariables::new(),
            timer_count: Instant::now(),
        }
    }

    pub fn init(&mut self) {
        self.timer_param.active = false;
    }

    pub fn fire(&mut self) {
        self.timer_param.active = true;
        self.timer_count = Instant::now();
        log::debug!("2MSL timer is fired. interval={}", TCP_2MSL);
    }

    pub fn is_expired(&self) -> Result<bool> {
        if self.timer_count.elapsed() > Duration::from_millis(TCP_2MSL as u64) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug)]
pub struct TcpTimer {
    pub retransmission: RetransmissionTimer,
    pub delayed_ack: DelayedAckTimer,
    pub two_msl: TwoMSLTimer,
}

impl TcpTimer {
    pub fn new() -> Self {
        Self {
            retransmission: RetransmissionTimer::new(),
            delayed_ack: DelayedAckTimer::new(),
            two_msl: TwoMSLTimer::new(),
        }
    }
}
