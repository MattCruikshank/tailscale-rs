//! Cheap timing of the data path, cheap enough to leave on: counters at the hand-offs, a
//! warning for slow steps and long lock waits, and a [`watchdog`] that notices when one hand-off
//! goes quiet while the others keep moving.
//!
//! Written to find tunnel-wide stalls of a few seconds under load (METAL ISSUE-00049): in a
//! real stall, *something* keeps moving — TCP retransmissions going out, or the peer's packets
//! still arriving — so a counter that stops while another one moves says where packets stop.
//! An ordinary pause in traffic stops everything and isn't reported.

use core::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// UDP datagrams read from the underlay sockets (direct paths).
pub static UDP_RX: AtomicU64 = AtomicU64::new(0);
/// UDP datagrams written to the underlay sockets (direct paths).
pub static UDP_TX: AtomicU64 = AtomicU64::new(0);
/// Packets the data plane took from the underlay transports.
pub static UNDERLAY_IN: AtomicU64 = AtomicU64::new(0);
/// Packets the data plane handed to the underlay transports.
pub static UNDERLAY_OUT: AtomicU64 = AtomicU64::new(0);
/// Packets the data plane took from the overlay (the local network stack).
pub static OVERLAY_IN: AtomicU64 = AtomicU64::new(0);
/// Packets the data plane handed to the overlay.
pub static OVERLAY_OUT: AtomicU64 = AtomicU64::new(0);

const COUNTERS: [(&str, &AtomicU64); 6] = [
    ("udp rx", &UDP_RX),
    ("udp tx", &UDP_TX),
    ("data plane in from the underlay", &UNDERLAY_IN),
    ("data plane out to the underlay", &UNDERLAY_OUT),
    ("data plane in from the overlay", &OVERLAY_IN),
    ("data plane out to the overlay", &OVERLAY_OUT),
];

/// A step, lock wait or lock hold longer than this is reported.
pub const SLOW: Duration = Duration::from_millis(200);

/// Counts `n` packets at a hand-off.
#[inline]
pub fn count(counter: &AtomicU64, n: usize) {
    counter.fetch_add(n as u64, Ordering::Relaxed);
}

/// Reports `what` if it took longer than [`SLOW`].
#[inline]
pub fn report_slow(what: &str, took: Duration) {
    if took > SLOW {
        tracing::warn!("data path: {what} took {took:.0?}");
    }
}

/// Watchdog tick.
const TICK: Duration = Duration::from_millis(250);
/// A counter quiet this long (while another moves) is reported.
const QUIET: Duration = Duration::from_secs(1);
/// ... if it had moved at least this many packets in the 2 s before it went quiet.
const BUSY_PACKETS: u64 = 20;
/// Ticks of history kept (2 s).
const HISTORY: usize = 8;

/// Watches the counters forever (spawn it once). Every 250 ms: a counter that moved at least
/// 20 packets in the 2 s before it went quiet, has been quiet for over 1 s, while another
/// counter moved in the last tick, is reported once — and again when it resumes, with how long
/// it was quiet. A late tick (the runtime didn't run it for over 500 ms) is reported too.
pub async fn watchdog() -> core::convert::Infallible {
    let snapshot = || COUNTERS.map(|(_, c)| c.load(Ordering::Relaxed));
    let mut history = std::collections::VecDeque::from([snapshot()]);
    let mut last_change = [Instant::now(); 6];
    let mut busy_before = [0u64; 6];
    let mut reported = [false; 6];
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_tick = Instant::now();
    loop {
        interval.tick().await;
        let now = Instant::now();
        let late = now.duration_since(last_tick).saturating_sub(TICK);
        last_tick = now;
        if late > Duration::from_millis(500) {
            tracing::warn!(
                "data path: watchdog ran {late:.0?} late (the runtime didn't get to it)"
            );
        }
        let current = snapshot();
        let previous = *history.back().unwrap_or(&current);
        let oldest = *history.front().unwrap_or(&current);
        for i in 0..COUNTERS.len() {
            if current[i] != previous[i] {
                if reported[i] {
                    tracing::warn!(
                        "data path: {} resumed after {:.1?} quiet",
                        COUNTERS[i].0,
                        now.duration_since(last_change[i])
                    );
                    reported[i] = false;
                }
                last_change[i] = now;
                busy_before[i] = current[i] - oldest[i];
            }
        }
        let moving: Vec<&str> = (0..COUNTERS.len())
            .filter(|&i| current[i] != previous[i])
            .map(|i| COUNTERS[i].0)
            .collect();
        for i in 0..COUNTERS.len() {
            let quiet = now.duration_since(last_change[i]);
            if !reported[i] && quiet > QUIET && busy_before[i] >= BUSY_PACKETS && !moving.is_empty()
            {
                tracing::warn!(
                    "data path: no packets {} for {quiet:.1?} (after {} in the 2 s before) while {} kept moving",
                    COUNTERS[i].0,
                    busy_before[i],
                    moving.join(", ")
                );
                reported[i] = true;
            }
        }
        history.push_back(current);
        if history.len() > HISTORY {
            history.pop_front();
        }
    }
}
