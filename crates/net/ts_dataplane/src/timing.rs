//! Cheap timing of the data path, cheap enough to leave on: counters at the hand-offs, a
//! warning for slow steps and long lock waits, and a [`watchdog`] that notices when one hand-off
//! goes quiet while the others keep moving (reported when it resumes).
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
/// A gap shorter than this isn't a stall.
const QUIET_MIN: Duration = Duration::from_secs(1);
/// ... and one longer than this is a pause in traffic, not a stall.
const QUIET_MAX: Duration = Duration::from_secs(30);
/// Busy before the gap: at least this many packets in the 2 s before it (~100/s).
const BUSY_PACKETS: u64 = 200;
/// ... and busy again after it: at least this many packets in the second after it resumed.
const BUSY_AFTER_PACKETS: u64 = 100;
/// Ticks of history kept (2 s).
const HISTORY: usize = 8;

/// Watches the counters forever (spawn it once). Reports a **gap** when a counter resumes: it
/// had moved at least 200 packets in the 2 s before it went quiet, was quiet for 1–30 s, and
/// moved at least 100 in the second after it resumed (a gap *in* busy traffic) —
/// with how many packets every hand-off moved during the gap, which says where packets
/// stopped (all zero: the whole tunnel; one zero among others: that hand-off). Light traffic
/// and pauses aren't reported. A late tick (the runtime didn't run the watchdog for over
/// 500 ms) is reported too.
pub async fn watchdog() -> core::convert::Infallible {
    let snapshot = || COUNTERS.map(|(_, c)| c.load(Ordering::Relaxed));
    let mut history = std::collections::VecDeque::from([snapshot()]);
    let mut last_change = [Instant::now(); 6];
    // Per counter: how busy it was in the 2 s before its last change, and all counters then.
    let mut busy_before = [0u64; 6];
    let mut at_last_change = [snapshot(); 6];
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_tick = Instant::now();
    // Gaps waiting for the second after they ended: (counter, its value then, when, report).
    let mut pending: Vec<(usize, u64, Instant, String)> = Vec::new();
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
            if current[i] == previous[i] {
                continue;
            }
            let quiet = now.duration_since(last_change[i]);
            if quiet > QUIET_MIN && quiet <= QUIET_MAX && busy_before[i] >= BUSY_PACKETS {
                let during: Vec<String> = (0..COUNTERS.len())
                    .filter(|&j| j != i)
                    .map(|j| format!("{} {}", COUNTERS[j].0, previous[j] - at_last_change[i][j]))
                    .collect();
                pending.push((
                    i,
                    previous[i],
                    now,
                    format!(
                        "data path: gap: no packets {} for {quiet:.1?} (after {} in the 2 s before); meanwhile {}",
                        COUNTERS[i].0,
                        busy_before[i],
                        during.join(", ")
                    ),
                ));
            }
            last_change[i] = now;
            busy_before[i] = current[i] - oldest[i];
            at_last_change[i] = current;
        }
        pending.retain(|(i, at, when, report)| {
            if now.duration_since(*when) < Duration::from_secs(1) {
                return true;
            }
            if current[*i] - at >= BUSY_AFTER_PACKETS {
                tracing::warn!("{report}");
            }
            false
        });
        history.push_back(current);
        if history.len() > HISTORY {
            history.pop_front();
        }
    }
}
