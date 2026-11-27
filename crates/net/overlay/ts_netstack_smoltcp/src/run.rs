use core::time::Duration;

use tracing::Instrument;

use crate::netcore;

/// Run the netstack in the current thread.
///
/// Expect this function to block forever.
#[tracing::instrument(skip_all, fields(?poll_max_delay))]
pub fn run_blocking(
    netstack: &mut netcore::Netstack,
    dev: &mut impl smoltcp::phy::Device,
    mut now: impl FnMut() -> smoltcp::time::Instant,
    poll_max_delay: Duration,
) {
    loop {
        let now = now();
        let span = tracing::trace_span!("loop", %now, delay = tracing::field::Empty).entered();

        netstack.poll_device_io(now, &mut *dev);

        let delay = netstack
            .poll_delay(now)
            .unwrap_or(Duration::MAX)
            .min(poll_max_delay);

        span.record("delay", tracing::field::debug(delay));

        tracing::trace!("wait");

        match netstack.wait_for_cmd_blocking(Some(delay)) {
            Ok(cmd) => {
                netstack.process_one_cmd(cmd);
                // process any more commands pending in the channel before polling device i/o
                netstack.process_cmds();
            }
            Err(flume::RecvTimeoutError::Timeout) => {
                // no commands received, fall through to poll for i/o
            }
            Err(flume::RecvTimeoutError::Disconnected) => {
                // this can't occur: netstack holds a sender, so the channel can't close until it
                // drops
                unreachable!("internal command channel closed")
            }
        }
    }
}

/// Counted once per iteration of [`run`]'s loop, if set ([`set_loop_counter`]; null: unset).
static LOOP_COUNTER: core::sync::atomic::AtomicPtr<core::sync::atomic::AtomicU64> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Count every iteration of the async run loop in `counter` (for timing the data path from
/// outside: a loop that stops while packets wait means the netstack task isn't running). Only
/// the first call has an effect.
pub fn set_loop_counter(counter: &'static core::sync::atomic::AtomicU64) {
    let _ = LOOP_COUNTER.compare_exchange(
        core::ptr::null_mut(),
        core::ptr::from_ref(counter).cast_mut(),
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Run the netstack indefinitely.
#[tracing::instrument(skip_all)]
pub async fn run(
    netstack: &mut netcore::Netstack,
    dev: &mut (impl netcore::AsyncWakeDevice + smoltcp::phy::Device + Unpin),
    mut now: impl FnMut() -> smoltcp::time::Instant,
    sleep: impl AsyncFn(Duration) + Clone,
) {
    use futures_util::FutureExt;

    // Spinning (METAL ISSUE-00049): the loop runs hundreds of times a second and nothing is
    // sent. Per one-second window: iterations, what woke the loop, the timer smoltcp asked for.
    const SPIN_PER_SECOND: u32 = 200;
    let mut window = SpinWindow::default();
    let mut window_start: Option<smoltcp::time::Instant> = None;
    let mut sent_at_start = crate::pipe::PACKETS_SENT.load(core::sync::atomic::Ordering::Relaxed);
    let mut last_report: Option<smoltcp::time::Instant> = None;

    loop {
        // SAFETY: a non-null pointer came from a `&'static AtomicU64` (`set_loop_counter`).
        if let Some(counter) = unsafe { LOOP_COUNTER.load(core::sync::atomic::Ordering::Acquire).as_ref() } {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        let now = now();

        let delay = netstack.poll_delay(now);
        let start = *window_start.get_or_insert(now);
        if now - start >= smoltcp::time::Duration::from_secs(1) {
            let sent = crate::pipe::PACKETS_SENT.load(core::sync::atomic::Ordering::Relaxed);
            if window.iterations >= SPIN_PER_SECOND
                && sent == sent_at_start
                && last_report.is_none_or(|t| now - t > smoltcp::time::Duration::from_secs(5))
            {
                last_report = Some(now);
                tracing::warn!(
                    "netstack: spinning: {} loop iterations in {} ms, nothing sent; woken by device {}, timer {}, command {}; \
                     timer asked for min {:?} max {:?} (none {}x); {} commands processed, {} blocked; {}",
                    window.iterations,
                    (now - start).total_millis(),
                    window.device,
                    window.timer,
                    window.command,
                    window.min_delay,
                    window.max_delay,
                    window.no_delay,
                    window.commands,
                    netstack.blocked_command_count(),
                    netstack.debug_sockets(now)
                );
            }
            window = SpinWindow::default();
            window_start = Some(now);
            sent_at_start = sent;
        }
        window.iterations += 1;
        match delay {
            Some(d) => {
                window.min_delay = Some(window.min_delay.map_or(d, |m| m.min(d)));
                window.max_delay = Some(window.max_delay.map_or(d, |m| m.max(d)));
            }
            None => window.no_delay += 1,
        }
        let span = tracing::trace_span!("loop", %now, ?delay);
        let cmd_fut = netstack.wait_for_cmd();

        tracing::trace!(parent: &span, "select");

        futures_util::select_biased![
            _ = netstack.wait_io_async(now, dev)
                .instrument(span.clone())
                .fuse() =>
            {
                window.device += 1;
                tracing::trace!(parent: &span, "device wakeup");
            },
            _ = option_timeout(sleep.clone(), delay).instrument(span.clone()).fuse() => {
                window.timer += 1;
                tracing::trace!(parent: &span, "timeout wakeup");
                // Sockets that finished closing on a timer (no packet, so no "progress") are
                // removed now, not when something else happens.
                netstack.drain_tcp_closes();
            },
            cmd = cmd_fut.instrument(span.clone()).fuse() => {
                window.command += 1;
                window.commands += 1;
                span.in_scope(|| {
                    tracing::trace!("command wakeup");

                    if let Some(cmd) = cmd {
                        netstack.process_one_cmd(cmd);
                    } else {
                        // this can't occur: netstack holds a sender for its own channel, so the receive
                        // channel can't close until the netstack itself drops
                        unreachable!("internal command channel closed");
                    }

                    // Process any more commands pending in the channel before polling device i/o
                    netstack.process_cmds();
                });
            }
        ]
    }
}

/// What one second of the run loop looked like (spinning diagnostics).
#[derive(Default)]
struct SpinWindow {
    iterations: u32,
    device: u32,
    timer: u32,
    command: u32,
    commands: u32,
    no_delay: u32,
    min_delay: Option<Duration>,
    max_delay: Option<Duration>,
}

async fn option_timeout(sleep: impl AsyncFn(Duration), dur: Option<Duration>) {
    match dur {
        Some(dur) => sleep(dur).await,
        _ => core::future::pending().await,
    }
}
