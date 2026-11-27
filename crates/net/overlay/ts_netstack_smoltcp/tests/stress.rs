//! Stress test: many short TCP exchanges between two netstacks over an in-memory pipe, run
//! the way METAL runs its tailnet netstack (`run_tokio` on a multi-threaded runtime). Every
//! exchange must finish within a second: under load in METAL, the netstack sometimes stopped
//! sending anything for up to ~15 s while packets kept arriving (METAL ISSUE-00049), and this
//! is a fast way to look for that without a VM.
//!
//! `NETSTACK_STRESS_SECS` (default 10) sets the duration, `NETSTACK_STRESS_CLIENTS` (default
//! 32) the number of parallel clients, and `NETSTACK_STRESS_LOSS` (percent, default 0) and
//! `NETSTACK_STRESS_DELAY_MS` (default 0) put a lossy, slow link between the stacks — a relay
//! that drops packets at random and delays the rest (which may reorder them), so TCP's
//! retransmission paths run too. With loss, an exchange may take up to 15 s (TCP backs off
//! 1, 2, 4, 8 s when the same packet is lost again); without, 1 s.
//!
//! Clients pick their local port at random from 49152-65535 as Windows does
//! (`NETSTACK_STRESS_PORTS=sequential`: counting up from 20000 instead), so at a few hundred
//! connections a second a new connection can reuse the port of one the server still holds in
//! TIME-WAIT — what METAL's soak does to its tailnet netstack (ISSUE-00049). Like an OS's
//! allocator, it never picks a port its own side may still be using: a live connection, or one
//! that ended less than 30 s ago (the client's socket can sit in LAST-ACK for a few FIN
//! retransmissions when the server's last ACK, or its reset, is lost). That caps the random
//! mode at ~550 connections a second (16,384 ports / 30 s) — more than METAL's soak makes.
//!
//! Slow (over the limit) and stuck (no end within 20 s) exchanges are counted and reported at
//! the end, which then fails. `NETSTACK_STRESS_LOG=1` prints the netstack's own warnings
//! (`RUST_LOG` filter; a debug build — this crate's dev-dependencies compile tracing out of
//! release builds).

use core::{
    net::SocketAddr,
    sync::atomic::{AtomicU16, AtomicU64, Ordering},
    time::Duration,
};
use std::{sync::Arc, time::Instant};

use ts_netstack_smoltcp::{
    Netstack, WakingPipe, WakingPipeDev, WakingPipeSender,
    netcore::{HasChannel, NetstackControl},
    netsock::{CreateSocket, TcpStream},
};

const REQUEST: usize = 200;
const RESPONSE: usize = 4096;
/// An exchange slower than this fails the test.
const SLOW: Duration = Duration::from_secs(1);
/// A client port is reused only this long after its exchange ended.
const PORT_REUSE_AFTER: Duration = Duration::from_secs(30);

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A tiny deterministic PRNG (xorshift64*), so a failing run can be repeated.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn percent(&mut self) -> u64 {
        self.next() % 100
    }
}

/// Per client port, the packets the lossy relay saw for its current connection (printed when
/// an exchange fails): time, direction (`>` client to server, `<` back), TCP flags, sequence and
/// ACK numbers, payload length, and whether the relay dropped it.
fn traces() -> &'static std::sync::Mutex<std::collections::HashMap<u16, Vec<String>>> {
    static T: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u16, Vec<String>>>> = std::sync::OnceLock::new();
    T.get_or_init(Default::default)
}

fn started() -> Instant {
    static S: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *S.get_or_init(Instant::now)
}

/// Records an IPv4/TCP packet in the trace of its client port.
fn trace(pkt: &[u8], to_server: bool, dropped: bool) {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return;
    }
    let ihl = usize::from(pkt[0] & 0xf) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    let Some(tcp) = pkt.get(ihl..) else { return };
    if tcp.len() < 20 {
        return;
    }
    let be16 = |i: usize| u16::from_be_bytes([tcp[i], tcp[i + 1]]);
    let be32 = |i: usize| u32::from_be_bytes([tcp[i], tcp[i + 1], tcp[i + 2], tcp[i + 3]]);
    let (sport, dport) = (be16(0), be16(2));
    let doff = usize::from(tcp[12] >> 4) * 4;
    let len = total.saturating_sub(ihl + doff);
    let f = tcp[13];
    let flags: String = [(0x02, 'S'), (0x10, 'A'), (0x08, 'P'), (0x01, 'F'), (0x04, 'R')]
        .iter()
        .filter(|(bit, _)| f & bit != 0)
        .map(|(_, c)| *c)
        .collect();
    let client_port = if to_server { sport } else { dport };
    let line = format!(
        "{:>7.1} ms {} {flags:<4} seq {} ack {} len {}{}",
        started().elapsed().as_secs_f64() * 1000.0,
        if to_server { '>' } else { '<' },
        be32(4),
        be32(8),
        len,
        if dropped { "  DROPPED" } else { "" }
    );
    let mut t = traces().lock().unwrap();
    let v = t.entry(client_port).or_default();
    if v.len() < 400 {
        v.push(line);
    }
}

/// The relay: drop `loss` percent of packets, deliver the rest after `delay`.
fn forward(pkt: bytes::Bytes, to: &WakingPipeSender, rng: &mut Rng, loss: u64, delay: Duration, to_server: bool) {
    let drop = rng.percent() < loss;
    trace(&pkt, to_server, drop);
    if drop {
        return;
    }
    if delay.is_zero() {
        to.send(&pkt);
    } else {
        let to = to.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            to.send(&pkt);
        });
    }
}

/// Prints the relay's packet trace for `port`'s connection (lossy mode only).
fn print_trace(port: u16) {
    if let Some(lines) = traces().lock().unwrap().get(&port) {
        eprintln!("  packets of port {port} (> to the server, < back):\n    {}", lines.join("\n    "));
    }
}

async fn send_all(sock: &TcpStream, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let n = sock.send(buf).await.map_err(|e| format!("send: {e:?}"))?;
        buf = &buf[n..];
    }
    Ok(())
}

async fn recv_exact(sock: &TcpStream, mut want: usize) -> Result<(), String> {
    let mut buf = [0u8; 2048];
    while want > 0 {
        let n = sock.recv(&mut buf[..want.min(2048)]).await.map_err(|e| format!("recv: {e:?}"))?;
        if n == 0 {
            return Err("closed early".into());
        }
        want -= n;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_short_exchanges_never_stall() {
    if std::env::var("NETSTACK_STRESS_LOG").as_deref() == Ok("1") {
        ts_cli_util::init_tracing();
    }
    let secs = env("NETSTACK_STRESS_SECS", 10);
    let clients = env("NETSTACK_STRESS_CLIENTS", 32);

    let loss = env("NETSTACK_STRESS_LOSS", 0);
    let delay = Duration::from_millis(env("NETSTACK_STRESS_DELAY_MS", 0));
    let slow = if loss > 0 { Duration::from_secs(15) } else { SLOW };
    let dev = |pipe| WakingPipeDev { pipe, mtu: 1280, medium: smoltcp::phy::Medium::Ip };
    let (client_pipe, server_pipe) = if loss == 0 && delay.is_zero() {
        WakingPipe::new(None)
    } else {
        // client <-> (a) relay (b) <-> server
        let (client_pipe, a) = WakingPipe::new(None);
        let (b, server_pipe) = WakingPipe::new(None);
        let WakingPipe { rx: mut a_rx, tx: a_tx } = a;
        let WakingPipe { rx: mut b_rx, tx: b_tx } = b;
        tokio::spawn(async move {
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
            while let Some(pkt) = a_rx.recv_async().await {
                forward(pkt, &b_tx, &mut rng, loss, delay, true);
            }
        });
        tokio::spawn(async move {
            let mut rng = Rng(0xd1b5_4a32_d192_ed03);
            while let Some(pkt) = b_rx.recv_async().await {
                forward(pkt, &a_tx, &mut rng, loss, delay, false);
            }
        });
        (client_pipe, server_pipe)
    };
    let mut client_stack = Netstack::new(dev(client_pipe), Default::default());
    let mut server_stack = Netstack::new(dev(server_pipe), Default::default());
    let (client_ch, server_ch) = (client_stack.command_channel(), server_stack.command_channel());
    tokio::spawn(async move { client_stack.run_tokio().await });
    tokio::spawn(async move { server_stack.run_tokio().await });

    let server_ep: SocketAddr = "100.64.0.1:80".parse().unwrap();
    let client_ip: std::net::IpAddr = "100.64.0.2".parse().unwrap();
    client_ch.set_ips([client_ip]).await.unwrap();
    server_ch.set_ips([server_ep.ip()]).await.unwrap();

    // Errors by kind, on each side (a lossy link can reset connections; a stall is the bug).
    let server_errors = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<String, u64>::new()));
    let client_errors = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<String, u64>::new()));

    // The server: read a request, answer, close.
    let listener = server_ch.tcp_listen(server_ep).await.unwrap();
    let server_errors_in = server_errors.clone();
    tokio::spawn(async move {
        let server_errors = server_errors_in;
        loop {
            let sock = listener.accept().await.expect("accept");
            let server_errors = server_errors.clone();
            tokio::spawn(async move {
                let served = async {
                    recv_exact(&sock, REQUEST).await?;
                    send_all(&sock, &[b'r'; RESPONSE]).await
                };
                if let Err(e) = served.await {
                    *server_errors.lock().unwrap().entry(e).or_insert(0) += 1;
                }
            });
        }
    });

    let next_port = Arc::new(AtomicU16::new(20000));
    // Client ports in use (until the time they're free again), shared by all clients.
    let ports_in_use = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<u16, Instant>::new()));
    let exchanges = Arc::new(AtomicU64::new(0));
    let slowest_ms = Arc::new(AtomicU64::new(0));
    let slow_exchanges = Arc::new(AtomicU64::new(0));
    let stuck_exchanges = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for _ in 0..clients {
        let (ch, next_port, exchanges, slowest_ms, client_errors, ports_in_use, slow_exchanges, stuck_exchanges) = (
            client_ch.clone(),
            next_port.clone(),
            exchanges.clone(),
            slowest_ms.clone(),
            client_errors.clone(),
            ports_in_use.clone(),
            slow_exchanges.clone(),
            stuck_exchanges.clone(),
        );
        tasks.push(tokio::spawn(async move {
            let mut rng = Rng(0x2545_f491_4f6c_dd1d ^ (next_port.fetch_add(7919, Ordering::Relaxed) as u64) << 17);
            let random_ports = std::env::var("NETSTACK_STRESS_PORTS").as_deref() != Ok("sequential");
            while Instant::now() < end {
                // A free port (in use until the exchange ends; updated below). If none is free
                // right now, wait a little outside the lock.
                let port = loop {
                    let picked = {
                        let mut in_use = ports_in_use.lock().unwrap();
                        let now = Instant::now();
                        (0..64)
                            .map(|_| {
                                if random_ports {
                                    49152 + (rng.next() % 16384) as u16
                                } else {
                                    20000 + next_port.fetch_add(1, Ordering::Relaxed) % 40000
                                }
                            })
                            .find(|p| in_use.get(p).is_none_or(|free_at| *free_at <= now))
                            .inspect(|&p| {
                                in_use.insert(p, now + Duration::from_secs(3600));
                            })
                    };
                    match picked {
                        Some(p) => break p,
                        // Out of ports at the end of the run: done.
                        None if Instant::now() >= end => return,
                        None => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                };
                let local = SocketAddr::new(client_ip, port);
                traces().lock().unwrap().remove(&port);
                let started = Instant::now();
                let exchange = async {
                    let sock = ch.tcp_connect(local, server_ep).await.map_err(|e| format!("connect: {e:?}"))?;
                    send_all(&sock, &[b'q'; REQUEST]).await?;
                    recv_exact(&sock, RESPONSE).await
                };
                let finished = tokio::time::timeout(Duration::from_secs(20), exchange).await;
                ports_in_use.lock().unwrap().insert(port, Instant::now() + PORT_REUSE_AFTER);
                match finished {
                    Err(_) => {
                        eprintln!("stress: an exchange (local port {port}) didn't finish within 20 s");
                        print_trace(port);
                        stuck_exchanges.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Ok(Err(e)) => {
                        if client_errors.lock().unwrap().values().sum::<u64>() < 3 {
                            eprintln!("stress: an exchange (local port {port}) failed: {e}");
                            print_trace(port);
                        }
                        *client_errors.lock().unwrap().entry(e).or_insert(0) += 1;
                        continue;
                    }
                    Ok(Ok(())) => {}
                }
                let took = started.elapsed();
                slowest_ms.fetch_max(took.as_millis() as u64, Ordering::Relaxed);
                exchanges.fetch_add(1, Ordering::Relaxed);
                if took >= slow {
                    eprintln!("stress: an exchange (local port {port}) took {took:?}");
                    print_trace(port);
                    slow_exchanges.fetch_add(1, Ordering::Relaxed);
                }
                traces().lock().unwrap().remove(&port);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let n = exchanges.load(Ordering::Relaxed);
    let (slow_n, stuck_n) = (slow_exchanges.load(Ordering::Relaxed), stuck_exchanges.load(Ordering::Relaxed));
    eprintln!(
        "stress: {n} exchanges in {secs} s ({:.0}/s), slowest {} ms, {slow_n} slow, {stuck_n} stuck; client errors {:?}; server errors {:?}",
        n as f64 / secs as f64,
        slowest_ms.load(Ordering::Relaxed),
        client_errors.lock().unwrap(),
        server_errors.lock().unwrap()
    );
    assert!(n > 0);
    assert_eq!((slow_n, stuck_n), (0, 0), "slow or stuck exchanges");
}
