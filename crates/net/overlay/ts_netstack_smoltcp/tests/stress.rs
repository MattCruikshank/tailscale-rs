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
//! retransmission paths run too. With loss, an exchange may take up to 5 s (several
//! retransmissions); without, 1 s.

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

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A tiny deterministic PRNG (xorshift64*), so a failing run can be repeated.
struct Rng(u64);

impl Rng {
    fn percent(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % 100
    }
}

/// The relay: drop `loss` percent of packets, deliver the rest after `delay`.
fn forward(pkt: bytes::Bytes, to: &WakingPipeSender, rng: &mut Rng, loss: u64, delay: Duration) {
    if rng.percent() < loss {
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
    let secs = env("NETSTACK_STRESS_SECS", 10);
    let clients = env("NETSTACK_STRESS_CLIENTS", 32);

    let loss = env("NETSTACK_STRESS_LOSS", 0);
    let delay = Duration::from_millis(env("NETSTACK_STRESS_DELAY_MS", 0));
    let slow = if loss > 0 { Duration::from_secs(5) } else { SLOW };
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
                forward(pkt, &b_tx, &mut rng, loss, delay);
            }
        });
        tokio::spawn(async move {
            let mut rng = Rng(0xd1b5_4a32_d192_ed03);
            while let Some(pkt) = b_rx.recv_async().await {
                forward(pkt, &a_tx, &mut rng, loss, delay);
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
    let exchanges = Arc::new(AtomicU64::new(0));
    let slowest_ms = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for _ in 0..clients {
        let (ch, next_port, exchanges, slowest_ms, client_errors) =
            (client_ch.clone(), next_port.clone(), exchanges.clone(), slowest_ms.clone(), client_errors.clone());
        tasks.push(tokio::spawn(async move {
            while Instant::now() < end {
                let port = 20000 + next_port.fetch_add(1, Ordering::Relaxed) % 40000;
                let local = SocketAddr::new(client_ip, port);
                let started = Instant::now();
                let exchange = async {
                    let sock = ch.tcp_connect(local, server_ep).await.map_err(|e| format!("connect: {e:?}"))?;
                    send_all(&sock, &[b'q'; REQUEST]).await?;
                    recv_exact(&sock, RESPONSE).await
                };
                match tokio::time::timeout(Duration::from_secs(20), exchange).await {
                    Err(_) => panic!("an exchange (local port {port}) didn't finish within 20 s"),
                    Ok(Err(e)) => {
                        *client_errors.lock().unwrap().entry(e).or_insert(0) += 1;
                        continue;
                    }
                    Ok(Ok(())) => {}
                }
                let took = started.elapsed();
                slowest_ms.fetch_max(took.as_millis() as u64, Ordering::Relaxed);
                exchanges.fetch_add(1, Ordering::Relaxed);
                assert!(took < slow, "an exchange (local port {port}) took {took:?}");
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let n = exchanges.load(Ordering::Relaxed);
    eprintln!(
        "stress: {n} exchanges in {secs} s ({:.0}/s), slowest {} ms; client errors {:?}; server errors {:?}",
        n as f64 / secs as f64,
        slowest_ms.load(Ordering::Relaxed),
        client_errors.lock().unwrap(),
        server_errors.lock().unwrap()
    );
    assert!(n > 0);
}
