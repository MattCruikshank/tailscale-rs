use bytes::Bytes;
use smoltcp::{iface::SocketHandle, socket::tcp};

use crate::netcore::{
    Netstack,
    command::{
        Error, Response,
        tcp::stream::{Command as TcpStreamCommand, Response as TcpStreamResponse},
    },
};


/// How long a closed connection stays in TIME-WAIT here: just long enough for our final ACK
/// (smoltcp delays ACKs up to 10 ms) to go out, instead of TCP's usual ~10 s (smoltcp) or 60 s.
///
/// METAL ISSUE-00049/ISSUE-00057: a server closing a few hundred connections a second held
/// thousands of TIME-WAIT sockets, and a client's new connection reusing a port found the old one
/// instead of the listener — its SYN went unanswered until TIME-WAIT ended (1, 3, 7, 15 s
/// stalls); every wake-up also walked all of them. Dropping a socket the moment it enters
/// TIME-WAIT loses that delayed ACK (the client then waits in LAST-ACK, and a new connection on
/// its port lands on the old socket). The cost of a short TIME-WAIT: an old duplicate segment
/// could reach a new connection on the same ports (unlikely on a tailnet, where WireGuard
/// authenticates every packet), and a FIN retransmitted after our ACK was lost gets a reset.
pub(crate) const TIME_WAIT_GRACE: smoltcp::time::Duration = smoltcp::time::Duration::from_millis(100);

/// How long a closed socket may wait in FIN-WAIT-2 for its peer's FIN (like Linux's
/// `tcp_fin_timeout` for orphaned sockets; smoltcp has no limit). All our data and our FIN have
/// been acknowledged, so removing it loses nothing; without a limit a peer whose FIN never
/// comes keeps the socket — and its port — forever, and a new connection from that port meets
/// it instead of the listener (METAL ISSUE-00056). The other closing states still have our data
/// or FIN in flight and aren't limited (a slow reader's response isn't cut short).
pub(crate) const FIN_WAIT_2_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(15);

/// The time limit for a closing socket's state, if any.
fn closing_limit(state: tcp::State) -> Option<smoltcp::time::Duration> {
    match state {
        tcp::State::TimeWait => Some(TIME_WAIT_GRACE),
        tcp::State::FinWait2 => Some(FIN_WAIT_2_TIMEOUT),
        _ => None,
    }
}

impl Netstack {
    /// Process a TCP stream command.
    #[tracing::instrument(skip_all, fields(?cmd, ?handle), level = "debug")]
    pub(crate) fn process_tcp_stream(
        &mut self,
        cmd: TcpStreamCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        match cmd {
            TcpStreamCommand::Connect {
                remote_endpoint,
                local_endpoint,
            } => {
                if remote_endpoint.is_ipv4() != local_endpoint.is_ipv4() {
                    return Response::Error(Error::wrong_ip_version());
                }

                // Only occurs if we're polling a `WouldBlock`.
                if let Some(handle) = handle {
                    return self.check_conn(
                        handle,
                        TcpStreamCommand::Connect {
                            local_endpoint,
                            remote_endpoint,
                        },
                    );
                }

                let mut sock = tcp::Socket::new(self.tcp_buffer(), self.tcp_buffer());

                if let Err(e) = sock.connect(self.iface.context(), remote_endpoint, local_endpoint)
                {
                    tracing::error!(error = %e, "tcp connect");
                    return Response::Error(e.into());
                }

                let handle = self.socket_set.add(sock);

                Response::WouldBlock {
                    handle: Some(handle),
                    command: TcpStreamCommand::Connect {
                        local_endpoint,
                        remote_endpoint,
                    }
                    .into(),
                }
            }

            TcpStreamCommand::Send { buf } => {
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

                match sock.send_slice(&buf) {
                    Ok(0) => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Send { buf }.into(),
                    },
                    Ok(n) => TcpStreamResponse::Sent { n }.into(),
                    Err(tcp::SendError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for send");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Recv { max_len } => {
                let handle = handle.unwrap();
                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

                match sock.recv(|buf| {
                    let mut len = buf.len();

                    if let Some(max_len) = max_len {
                        len = len.min(max_len);
                    }

                    (len, Bytes::copy_from_slice(&buf[..len]))
                }) {
                    Ok(buf) if buf.is_empty() => Response::WouldBlock {
                        handle: Some(handle),
                        command: TcpStreamCommand::Recv { max_len }.into(),
                    },
                    Ok(buf) => TcpStreamResponse::Recv { buf }.into(),
                    Err(tcp::RecvError::Finished) => TcpStreamResponse::Finished.into(),
                    Err(tcp::RecvError::InvalidState) => {
                        tracing::error!(state = %sock.state(), "invalid socket state for recv");
                        Response::Error(Error::invalid_socket_state())
                    }
                }
            }

            TcpStreamCommand::Close => {
                let handle = handle.unwrap();

                let sock = self.socket_set.get_mut::<tcp::Socket>(handle);
                sock.close();

                self.pending_tcp_closes.push(handle);

                Response::Ok
            }
        }
    }

    /// Drop all TCP sockets that have finished closing — and those that stayed in TIME-WAIT
    /// ([`TIME_WAIT_GRACE`]) or FIN-WAIT-2 ([`FIN_WAIT_2_TIMEOUT`]) too long.
    #[tracing::instrument(skip_all)]
    pub(crate) fn drain_tcp_closes(&mut self) {
        let Self { pending_tcp_closes, socket_set, closing_since, now, .. } = self;
        let now = *now;
        pending_tcp_closes.retain(|&handle| {
            let state = socket_set.get::<tcp::Socket>(handle).state();
            let should_remove = match closing_limit(state) {
                _ if state == tcp::State::Closed => true,
                Some(limit) => {
                    // Since when in this state (a new state restarts the clock).
                    let entry = closing_since.entry(handle).or_insert((state, now));
                    if entry.0 != state {
                        *entry = (state, now);
                    }
                    let expired = now - entry.1 >= limit;
                    if expired && state == tcp::State::FinWait2 {
                        tracing::debug!(?handle, "FIN-WAIT-2 timed out: the peer never closed");
                    }
                    expired
                }
                None => {
                    closing_since.remove(&handle);
                    false
                }
            };
            if should_remove {
                socket_set.remove(handle);
                closing_since.remove(&handle);
            }

            !should_remove
        });
    }

    /// When the next time-limited closing socket is due (so the run loop wakes up to remove it).
    pub(crate) fn next_closing_removal(&self) -> Option<smoltcp::time::Instant> {
        self.closing_since
            .values()
            .filter_map(|&(state, since)| closing_limit(state).map(|limit| since + limit))
            .min()
    }

    fn check_conn(&mut self, handle: SocketHandle, orig_cmd: TcpStreamCommand) -> Response {
        let sock = self.socket_set.get_mut::<tcp::Socket>(handle);

        match sock.state() {
            tcp::State::Established => {
                tracing::trace!("connection succeeded");
                TcpStreamResponse::Connected { handle }.into()
            }

            tcp::State::SynReceived | tcp::State::SynSent => Response::WouldBlock {
                handle: Some(handle),
                command: orig_cmd.into(),
            },

            _ => {
                tracing::warn!("connecting socket was reset or closed");
                self.pending_tcp_closes.push(handle);
                Response::Error(Error::ConnectionReset)
            }
        }
    }
}
