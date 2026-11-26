//! Extra hosts to try at peers' UDP ports, for direct paths through NATs that hide a peer's own
//! address from us.
//!
//! The case it's for: a node in a VM behind QEMU's user networking ("slirp"), whose host runs
//! another tailnet node. The host advertises its LAN and public addresses, which the VM can't
//! reach (WSL2's mirrored networking, for one, doesn't let a guest reach its host by the host's
//! LAN address), but the VM reaches the host as `10.0.2.2` — QEMU's alias for the host's
//! loopback. With `10.0.2.2` set here, every disco ping to a peer's IPv4 endpoint `a:port` also
//! goes to `10.0.2.2:port`; if the host's node answers, that's a direct path. Peers that aren't
//! on the host simply don't answer there.
//!
//! Process-wide and empty by default (nothing changes unless an embedder sets it).

use std::{
    net::{IpAddr, SocketAddr},
    sync::RwLock,
};

static HOSTS: RwLock<Vec<IpAddr>> = RwLock::new(Vec::new());

/// Sets the extra hosts (IPv4 only are used). See the module docs.
pub fn set_extra_candidate_hosts(hosts: Vec<IpAddr>) {
    *HOSTS.write().unwrap_or_else(|e| e.into_inner()) = hosts;
}

/// `addr` at each extra host (IPv4 endpoints only; not `addr` itself).
pub(crate) fn aliases(addr: SocketAddr) -> Vec<SocketAddr> {
    if !addr.is_ipv4() {
        return Vec::new();
    }
    HOSTS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|h| h.is_ipv4() && **h != addr.ip())
        .map(|h| SocketAddr::new(*h, addr.port()))
        .collect()
}
