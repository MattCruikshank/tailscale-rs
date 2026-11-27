/// Netstack configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// Capacity of the command channel.
    ///
    /// If `None` (the default), the channel is unbounded. With a bound, fire-and-forget commands
    /// (a dropped socket's close) are **lost** when it's full — the socket is never closed and
    /// its peer waits for a FIN forever — so only bound it if nothing is dropped under load.
    /// Unbounded is safe: every other command's caller awaits its reply, so the queue holds at
    /// most about one command per waiting task.
    pub command_channel_capacity: Option<usize>,

    /// Maximum transmission unit of the underlying net device.
    pub mtu: usize,

    /// Assign the IPv4 and IPv6 loopback addresses to the interface.
    pub loopback: bool,

    /// The default size of buffer allocated for each UDP socket created.
    pub udp_buffer_size: usize,
    /// The default number of pending messages supported for each UDP socket created.
    pub udp_message_count: usize,

    /// The default size of buffer allocated for each TCP socket created.
    pub tcp_buffer_size: usize,

    /// The default size of buffer allocated for each raw socket.
    pub raw_buffer_size: usize,
    /// The default number of pending messages supported for each raw socket.
    pub raw_message_count: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            command_channel_capacity: None,

            mtu: 1280,

            loopback: false,

            udp_buffer_size: 1024 * 4,
            udp_message_count: 32,

            tcp_buffer_size: 1024 * 16,

            raw_buffer_size: 1024 * 4,
            raw_message_count: 32,
        }
    }
}
