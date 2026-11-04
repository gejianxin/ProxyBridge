//! Shared ProxyBridge engine: configuration, rule matching, and proxy handshakes.
//!
//! The original Windows, Linux, and macOS implementations are copyright
//! Anof-cyber/InterceptSuite and released under the MIT License. This crate is the
//! Rust port of that design and stays under the same license.

mod config;
mod decision;
mod error;
mod http_connect;
mod relay;
mod rules;
mod socks5;

pub use config::{
    overrides_from_env, overrides_from_pairs, parse_proxy_spec, Config, Overrides, ProxyEndpoint,
    ProxyKind, DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, DEFAULT_PROXY_TYPE,
};
pub use decision::{Decision, DecisionAction, Flow, Transport};
pub use error::{Error, Result};
pub use http_connect::http_connect;
pub use relay::splice_tcp;
pub use rules::{glob_match, RuleAction, RuleProtocol};
pub use socks5::{
    client_handshake, encode_udp, parse_udp, server_negotiate, server_read_request,
    server_write_reply, Socks5Udp, SocksAddr, SocksTarget, UdpHeader, CMD_CONNECT,
    CMD_UDP_ASSOCIATE, REP_HOST_UNREACHABLE, REP_NOT_ALLOWED, REP_OK, REP_REFUSED,
};

/// Packet mark applied to sockets opened by the Linux redirect backend.
/// iptables excludes this mark so ProxyBridge's own connections are not diverted again.
pub const LINUX_FW_MARK: i32 = 1;
