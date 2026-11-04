//! Platform backends for ProxyBridge.
//!
//! `--mode socks` is implemented for every target: it is a userspace SOCKS5
//! listener that applies the shared rule engine and opens a SOCKS5 or HTTP
//! CONNECT tunnel. Linux also has a transparent TCP listener that reads
//! `SO_ORIGINAL_DST` after an iptables `REDIRECT` rule. WinDivert and the
//! macOS Network Extension are explicit stubs.

mod backends;
mod bridge;
mod iptables;
mod local_socks;
mod macos;
mod process;
mod redirect;
mod windows;

#[cfg(target_os = "linux")]
mod linux_net;

pub use backends::{backend_lines, BackendStatus};
pub use bridge::BridgeError;
pub use iptables::iptables_script;
pub use local_socks::LocalSocks;
pub use redirect::RedirectProxy;

pub use macos::start_network_extension;
pub use windows::start_windivert;
