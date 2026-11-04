//! Platform backends for ProxyBridge.
//!
//! `--mode socks` is implemented for every target. Linux `redirect` covers TCP
//! and UDP. Windows `windivert` rewrites IPv4 packets when WinDivert.dll is
//! installed. `--mode extension` is the helper a signed macOS Network
//! Extension connects to.

mod backends;
mod bridge;
mod extension;
mod iptables;
mod local_socks;
mod macos;
mod packet;
mod process;
mod redirect;
mod windows;

#[cfg(target_os = "linux")]
mod linux_net;
#[cfg(target_os = "macos")]
mod macos_proc;
#[cfg(target_os = "linux")]
mod udp_redirect;
#[cfg(windows)]
mod windivert_driver;
#[cfg(windows)]
mod windows_proc;

pub use backends::{backend_lines, BackendStatus};
pub use bridge::BridgeError;
pub use extension::{encode_header, ExtensionBridge};
pub use iptables::iptables_script;
pub use local_socks::LocalSocks;
pub use macos::EXTENSION_HELPER_PORT;
pub use redirect::RedirectProxy;
pub use windows::WinDivertProxy;
