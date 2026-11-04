//! macOS-specific notes live with the extension sources.
//!
//! Process lookup is `macos_proc` (compiled only for the Apple targets).
//! The flow helper that a Network Extension connects to is [`crate::ExtensionBridge`].

/// Default port of `--mode extension` when `--listen` is omitted.
pub const EXTENSION_HELPER_PORT: u16 = 34080;
