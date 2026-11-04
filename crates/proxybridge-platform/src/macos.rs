use crate::bridge::BridgeError;

/// The Swift port uses a Network Extension transparent proxy (`NEAppProxyProvider`).
/// That extension needs Apple entitlements and a signed system extension, so it
/// is not reimplemented here. macOS x64 and Apple Silicon can still run the
/// userspace SOCKS backend, which is ordinary Rust and does not need the extension.
pub async fn start_network_extension() -> Result<(), BridgeError> {
    Err(BridgeError::Unavailable(
        "macOS Network Extension transparent proxy is not implemented in this Rust build. --mode socks is the supported path on Intel and Apple Silicon; the system extension remains a stub.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn network_extension_reports_that_it_is_a_stub() {
        let err = start_network_extension().await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Network Extension"));
        assert!(text.contains("stub"));
    }
}
