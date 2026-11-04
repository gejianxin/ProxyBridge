use crate::bridge::BridgeError;

/// The C implementation captures packets with WinDivert. This build does not
/// link that driver or DLL. The function exists so Windows builds have a real
/// call site that fails clearly instead of a pretend capture loop.
pub async fn start_windivert() -> Result<(), BridgeError> {
    Err(BridgeError::Unavailable(
        "WinDivert packet diversion is not linked in this Rust build. The shared engine and --mode socks run on Windows x64; the kernel driver backend from the C port is still a stub.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn windivert_reports_that_it_is_not_linked() {
        let err = start_windivert().await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("WinDivert"));
        assert!(text.contains("stub"));
    }
}
