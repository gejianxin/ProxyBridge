/// One row in `proxybridge backends`.
#[derive(Debug, Clone, Copy)]
pub struct BackendStatus {
    pub id: &'static str,
    pub targets: &'static str,
    pub state: &'static str,
    pub detail: &'static str,
}

pub fn backends() -> Vec<BackendStatus> {
    vec![
        BackendStatus {
            id: "socks",
            targets: "linux x64, linux arm64, windows x64, macOS x64, macOS arm64",
            state: "implemented",
            detail: "Userspace SOCKS5 inbound. TCP uses SOCKS5 or HTTP CONNECT. UDP ASSOCIATE is relayed for SOCKS5 upstreams and direct destinations. Process match uses /proc on Linux, the IP helper tables on Windows, and libproc on macOS.",
        },
        BackendStatus {
            id: "redirect",
            targets: "linux x64, linux arm64",
            state: if cfg!(target_os = "linux") {
                "implemented"
            } else {
                "linux-only"
            },
            detail: "Transparent TCP via iptables REDIRECT and SO_ORIGINAL_DST, plus UDP via IP_RECVORIGDSTADDR. DNS replies that this process forwards are remembered for domain rules. Outbound sockets are marked. IPv6 transparent UDP replies are not spoofed.",
        },
        BackendStatus {
            id: "windivert",
            targets: "windows x64",
            state: "driver-required",
            detail: "IPv4 TCP and UDP are rewritten toward a local listener (WinDivert 2.2 ABI). WinDivert.dll and WinDivert64.sys are not bundled; --mode windivert fails with a clear error until they are installed beside the exe and the process is elevated. A Windows host still has to confirm the driver.",
        },
        BackendStatus {
            id: "network-extension",
            targets: "macOS x64 (Intel), macOS arm64 (Apple Silicon)",
            state: "signing-required",
            detail: "The Rust helper (--mode extension) accepts flows from NEAppProxyProvider. The Swift provider, Info.plist, and entitlements are in macos/NetworkExtension. Apple must sign that extension; this build does not notarize it. Both Mac architectures compile the helper and the libproc lookup.",
        },
    ]
}

pub fn backend_lines() -> String {
    let mut out = String::new();
    for backend in backends() {
        out.push_str(&format!(
            "{}\t{}\t{}\n    {}\n",
            backend.id, backend.state, backend.targets, backend.detail
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_backends_name_what_a_host_still_has_to_provide() {
        let text = backend_lines();
        assert!(text.contains("windivert"));
        assert!(text.contains("driver-required"));
        assert!(text.contains("WinDivert.dll"));
        assert!(text.contains("network-extension"));
        assert!(text.contains("signing-required"));
        assert!(text.contains("socks"));
        assert!(text.contains("implemented"));
        assert!(text.contains("IP_RECVORIGDSTADDR"));
    }
}
