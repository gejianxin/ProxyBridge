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
            detail: "Userspace SOCKS5 inbound. Rules run in this process and matching TCP is tunneled with SOCKS5 or HTTP CONNECT. UDP ASSOCIATE is relayed for SOCKS5 upstreams and for direct destinations. Linux can attribute the client process from /proc; Windows and macOS process match is not implemented, so only process='*' rules match there.",
        },
        BackendStatus {
            id: "redirect",
            targets: "linux x64, linux arm64",
            state: if cfg!(target_os = "linux") {
                "implemented"
            } else {
                "linux-only"
            },
            detail: "Transparent TCP via iptables NAT REDIRECT and SO_ORIGINAL_DST. Outbound sockets are marked so they are not redirected again. Transparent UDP, cgroup/eBPF process identity, and DNS snooping from the C port are not in this backend.",
        },
        BackendStatus {
            id: "windivert",
            targets: "windows x64",
            state: "stub",
            detail: "The C port's WinDivert driver is not linked. proxybridge start_windivert returns an error. Use --mode socks on Windows until a driver-backed capture loop is added.",
        },
        BackendStatus {
            id: "network-extension",
            targets: "macOS x64 (Intel), macOS arm64 (Apple Silicon)",
            state: "stub",
            detail: "Apple's Network Extension transparent proxy is not part of this Rust build. Both Mac architectures can compile and run --mode socks. A signed system extension remains future work; it cannot be honestly shipped from a Linux cross-check.",
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
    fn unfinished_kernel_backends_are_labeled_stubs() {
        let text = backend_lines();
        assert!(text.contains("windivert"));
        assert!(text.contains("stub"));
        assert!(text.contains("network-extension"));
        assert!(text.contains("socks"));
        assert!(text.contains("implemented"));
    }
}
