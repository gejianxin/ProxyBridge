//! Best-effort process attribution for an accepted TCP peer.
//!
//! On Linux the peer's ephemeral port is matched against `/proc/net/tcp` and
//! the socket inode is resolved through `/proc/<pid>/fd`. Other operating
//! systems return `None`; rules that name a process then do not match, while
//! `process = "*"` still does.

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: String,
}

pub fn lookup_peer_process(peer: SocketAddr) -> Option<ProcessInfo> {
    dispatch(peer, false)
}

/// Owner of a UDP socket bound to `local` (the source of a datagram).
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub fn lookup_udp_process(local: SocketAddr) -> Option<ProcessInfo> {
    dispatch(local, true)
}

fn dispatch(addr: SocketAddr, udp: bool) -> Option<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        linux_lookup(normalize(addr), udp)
    }
    #[cfg(windows)]
    {
        if udp {
            crate::windows_proc::lookup_udp(addr)
        } else {
            crate::windows_proc::lookup_tcp(addr)
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = udp;
        crate::macos_proc::lookup(addr)
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = (addr, udp);
        None
    }
}

#[cfg(target_os = "linux")]
fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

#[cfg(target_os = "linux")]
fn linux_lookup(peer: SocketAddr, udp: bool) -> Option<ProcessInfo> {
    let inodes = inodes_for(peer, udp);
    if inodes.is_empty() {
        return None;
    }
    if let Some(info) = scan_pid("self", &inodes) {
        return Some(info);
    }
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Some(info) = scan_pid(&name, &inodes) {
            return Some(info);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn inodes_for(peer: SocketAddr, udp: bool) -> Vec<u64> {
    let mut out = Vec::new();
    let (v4, v6) = if udp {
        ("/proc/net/udp", "/proc/net/udp6")
    } else {
        ("/proc/net/tcp", "/proc/net/tcp6")
    };
    match peer.ip() {
        IpAddr::V4(_) => collect_inodes(v4, peer, false, udp, &mut out),
        IpAddr::V6(_) => collect_inodes(v6, peer, true, udp, &mut out),
    }
    out
}

#[cfg(target_os = "linux")]
fn collect_inodes(path: &str, peer: SocketAddr, v6: bool, any_state: bool, out: &mut Vec<u64>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // TCP: established only, so a TIME_WAIT row cannot steal the port.
        // UDP sockets are not in state 01.
        if !any_state && fields[3] != "01" {
            continue;
        }
        let Some(local) = parse_proc_addr(fields[1], v6) else {
            continue;
        };
        if local != peer {
            continue;
        }
        if let Ok(inode) = fields[9].parse::<u64>() {
            out.push(inode);
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_addr(text: &str, v6: bool) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = text.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if v6 {
        if ip_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word = u32::from_str_radix(&ip_hex[i * 8..i * 8 + 8], 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = Ipv4Addr::from(raw.swap_bytes());
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    }
}

#[cfg(target_os = "linux")]
fn scan_pid(pid_name: &str, inodes: &[u64]) -> Option<ProcessInfo> {
    let fd_dir = format!("/proc/{pid_name}/fd");
    let entries = std::fs::read_dir(&fd_dir).ok()?;
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        if !inodes.contains(&inode) {
            continue;
        }
        let pid = if pid_name == "self" {
            std::process::id()
        } else {
            pid_name.parse().unwrap_or(0)
        };
        let exe = std::fs::read_link(format!("/proc/{pid_name}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Some(ProcessInfo { pid, exe });
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    #[test]
    fn proc_hex_decodes_loopback() {
        let addr = parse_proc_addr("0100007F:1F90", false).unwrap();
        assert_eq!(addr, SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8080)));
    }

    #[test]
    fn lookup_finds_this_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let _accepted = listener.accept().unwrap();
        let peer = client.local_addr().unwrap();
        // Keep the descriptor alive until the lookup finishes.
        let _fd = client.as_raw_fd();
        let info = lookup_peer_process(peer).expect("process lookup");
        assert_eq!(info.pid, std::process::id());
        assert!(!info.exe.is_empty());
    }
}
