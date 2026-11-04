//! IPv4 TCP/UDP rewrite used by the Windows WinDivert backend.
//!
//! The classifier is pure and tested on every OS. Injecting the rewritten
//! packet still needs WinDivert on Windows x64. On other targets nothing in
//! the running binary calls these items; the Windows module does.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Datagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: L4,
    pub syn: bool,
    pub ack: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Source,
    Dest,
}

/// What the capture loop should do with one IPv4 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketAction {
    /// Reinject the original bytes.
    Pass,
    /// Do not reinject. The application sees a timeout.
    Drop,
    /// Reinject `packet`. `loopback` tells WinDivert this now targets the local stack.
    Rewrite { packet: Vec<u8>, loopback: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFlow {
    Direct,
    Block,
    Proxy,
}

/// Client socket → original destination, for packets that were diverted to us.
#[derive(Debug, Default)]
pub struct NatTable {
    by_client: Mutex<HashMap<(Ipv4Addr, u16), SocketAddr>>,
}

impl NatTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, client: SocketAddr, original: SocketAddr) {
        let SocketAddr::V4(client) = client else {
            return;
        };
        self.by_client
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert((*client.ip(), client.port()), original);
    }

    pub fn lookup(&self, client: SocketAddr) -> Option<SocketAddr> {
        let SocketAddr::V4(client) = client else {
            return None;
        };
        self.by_client
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(&(*client.ip(), client.port()))
            .copied()
    }
}

/// WinDivert filter that keeps the upstream proxy itself out of the rewrite.
pub fn windivert_filter(proxy_host: &str, proxy_port: u16) -> String {
    if let Ok(ip) = proxy_host.parse::<Ipv4Addr>() {
        format!(
            "outbound and !loopback and ip and (tcp or udp) and !(ip.DstAddr == {ip} and (tcp.DstPort == {proxy_port} or udp.DstPort == {proxy_port}))"
        )
    } else {
        "outbound and !loopback and ip and (tcp or udp)".into()
    }
}

pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Datagram> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    if frag & 0x1fff != 0 {
        return None;
    }
    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let (protocol, syn, ack, src_port, dst_port) = match proto {
        6 if packet.len() >= ihl + 20 => {
            let flags = packet[ihl + 13];
            (
                L4::Tcp,
                flags & 0x02 != 0,
                flags & 0x10 != 0,
                u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
                u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
            )
        }
        17 if packet.len() >= ihl + 8 => (
            L4::Udp,
            false,
            false,
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        ),
        _ => return None,
    };
    Some(Ipv4Datagram {
        src: SocketAddr::from((src_ip, src_port)),
        dst: SocketAddr::from((dst_ip, dst_port)),
        protocol,
        syn,
        ack,
    })
}

/// Decide how a captured IPv4 packet is rewritten.
///
/// `decide_new` runs only for a TCP SYN or a UDP datagram that is not already
/// in the NAT table. `listen` is the local TCP and UDP port that receives the
/// rewritten flows.
pub fn classify_ipv4(
    packet: &[u8],
    listen: SocketAddr,
    nat: &NatTable,
    decide_new: impl FnOnce(SocketAddr, SocketAddr, L4) -> NewFlow,
) -> PacketAction {
    let Some(flow) = parse_ipv4(packet) else {
        return PacketAction::Pass;
    };
    if flow.src.ip() == listen.ip() && flow.src.port() == listen.port() {
        if let Some(original) = nat.lookup(flow.dst) {
            let mut rewritten = packet.to_vec();
            if rewrite_ipv4(&mut rewritten, End::Source, original) {
                return PacketAction::Rewrite {
                    packet: rewritten,
                    loopback: false,
                };
            }
        }
        return PacketAction::Pass;
    }
    if nat.lookup(flow.src).is_some() {
        let mut rewritten = packet.to_vec();
        if rewrite_ipv4(&mut rewritten, End::Dest, listen) {
            return PacketAction::Rewrite {
                packet: rewritten,
                loopback: true,
            };
        }
        return PacketAction::Pass;
    }
    let start = match flow.protocol {
        L4::Tcp => flow.syn && !flow.ack,
        L4::Udp => true,
    };
    if !start {
        return PacketAction::Pass;
    }
    match decide_new(flow.src, flow.dst, flow.protocol) {
        NewFlow::Direct => PacketAction::Pass,
        NewFlow::Block => PacketAction::Drop,
        NewFlow::Proxy => {
            nat.insert(flow.src, flow.dst);
            let mut rewritten = packet.to_vec();
            if rewrite_ipv4(&mut rewritten, End::Dest, listen) {
                PacketAction::Rewrite {
                    packet: rewritten,
                    loopback: true,
                }
            } else {
                PacketAction::Pass
            }
        }
    }
}

fn rewrite_ipv4(packet: &mut [u8], end: End, addr: SocketAddr) -> bool {
    let SocketAddr::V4(addr) = addr else {
        return false;
    };
    let Some(parsed) = parse_ipv4(packet) else {
        return false;
    };
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let (ip_off, port_off) = match end {
        End::Source => (12, ihl),
        End::Dest => (16, ihl + 2),
    };
    packet[ip_off..ip_off + 4].copy_from_slice(&addr.ip().octets());
    packet[port_off..port_off + 2].copy_from_slice(&addr.port().to_be_bytes());
    packet[10] = 0;
    packet[11] = 0;
    let ip_sum = checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let l4_off = match parsed.protocol {
        L4::Tcp => 16,
        L4::Udp => 6,
    };
    let csum_at = ihl + l4_off;
    if packet.len() < csum_at + 2 {
        return false;
    }
    packet[csum_at] = 0;
    packet[csum_at + 1] = 0;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let proto = packet[9];
    let mut sum = pseudo_sum(src, dst, proto, &packet[ihl..]);
    if sum == 0 {
        sum = 0xffff;
    }
    packet[csum_at..csum_at + 2].copy_from_slice(&sum.to_be_bytes());
    true
}

fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut words = Vec::with_capacity(6 + segment.len() / 2 + 1);
    words.extend_from_slice(&src.octets());
    words.extend_from_slice(&dst.octets());
    words.push(0);
    words.push(proto);
    let len = segment.len() as u16;
    words.extend_from_slice(&len.to_be_bytes());
    words.extend_from_slice(segment);
    checksum(&words)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_syn(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 40;
        pkt[8] = 64;
        pkt[9] = 6;
        let SocketAddr::V4(src) = src else {
            unreachable!()
        };
        let SocketAddr::V4(dst) = dst else {
            unreachable!()
        };
        pkt[12..16].copy_from_slice(&src.ip().octets());
        pkt[16..20].copy_from_slice(&dst.ip().octets());
        pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
        pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
        pkt[32] = 0x50; // data offset
        pkt[33] = 0x02; // SYN
        let _ = rewrite_ipv4(
            &mut pkt,
            End::Dest,
            SocketAddr::from((*dst.ip(), dst.port())),
        );
        pkt
    }

    #[test]
    fn filter_keeps_the_default_proxy_out() {
        let text = windivert_filter("127.0.0.1", 7898);
        assert!(text.contains("7898"));
        assert!(text.contains("127.0.0.1"));
        assert!(text.contains("!loopback"));
        assert_eq!(
            windivert_filter("proxy.example", 1080),
            "outbound and !loopback and ip and (tcp or udp)"
        );
    }

    #[test]
    fn proxy_syn_is_rewritten_and_the_reply_is_restored() {
        let client: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:34010".parse().unwrap();
        let nat = NatTable::new();
        let syn = tcp_syn(client, dest);
        let action = classify_ipv4(&syn, listen, &nat, |src, dst, proto| {
            assert_eq!(src, client);
            assert_eq!(dst, dest);
            assert_eq!(proto, L4::Tcp);
            NewFlow::Proxy
        });
        let PacketAction::Rewrite { packet, loopback } = action else {
            panic!("expected rewrite, got {action:?}");
        };
        assert!(loopback);
        let parsed = parse_ipv4(&packet).unwrap();
        assert_eq!(parsed.dst, listen);
        assert_eq!(parsed.src, client);
        assert_eq!(nat.lookup(client), Some(dest));

        let mut reply = tcp_syn(listen, client);
        reply[33] = 0x12; // SYN-ACK
        let _ = rewrite_ipv4(&mut reply, End::Dest, client);
        let action = classify_ipv4(&reply, listen, &nat, |_, _, _| NewFlow::Direct);
        let PacketAction::Rewrite { packet, loopback } = action else {
            panic!("expected source restore, got {action:?}");
        };
        assert!(!loopback);
        assert_eq!(parse_ipv4(&packet).unwrap().src, dest);
    }

    #[test]
    fn direct_passes_and_block_drops() {
        let client: SocketAddr = "10.0.0.5:40001".parse().unwrap();
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let listen: SocketAddr = "127.0.0.1:34010".parse().unwrap();
        let nat = NatTable::new();
        let syn = tcp_syn(client, dest);
        assert_eq!(
            classify_ipv4(&syn, listen, &nat, |_, _, _| NewFlow::Direct),
            PacketAction::Pass
        );
        assert!(nat.lookup(client).is_none());
        assert_eq!(
            classify_ipv4(&syn, listen, &nat, |_, _, _| NewFlow::Block),
            PacketAction::Drop
        );
    }
}
