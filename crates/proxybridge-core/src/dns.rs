//! Unencrypted DNS answers used to attach a name to a later connection.
//!
//! Only standard responses are parsed (QR = 1). Queries, truncated messages,
//! and pointer loops are ignored. DoH and DoT never reach this parser.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

/// IP addresses learned from DNS replies, newest names first.
#[derive(Debug, Default)]
pub struct DnsCache {
    by_ip: Mutex<HashMap<IpAddr, Vec<String>>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record A and AAAA answers. Returns how many addresses were stored.
    pub fn observe(&self, payload: &[u8]) -> usize {
        let records = parse_response(payload);
        if records.is_empty() {
            return 0;
        }
        let mut map = self.by_ip.lock().unwrap_or_else(|err| err.into_inner());
        for (name, ip) in &records {
            let list = map.entry(*ip).or_default();
            if !list.iter().any(|have| have == name) {
                list.insert(0, name.clone());
                if list.len() > 8 {
                    list.truncate(8);
                }
            }
        }
        records.len()
    }

    pub fn names(&self, ip: IpAddr) -> Vec<String> {
        self.by_ip
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(&ip)
            .cloned()
            .unwrap_or_default()
    }
}

fn parse_response(payload: &[u8]) -> Vec<(String, IpAddr)> {
    if payload.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let an = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qd {
        if skip_name(payload, &mut offset).is_err() || offset + 4 > payload.len() {
            return Vec::new();
        }
        offset += 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let Some((name, next)) = read_name(payload, offset) else {
            break;
        };
        offset = next;
        if offset + 10 > payload.len() {
            break;
        }
        let typ = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let class = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        let rdlen = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > payload.len() {
            break;
        }
        if class == 1 {
            if typ == 1 && rdlen == 4 {
                let ip = Ipv4Addr::new(
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                );
                out.push((name, IpAddr::V4(ip)));
            } else if typ == 28 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[offset..offset + 16]);
                out.push((name, IpAddr::V6(Ipv6Addr::from(octets))));
            }
        }
        offset += rdlen;
    }
    out
}

fn skip_name(payload: &[u8], offset: &mut usize) -> Result<(), ()> {
    let (_, next) = read_name(payload, *offset).ok_or(())?;
    *offset = next;
    Ok(())
}

fn read_name(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut hops = 0;
    let mut end = None;
    loop {
        if offset >= payload.len() || hops > 16 {
            return None;
        }
        let len = payload[offset];
        if len == 0 {
            if end.is_none() {
                end = Some(offset + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            let ptr = (((len as usize) & 0x3f) << 8) | payload[offset + 1] as usize;
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = ptr;
            hops += 1;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let start = offset + 1;
        let stop = start + len as usize;
        if stop > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[start..stop]).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = stop;
    }
    let name = labels.join(".");
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    Some((name, end?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184,
            216, 34,
        ];
        // AAAA answer for the same name, pointing at the question.
        pkt.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        pkt[7] = 2; // ancount
        pkt
    }

    #[test]
    fn response_fills_the_cache_and_queries_do_not() {
        let cache = DnsCache::new();
        assert_eq!(cache.observe(b"not dns"), 0);
        let mut query = sample_response();
        query[2] = 0x01; // QR cleared
        assert_eq!(cache.observe(&query), 0);
        assert_eq!(cache.observe(&sample_response()), 2);
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(cache.names(v4), vec!["example.com".to_string()]);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(cache.names(v6), vec!["example.com".to_string()]);
    }
}
