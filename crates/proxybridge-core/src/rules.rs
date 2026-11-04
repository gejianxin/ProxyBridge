//! Process, host, and port matching.
//!
//! Semantics follow the Linux userspace matcher in the original project: first
//! enabled rule wins, `*` matches anything, and host lists accept addresses,
//! CIDR, ranges, per-octet wildcards, and domain globs. Tokens that do not fit
//! are rejected instead of being silently truncated.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// TCP, UDP, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Both,
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostPat {
    V4Range { lo: u32, hi: u32 },
    V4Box { lo: [u8; 4], hi: [u8; 4] },
    V6Range { lo: u128, hi: u128 },
}

/// A rule after its pattern strings have been parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub name: String,
    pub enabled: bool,
    pub protocol: RuleProtocol,
    pub action: RuleAction,
    /// `None` selects the primary proxy.
    pub proxy_name: Option<String>,
    pub localhost: bool,
    pub any_proc: bool,
    pub(crate) procs: Vec<String>,
    pub any_host: bool,
    pub(crate) hosts: Vec<HostPat>,
    pub(crate) domains: Vec<String>,
    pub any_port: bool,
    pub(crate) ports: Vec<(u16, u16)>,
}

const MAX_PROC_PATTERNS: usize = 64;
const MAX_PORT_PATTERNS: usize = 64;
const MAX_HOST_PATTERNS: usize = 1024;
const MAX_PROC_LEN: usize = 511;
const MAX_PORT_LEN: usize = 511;
const MAX_HOST_LEN: usize = 8191;
const MAX_TOKEN: usize = 255;

/// Shell-style `*` and `?` match. `*` spans any length, including empty.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = text.chars().collect();
    let mut pi = 0;
    let mut si = 0;
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = si;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub(crate) struct RuleInput {
    pub name: String,
    pub process: String,
    pub hosts: String,
    pub ports: String,
    pub protocol: RuleProtocol,
    pub action: RuleAction,
    pub proxy_name: Option<String>,
    pub localhost: bool,
    pub enabled: bool,
}

pub(crate) fn compile_rule(input: RuleInput, known_proxies: &[String]) -> Result<CompiledRule> {
    if input.process.len() > MAX_PROC_LEN {
        return Err(Error::Rule(format!(
            "rule '{}': process pattern is longer than {MAX_PROC_LEN} characters",
            input.name
        )));
    }
    if input.ports.len() > MAX_PORT_LEN {
        return Err(Error::Rule(format!(
            "rule '{}': port pattern is longer than {MAX_PORT_LEN} characters",
            input.name
        )));
    }
    if input.hosts.len() > MAX_HOST_LEN {
        return Err(Error::Rule(format!(
            "rule '{}': host pattern is longer than {MAX_HOST_LEN} characters",
            input.name
        )));
    }

    let (any_proc, procs) = parse_proc_list(&input.name, &input.process)?;
    let (any_host, hosts, domains) = parse_host_list(&input.name, &input.hosts)?;
    let (any_port, ports) = parse_port_list(&input.name, &input.ports)?;

    if let Some(name) = &input.proxy_name {
        if input.action == RuleAction::Proxy && !known_proxies.iter().any(|p| p == name) {
            return Err(Error::Rule(format!(
                "rule '{}': proxy '{name}' is not defined",
                input.name
            )));
        }
    }

    Ok(CompiledRule {
        name: input.name,
        enabled: input.enabled,
        protocol: input.protocol,
        action: input.action,
        proxy_name: input.proxy_name,
        localhost: input.localhost,
        any_proc,
        procs,
        any_host,
        hosts,
        domains,
        any_port,
        ports,
    })
}

fn parse_proc_list(rule: &str, text: &str) -> Result<(bool, Vec<String>)> {
    if is_any(text) {
        return Ok((true, Vec::new()));
    }
    let tokens = split_list(text, MAX_PROC_PATTERNS)
        .map_err(|e| Error::Rule(format!("rule '{rule}': {e}")))?;
    let mut procs = Vec::new();
    for tok in tokens {
        if tok == "*" {
            return Ok((true, Vec::new()));
        }
        if tok.chars().count() > MAX_TOKEN {
            return Err(Error::Rule(format!(
                "rule '{rule}': process pattern '{tok}' is longer than {MAX_TOKEN} characters"
            )));
        }
        procs.push(tok);
    }
    Ok((false, procs))
}

fn parse_port_list(rule: &str, text: &str) -> Result<(bool, Vec<(u16, u16)>)> {
    if is_any(text) {
        return Ok((true, Vec::new()));
    }
    let tokens = split_list(text, MAX_PORT_PATTERNS)
        .map_err(|e| Error::Rule(format!("rule '{rule}': {e}")))?;
    let mut ports = Vec::new();
    for tok in tokens {
        if tok == "*" {
            return Ok((true, Vec::new()));
        }
        ports.push(parse_port_token(rule, &tok)?);
    }
    Ok((false, ports))
}

fn parse_host_list(rule: &str, text: &str) -> Result<(bool, Vec<HostPat>, Vec<String>)> {
    if is_any(text) {
        return Ok((true, Vec::new(), Vec::new()));
    }
    let tokens = split_list(text, MAX_HOST_PATTERNS)
        .map_err(|e| Error::Rule(format!("rule '{rule}': {e}")))?;
    let mut hosts = Vec::new();
    let mut domains = Vec::new();
    for tok in tokens {
        if tok == "*" {
            return Ok((true, Vec::new(), Vec::new()));
        }
        if tok.contains(':') {
            hosts.push(parse_v6(rule, &tok)?);
            continue;
        }
        if looks_like_domain(&tok) {
            domains.push(parse_domain(rule, &tok)?);
            continue;
        }
        hosts.push(parse_v4(rule, &tok)?);
    }
    Ok((false, hosts, domains))
}

fn is_any(text: &str) -> bool {
    let t = text.trim();
    t.is_empty() || t == "*"
}

fn split_list(text: &str, max: usize) -> std::result::Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in text.split([';', ',']) {
        let tok = part.trim();
        if tok.is_empty() {
            continue;
        }
        if out.len() >= max {
            return Err(format!("too many patterns (max {max})"));
        }
        out.push(tok.to_string());
    }
    Ok(out)
}

fn looks_like_domain(tok: &str) -> bool {
    tok.chars()
        .any(|c| c.is_ascii_alphabetic() || c == '_' || c == '?')
}

fn parse_domain(rule: &str, tok: &str) -> Result<String> {
    if tok.len() > 253 || tok.is_empty() {
        return Err(Error::Rule(format!(
            "rule '{rule}': invalid domain pattern '{tok}'"
        )));
    }
    if tok.starts_with('.') || tok.ends_with('.') || tok.contains("..") {
        return Err(Error::Rule(format!(
            "rule '{rule}': invalid domain pattern '{tok}'"
        )));
    }
    for c in tok.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*' | '?')) {
            return Err(Error::Rule(format!(
                "rule '{rule}': invalid character '{c}' in domain pattern '{tok}'"
            )));
        }
    }
    Ok(tok.to_ascii_lowercase())
}

fn parse_port_token(rule: &str, tok: &str) -> Result<(u16, u16)> {
    let parsed = if let Some((lo, hi)) = tok.split_once('-') {
        match (parse_u16(lo), parse_u16(hi)) {
            (Ok(a), Ok(b)) => Some((a, b)),
            _ => None,
        }
    } else {
        parse_u16(tok).ok().map(|p| (p, p))
    };
    let Some((a, b)) = parsed else {
        return Err(Error::Rule(format!(
            "rule '{rule}': invalid port range '{tok}'"
        )));
    };
    if a == 0 || b == 0 || a > b {
        return Err(Error::Rule(format!(
            "rule '{rule}': invalid port range '{tok}'"
        )));
    }
    Ok((a, b))
}

fn parse_u16(text: &str) -> std::result::Result<u16, ()> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    text.parse::<u16>().map_err(|_| ())
}

fn parse_v4(rule: &str, tok: &str) -> Result<HostPat> {
    if let Some((addr, prefix)) = tok.split_once('/') {
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|_| Error::Rule(format!("rule '{rule}': invalid IPv4 CIDR '{tok}'")))?;
        let pre: u8 = prefix
            .parse()
            .map_err(|_| Error::Rule(format!("rule '{rule}': invalid IPv4 CIDR '{tok}'")))?;
        if pre > 32 {
            return Err(Error::Rule(format!(
                "rule '{rule}': invalid IPv4 CIDR '{tok}'"
            )));
        }
        let ip = u32::from(ip);
        let mask = if pre == 0 { 0 } else { u32::MAX << (32 - pre) };
        return Ok(HostPat::V4Range {
            lo: ip & mask,
            hi: ip | !mask,
        });
    }

    if let Some((start, end)) = split_v4_range(tok) {
        let a: Ipv4Addr = start
            .parse()
            .map_err(|_| Error::Rule(format!("rule '{rule}': invalid IPv4 range '{tok}'")))?;
        let b: Ipv4Addr = end
            .parse()
            .map_err(|_| Error::Rule(format!("rule '{rule}': invalid IPv4 range '{tok}'")))?;
        let a = u32::from(a);
        let b = u32::from(b);
        if a > b {
            return Err(Error::Rule(format!(
                "rule '{rule}': IPv4 range '{tok}' has start > end"
            )));
        }
        return Ok(HostPat::V4Range { lo: a, hi: b });
    }

    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::Rule(format!(
            "rule '{rule}': invalid IPv4 address or pattern '{tok}'"
        )));
    }
    let mut lo = [0u8; 4];
    let mut hi = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let (a, b) = parse_octet(part).map_err(|_| {
            Error::Rule(format!(
                "rule '{rule}': invalid IPv4 address or pattern '{tok}'"
            ))
        })?;
        lo[i] = a;
        hi[i] = b;
    }
    if contiguous_suffix(&lo, &hi) {
        let mut lo_n = 0u32;
        let mut hi_n = 0u32;
        for i in 0..4 {
            lo_n = (lo_n << 8) | u32::from(lo[i]);
            hi_n = (hi_n << 8) | u32::from(hi[i]);
        }
        Ok(HostPat::V4Range { lo: lo_n, hi: hi_n })
    } else {
        Ok(HostPat::V4Box { lo, hi })
    }
}

/// `a.b.c.d-e.f.g.h` is an address range. A dash inside an octet is not.
fn split_v4_range(tok: &str) -> Option<(&str, &str)> {
    let dash = tok.find('-')?;
    let dots = tok[..dash].bytes().filter(|b| *b == b'.').count();
    if dots == 3 {
        Some((&tok[..dash], &tok[dash + 1..]))
    } else {
        None
    }
}

fn parse_octet(text: &str) -> std::result::Result<(u8, u8), ()> {
    if text == "*" {
        return Ok((0, 255));
    }
    if let Some((a, b)) = text.split_once('-') {
        let lo = parse_octet_num(a)?;
        let hi = parse_octet_num(b)?;
        if lo > hi {
            return Err(());
        }
        return Ok((lo, hi));
    }
    let n = parse_octet_num(text)?;
    Ok((n, n))
}

fn parse_octet_num(text: &str) -> std::result::Result<u8, ()> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let n: u16 = text.parse().map_err(|_| ())?;
    if n > 255 {
        Err(())
    } else {
        Ok(n as u8)
    }
}

fn contiguous_suffix(lo: &[u8; 4], hi: &[u8; 4]) -> bool {
    let mut i = 0;
    while i < 4 && lo[i] == hi[i] {
        i += 1;
    }
    if i == 4 {
        return true;
    }
    for j in (i + 1)..4 {
        if lo[j] != 0 || hi[j] != 255 {
            return false;
        }
    }
    true
}

fn parse_v6(rule: &str, tok: &str) -> Result<HostPat> {
    if let Some((addr, prefix)) = tok.split_once('/') {
        let ip: Ipv6Addr = addr.parse().map_err(|_| {
            Error::Rule(format!(
                "rule '{rule}': invalid IPv6 address or range '{tok}'"
            ))
        })?;
        let pre: u8 = prefix.parse().map_err(|_| {
            Error::Rule(format!(
                "rule '{rule}': invalid IPv6 address or range '{tok}'"
            ))
        })?;
        if pre > 128 {
            return Err(Error::Rule(format!(
                "rule '{rule}': invalid IPv6 address or range '{tok}'"
            )));
        }
        let (lo, hi) = v6_prefix(u128::from(ip), pre);
        return Ok(HostPat::V6Range { lo, hi });
    }
    if let Some((start, end)) = tok.split_once('-') {
        let a: Ipv6Addr = start.parse().map_err(|_| {
            Error::Rule(format!(
                "rule '{rule}': invalid IPv6 address or range '{tok}'"
            ))
        })?;
        let b: Ipv6Addr = end.parse().map_err(|_| {
            Error::Rule(format!(
                "rule '{rule}': invalid IPv6 address or range '{tok}'"
            ))
        })?;
        let a = u128::from(a);
        let b = u128::from(b);
        if a > b {
            return Err(Error::Rule(format!(
                "rule '{rule}': IPv6 range '{tok}' has start > end"
            )));
        }
        return Ok(HostPat::V6Range { lo: a, hi: b });
    }
    let ip: Ipv6Addr = tok.parse().map_err(|_| {
        Error::Rule(format!(
            "rule '{rule}': invalid IPv6 address or range '{tok}'"
        ))
    })?;
    let n = u128::from(ip);
    Ok(HostPat::V6Range { lo: n, hi: n })
}

fn v6_prefix(ip: u128, prefix: u8) -> (u128, u128) {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (ip & mask, ip | !mask)
}

pub(crate) fn rule_matches(
    rule: &CompiledRule,
    process_path: Option<&str>,
    dest_ip: Option<IpAddr>,
    dest_host: Option<&str>,
    dest_port: u16,
    protocol_tcp: bool,
    case_insensitive_process: bool,
) -> bool {
    if !rule.enabled {
        return false;
    }
    if !protocol_matches(rule.protocol, protocol_tcp) {
        return false;
    }
    if !process_matches(rule, process_path, case_insensitive_process) {
        return false;
    }
    dest_matches(rule, dest_ip, dest_host, dest_port)
}

fn protocol_matches(rule: RuleProtocol, tcp: bool) -> bool {
    match rule {
        RuleProtocol::Both => true,
        RuleProtocol::Tcp => tcp,
        RuleProtocol::Udp => !tcp,
    }
}

fn process_matches(rule: &CompiledRule, path: Option<&str>, case_insensitive: bool) -> bool {
    if rule.any_proc {
        return true;
    }
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return false;
    };
    let base = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path);
    for pat in &rule.procs {
        if case_insensitive {
            let pat = pat.to_ascii_lowercase();
            if glob_match(&pat, &path.to_ascii_lowercase())
                || glob_match(&pat, &base.to_ascii_lowercase())
            {
                return true;
            }
        } else if glob_match(pat, path) || glob_match(pat, base) {
            return true;
        }
    }
    false
}

fn dest_matches(
    rule: &CompiledRule,
    dest_ip: Option<IpAddr>,
    dest_host: Option<&str>,
    dest_port: u16,
) -> bool {
    if !rule.any_port
        && !rule
            .ports
            .iter()
            .any(|(lo, hi)| dest_port >= *lo && dest_port <= *hi)
    {
        return false;
    }
    if rule.any_host {
        return true;
    }
    if let Some(ip) = dest_ip {
        if host_ip_matches(&rule.hosts, normalize_ip(ip)) {
            return true;
        }
    }
    if let Some(host) = dest_host {
        let host = trim_dot(&host.to_ascii_lowercase());
        if rule.domains.iter().any(|pat| glob_match(pat, &host)) {
            return true;
        }
    }
    false
}

fn trim_dot(host: &str) -> String {
    host.trim_end_matches('.').to_string()
}

pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn host_ip_matches(pats: &[HostPat], ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(v4);
            let octets = v4.octets();
            pats.iter().any(|p| match p {
                HostPat::V4Range { lo, hi } => n >= *lo && n <= *hi,
                HostPat::V4Box { lo, hi } => {
                    (0..4).all(|i| octets[i] >= lo[i] && octets[i] <= hi[i])
                }
                HostPat::V6Range { .. } => false,
            })
        }
        IpAddr::V6(v6) => {
            let n = u128::from(v6);
            pats.iter().any(|p| match p {
                HostPat::V6Range { lo, hi } => n >= *lo && n <= *hi,
                _ => false,
            })
        }
    }
}

pub(crate) fn is_loopback(ip: Option<IpAddr>, host: Option<&str>) -> bool {
    if let Some(ip) = ip {
        if normalize_ip(ip).is_loopback() {
            return true;
        }
    }
    if let Some(host) = host {
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
    }
    false
}

/// Destinations the original datapath never redirects: multicast, broadcast,
/// unspecified, and IPv6 link-local. Loopback and DNS are decided separately.
pub(crate) fn is_hard_implicit(ip: Option<IpAddr>) -> bool {
    let Some(ip) = ip else {
        return false;
    };
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets()[0];
            o == 0 || o >= 224
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0xff || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
        }
    }
}

pub(crate) fn rules_need_resolution(rules: &[CompiledRule]) -> bool {
    rules
        .iter()
        .any(|r| r.enabled && !r.any_host && !r.hosts.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(hosts: &str, ports: &str, process: &str) -> CompiledRule {
        compile_rule(
            RuleInput {
                name: "t".into(),
                process: process.into(),
                hosts: hosts.into(),
                ports: ports.into(),
                protocol: RuleProtocol::Both,
                action: RuleAction::Proxy,
                proxy_name: None,
                localhost: false,
                enabled: true,
            },
            &["default".into()],
        )
        .unwrap()
    }

    fn matches(rule: &CompiledRule, ip: &str, port: u16) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        rule_matches(rule, Some("curl"), Some(ip), None, port, true, false)
    }

    #[test]
    fn glob_stars_and_questions() {
        assert!(glob_match("fire*", "firefox"));
        assert!(glob_match("curl", "curl"));
        assert!(!glob_match("curl", "curlw"));
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn ipv4_cidr_range_and_wildcards() {
        let r = rule("10.0.0.0/8,192.168.*.*,10.1.0.1-10.1.0.10", "*", "*");
        assert!(matches(&r, "10.1.2.3", 1));
        assert!(matches(&r, "192.168.4.5", 1));
        assert!(!matches(&r, "192.169.0.1", 1));
        assert!(matches(&r, "10.1.0.10", 1));
        assert!(!matches(&r, "11.0.0.1", 1));

        let box_rule = rule("10.1-2.*.5", "*", "*");
        assert!(matches(&box_rule, "10.1.9.5", 80));
        assert!(matches(&box_rule, "10.2.0.5", 80));
        assert!(!matches(&box_rule, "10.3.0.5", 80));
        assert!(!matches(&box_rule, "10.1.9.6", 80));
    }

    #[test]
    fn ports_process_and_domain() {
        let r = rule("*.example.com,1.2.3.4", "80,443,8000-8002", "curl,fire*");
        assert!(rule_matches(
            &r,
            Some("/usr/bin/curl"),
            None,
            Some("A.Example.com."),
            443,
            true,
            false
        ));
        assert!(!rule_matches(
            &r,
            Some("/usr/bin/curl"),
            None,
            Some("example.com"),
            443,
            true,
            false
        ));
        assert!(rule_matches(
            &r,
            Some("C:\\Program Files\\firefox.exe"),
            Some("1.2.3.4".parse().unwrap()),
            None,
            8001,
            true,
            false
        ));
        assert!(!rule_matches(
            &r,
            Some("/usr/bin/wget"),
            Some("1.2.3.4".parse().unwrap()),
            None,
            80,
            true,
            false
        ));
        assert!(!matches(&r, "1.2.3.4", 81));
        assert!(!rule_matches(
            &r,
            None,
            Some("1.2.3.4".parse().unwrap()),
            None,
            80,
            true,
            false
        ));
    }

    #[test]
    fn ipv6_cidr_and_invalid_patterns() {
        let r = rule("2001:db8::/32", "*", "*");
        assert!(matches(&r, "2001:db8::1", 9));
        assert!(!matches(&r, "2001:db9::1", 9));
        assert!(compile_rule(
            RuleInput {
                name: "bad".into(),
                process: "*".into(),
                hosts: "10.0.0.1/33".into(),
                ports: "*".into(),
                protocol: RuleProtocol::Tcp,
                action: RuleAction::Direct,
                proxy_name: None,
                localhost: false,
                enabled: true,
            },
            &[],
        )
        .is_err());
        assert!(compile_rule(
            RuleInput {
                name: "badport".into(),
                process: "*".into(),
                hosts: "*".into(),
                ports: "0".into(),
                protocol: RuleProtocol::Tcp,
                action: RuleAction::Direct,
                proxy_name: None,
                localhost: false,
                enabled: true,
            },
            &[],
        )
        .is_err());
    }

    #[test]
    fn case_insensitive_process_names() {
        let r = rule("*", "*", "Chrome");
        assert!(!rule_matches(
            &r,
            Some("chrome"),
            None,
            None,
            1,
            true,
            false
        ));
        assert!(rule_matches(&r, Some("chrome"), None, None, 1, true, true));
    }
}
