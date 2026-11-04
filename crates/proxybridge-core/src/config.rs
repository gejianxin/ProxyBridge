//! Configuration file, built-in defaults, and environment overrides.
//!
//! The coded default proxy is SOCKS5 at `127.0.0.1:7898`. A file, environment
//! variables, and CLI flags can replace that endpoint. When no rules are
//! configured, one enabled catch-all rule sends matching traffic to it.
//! Loopback, multicast, the proxy's own address, and DNS (unless requested)
//! stay direct so the process does not proxy itself.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::rules::{compile_rule, CompiledRule, RuleAction, RuleInput, RuleProtocol};

/// Default proxy address. This is the coded default, not only a sample file.
pub const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
/// Default proxy port.
pub const DEFAULT_PROXY_PORT: u16 = 7898;
/// Default proxy protocol.
pub const DEFAULT_PROXY_TYPE: ProxyKind = ProxyKind::Socks5;

/// SOCKS5 or HTTP CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
}

impl ProxyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "socks5" | "socks" => Ok(ProxyKind::Socks5),
            "http" | "https" => Ok(ProxyKind::Http),
            other => Err(Error::Config(format!(
                "unknown proxy type '{other}' (expected socks5 or http)"
            ))),
        }
    }
}

/// One upstream proxy. Passwords are redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// When true, send a domain name to the proxy instead of a resolved address.
    pub send_domain: bool,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "****"))
            .field("send_domain", &self.send_domain)
            .finish()
    }
}

impl ProxyEndpoint {
    pub fn builtin() -> Self {
        Self {
            name: "default".into(),
            kind: DEFAULT_PROXY_TYPE,
            host: DEFAULT_PROXY_HOST.into(),
            port: DEFAULT_PROXY_PORT,
            username: None,
            password: None,
            send_domain: true,
        }
    }

    /// `socks5://127.0.0.1:7898` with no userinfo.
    pub fn label(&self) -> String {
        format!("{}://{}:{}", self.kind.as_str(), self.host, self.port)
    }

    pub fn has_auth(&self) -> bool {
        self.username.as_ref().is_some_and(|u| !u.is_empty())
    }
}

/// Field overrides applied after the file is loaded. `Some` replaces a field
/// on the primary proxy (or a top-level switch). Later calls win, so CLI flags
/// can be applied after environment variables.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub proxy_type: Option<ProxyKind>,
    pub proxy_host: Option<String>,
    pub proxy_port: Option<u16>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    pub send_domain: Option<bool>,
    pub dns_via_proxy: Option<bool>,
    pub enabled: Option<bool>,
}

/// Effective configuration used by the engine.
#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub dns_via_proxy: bool,
    /// When true, UDP is left direct. Proxifier `Udp mode="mode_bypass"` maps here.
    pub udp_bypass: bool,
    pub log_every_connection: bool,
    pub proxies: Vec<ProxyEndpoint>,
    pub rules: Vec<CompiledRule>,
    pub case_insensitive_process: bool,
}

impl Config {
    /// Built-in configuration: SOCKS5 `127.0.0.1:7898` and a catch-all proxy rule.
    pub fn builtin() -> Self {
        let proxy = ProxyEndpoint::builtin();
        let rules = vec![builtin_rule(&proxy.name).expect("built-in rule is valid")];
        Self {
            enabled: true,
            dns_via_proxy: false,
            udp_bypass: false,
            log_every_connection: false,
            proxies: vec![proxy],
            rules,
            case_insensitive_process: cfg!(windows),
        }
    }

    pub fn from_toml_str(text: &str) -> Result<Self> {
        let file: FileConfig = toml::from_str(text)
            .map_err(|e| Error::Config(format!("could not parse TOML: {e}")))?;
        file.into_config()
    }

    pub fn primary(&self) -> &ProxyEndpoint {
        &self.proxies[0]
    }

    pub fn apply_overrides(&mut self, over: &Overrides) -> Result<()> {
        let primary = &mut self.proxies[0];
        if let Some(kind) = over.proxy_type {
            primary.kind = kind;
        }
        if let Some(host) = &over.proxy_host {
            validate_host(host)?;
            primary.host = host.clone();
        }
        if let Some(port) = over.proxy_port {
            validate_port(port)?;
            primary.port = port;
        }
        if let Some(user) = &over.proxy_username {
            primary.username = blank_to_none(user);
        }
        if let Some(pass) = &over.proxy_password {
            primary.password = blank_to_none(pass);
        }
        if let Some(send) = over.send_domain {
            primary.send_domain = send;
        }
        if let Some(dns) = over.dns_via_proxy {
            self.dns_via_proxy = dns;
        }
        if let Some(enabled) = over.enabled {
            self.enabled = enabled;
        }
        Ok(())
    }

    /// True when a domain target must be resolved before IP patterns can match.
    pub fn needs_ip_for_domain_match(&self) -> bool {
        crate::rules::rules_need_resolution(&self.rules)
    }

    pub fn proxy_named(&self, name: Option<&str>) -> &ProxyEndpoint {
        let Some(name) = name else {
            return self.primary();
        };
        self.proxies
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| self.primary())
    }

    /// Multi-line description. Passwords are never included.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "enabled={}\ndns_via_proxy={}\nudp_bypass={}\nlog_every_connection={}\n",
            self.enabled, self.dns_via_proxy, self.udp_bypass, self.log_every_connection
        ));
        for (i, proxy) in self.proxies.iter().enumerate() {
            let role = if i == 0 { "primary" } else { "extra" };
            out.push_str(&format!(
                "proxy {role} name={} {} send_domain={} auth={}\n",
                proxy.name,
                proxy.label(),
                proxy.send_domain,
                proxy.has_auth()
            ));
        }
        for rule in &self.rules {
            out.push_str(&format!(
                "rule name={} enabled={} protocol={} action={} proxy={} localhost={}\n",
                rule.name,
                rule.enabled,
                protocol_label(rule.protocol),
                action_label(rule.action),
                rule.proxy_name.as_deref().unwrap_or("default"),
                rule.localhost
            ));
        }
        out
    }

    pub(crate) fn is_proxy_dest(&self, port: u16, ip: Option<IpAddr>, host: Option<&str>) -> bool {
        self.proxies.iter().any(|proxy| {
            if proxy.port != port {
                return false;
            }
            if let Some(host) = host {
                if host.eq_ignore_ascii_case(&proxy.host) {
                    return true;
                }
            }
            if let (Some(dest), Ok(proxy_ip)) = (ip, proxy.host.parse::<IpAddr>()) {
                return crate::rules::normalize_ip(dest) == crate::rules::normalize_ip(proxy_ip);
            }
            false
        })
    }
}

/// Read the `PROXYBRIDGE_*` variables from the process environment.
pub fn overrides_from_env() -> Result<Overrides> {
    let pairs: Vec<(String, String)> = std::env::vars().collect();
    overrides_from_pairs(pairs)
}

/// Same as [`overrides_from_env`], but from an explicit list so tests stay isolated.
pub fn overrides_from_pairs<I, K, V>(pairs: I) -> Result<Overrides>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let map: HashMap<String, String> = pairs
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .collect();
    let mut over = Overrides::default();
    if let Some(v) = map.get("PROXYBRIDGE_PROXY_TYPE") {
        over.proxy_type = Some(ProxyKind::parse(v)?);
    }
    if let Some(v) = map.get("PROXYBRIDGE_PROXY_HOST") {
        over.proxy_host = Some(v.clone());
    }
    if let Some(v) = map.get("PROXYBRIDGE_PROXY_PORT") {
        let port = parse_port_str(v)?;
        over.proxy_port = Some(port);
    }
    if let Some(v) = map.get("PROXYBRIDGE_PROXY_USERNAME") {
        over.proxy_username = Some(v.clone());
    }
    if let Some(v) = map.get("PROXYBRIDGE_PROXY_PASSWORD") {
        over.proxy_password = Some(v.clone());
    }
    if let Some(v) = map.get("PROXYBRIDGE_SEND_DOMAIN") {
        over.send_domain = Some(parse_bool(v, "PROXYBRIDGE_SEND_DOMAIN")?);
    }
    if let Some(v) = map.get("PROXYBRIDGE_DNS_VIA_PROXY") {
        over.dns_via_proxy = Some(parse_bool(v, "PROXYBRIDGE_DNS_VIA_PROXY")?);
    }
    if let Some(v) = map.get("PROXYBRIDGE_ENABLED") {
        over.enabled = Some(parse_bool(v, "PROXYBRIDGE_ENABLED")?);
    }
    Ok(over)
}

/// `socks5://host:port`, `http://host:port`, or `host:port` (SOCKS5).
pub fn parse_proxy_spec(text: &str) -> Result<(ProxyKind, String, u16)> {
    let text = text.trim();
    let (kind, rest) = if let Some(rest) = text.strip_prefix("socks5://") {
        (ProxyKind::Socks5, rest)
    } else if let Some(rest) = text.strip_prefix("socks://") {
        (ProxyKind::Socks5, rest)
    } else if let Some(rest) = text.strip_prefix("http://") {
        (ProxyKind::Http, rest)
    } else if let Some(rest) = text.strip_prefix("https://") {
        (ProxyKind::Http, rest)
    } else {
        (ProxyKind::Socks5, text)
    };
    if rest.contains("://") || rest.contains('@') {
        return Err(Error::Config(
            "proxy URL must not include userinfo; use --proxy-user and --proxy-pass".into(),
        ));
    }
    let (host, port) = split_host_port(rest)?;
    validate_host(&host)?;
    validate_port(port)?;
    Ok((kind, host, port))
}

fn split_host_port(text: &str) -> Result<(String, u16)> {
    if let Some(rest) = text.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(Error::Config(format!(
                "invalid proxy address '{text}' (use [ipv6]:port)"
            )));
        };
        let port = parse_port_str(port)?;
        return Ok((host.to_string(), port));
    }
    let Some((host, port)) = text.rsplit_once(':') else {
        return Err(Error::Config(format!(
            "invalid proxy address '{text}' (expected host:port)"
        )));
    };
    if host.is_empty() || port.is_empty() {
        return Err(Error::Config(format!("invalid proxy address '{text}'")));
    }
    Ok((host.to_string(), parse_port_str(port)?))
}

fn builtin_rule(proxy_name: &str) -> Result<CompiledRule> {
    compile_rule(
        RuleInput {
            name: "default".into(),
            process: "*".into(),
            hosts: "*".into(),
            ports: "*".into(),
            protocol: RuleProtocol::Both,
            action: RuleAction::Proxy,
            proxy_name: None,
            localhost: false,
            enabled: true,
        },
        &[proxy_name.to_string()],
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    dns_via_proxy: bool,
    #[serde(default)]
    udp_bypass: bool,
    #[serde(default)]
    log_every_connection: bool,
    #[serde(default)]
    proxy: Option<ProxyFile>,
    #[serde(default)]
    proxies: Vec<ProxyFile>,
    /// `None` means the key was omitted, so the built-in catch-all rule is used.
    #[serde(default)]
    rules: Option<Vec<RuleFile>>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyFile {
    #[serde(default = "default_proxy_name")]
    name: String,
    #[serde(rename = "type", default = "default_type_name")]
    kind: String,
    #[serde(default = "default_host")]
    host: String,
    #[serde(default = "default_port_value")]
    port: FlexiblePort,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default = "default_true")]
    send_domain: bool,
}

fn default_proxy_name() -> String {
    "default".into()
}
fn default_type_name() -> String {
    "socks5".into()
}
fn default_host() -> String {
    DEFAULT_PROXY_HOST.into()
}
fn default_port_value() -> FlexiblePort {
    FlexiblePort::Num(DEFAULT_PROXY_PORT)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexiblePort {
    Num(u16),
    Str(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    name: String,
    #[serde(default = "star")]
    process: String,
    #[serde(default = "star")]
    hosts: String,
    #[serde(default = "star")]
    ports: String,
    #[serde(default = "both")]
    protocol: String,
    #[serde(default = "proxy_action")]
    action: String,
    #[serde(default)]
    proxy: String,
    #[serde(default)]
    localhost: bool,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn star() -> String {
    "*".into()
}
fn both() -> String {
    "both".into()
}
fn proxy_action() -> String {
    "proxy".into()
}

impl FileConfig {
    fn into_config(self) -> Result<Config> {
        let mut proxies = Vec::new();
        if let Some(primary) = self.proxy {
            proxies.push(primary.into_endpoint(true)?);
        } else {
            proxies.push(ProxyEndpoint::builtin());
        }
        for extra in self.proxies {
            proxies.push(extra.into_endpoint(false)?);
        }
        let mut seen = HashMap::<String, ()>::new();
        for proxy in &proxies {
            if seen.insert(proxy.name.clone(), ()).is_some() {
                return Err(Error::Config(format!(
                    "duplicate proxy name '{}'",
                    proxy.name
                )));
            }
        }
        let names: Vec<String> = proxies.iter().map(|p| p.name.clone()).collect();
        let rules = match self.rules {
            None => vec![builtin_rule(&names[0])?],
            Some(list) => {
                let mut compiled = Vec::with_capacity(list.len());
                for (idx, rule) in list.into_iter().enumerate() {
                    compiled.push(rule.into_rule(idx, &names)?);
                }
                compiled
            }
        };
        Ok(Config {
            enabled: self.enabled,
            dns_via_proxy: self.dns_via_proxy,
            udp_bypass: self.udp_bypass,
            log_every_connection: self.log_every_connection,
            proxies,
            rules,
            case_insensitive_process: cfg!(windows),
        })
    }
}

impl ProxyFile {
    fn into_endpoint(self, primary: bool) -> Result<ProxyEndpoint> {
        let name = if primary && self.name.trim().is_empty() {
            "default".to_string()
        } else {
            self.name.trim().to_string()
        };
        if name.is_empty() {
            return Err(Error::Config("proxy name must not be empty".into()));
        }
        if !primary && name == "default" {
            return Err(Error::Config(
                "extra proxies cannot be named 'default'; that name selects the [proxy] entry"
                    .into(),
            ));
        }
        validate_host(&self.host)?;
        let port = flexible_port(&self.port)?;
        validate_port(port)?;
        let kind = ProxyKind::parse(&self.kind)?;
        reject_header_injection(&self.username)?;
        reject_header_injection(&self.password)?;
        Ok(ProxyEndpoint {
            name,
            kind,
            host: self.host,
            port,
            username: blank_to_none(&self.username),
            password: blank_to_none(&self.password),
            send_domain: self.send_domain,
        })
    }
}

impl RuleFile {
    fn into_rule(self, index: usize, proxies: &[String]) -> Result<CompiledRule> {
        let name = if self.name.trim().is_empty() {
            format!("rule-{}", index + 1)
        } else {
            self.name.trim().to_string()
        };
        let protocol = match self.protocol.trim().to_ascii_lowercase().as_str() {
            "tcp" => RuleProtocol::Tcp,
            "udp" => RuleProtocol::Udp,
            "both" | "all" | "tcp+udp" => RuleProtocol::Both,
            other => {
                return Err(Error::Rule(format!(
                    "rule '{name}': unknown protocol '{other}' (expected tcp, udp, or both)"
                )))
            }
        };
        let action = match self.action.trim().to_ascii_lowercase().as_str() {
            "proxy" => RuleAction::Proxy,
            "direct" => RuleAction::Direct,
            "block" => RuleAction::Block,
            other => {
                return Err(Error::Rule(format!(
                    "rule '{name}': unknown action '{other}' (expected proxy, direct, or block)"
                )))
            }
        };
        let proxy_name = {
            let p = self.proxy.trim();
            if p.is_empty() || p.eq_ignore_ascii_case("default") {
                None
            } else {
                Some(p.to_string())
            }
        };
        compile_rule(
            RuleInput {
                name,
                process: self.process,
                hosts: self.hosts,
                ports: self.ports,
                protocol,
                action,
                proxy_name,
                localhost: self.localhost,
                enabled: self.enabled,
            },
            proxies,
        )
    }
}

fn flexible_port(port: &FlexiblePort) -> Result<u16> {
    match port {
        FlexiblePort::Num(n) => Ok(*n),
        FlexiblePort::Str(s) => parse_port_str(s),
    }
}

fn parse_port_str(text: &str) -> Result<u16> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Config(format!("invalid port '{text}'")));
    }
    let n: u32 = text
        .parse()
        .map_err(|_| Error::Config(format!("invalid port '{text}'")))?;
    if n == 0 || n > 65535 {
        return Err(Error::Config(format!(
            "invalid port '{text}' (expected 1-65535)"
        )));
    }
    Ok(n as u16)
}

fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        Err(Error::Config("invalid port '0' (expected 1-65535)".into()))
    } else {
        Ok(())
    }
}

fn validate_host(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() || host.len() > 253 {
        return Err(Error::Config("proxy host must be 1-253 characters".into()));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '@')
    {
        return Err(Error::Config(format!("invalid proxy host '{host}'")));
    }
    Ok(())
}

fn blank_to_none(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn reject_header_injection(text: &str) -> Result<()> {
    if text.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        return Err(Error::Config(
            "proxy username and password cannot contain newlines".into(),
        ));
    }
    Ok(())
}

fn parse_bool(text: &str, name: &str) -> Result<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(Error::Config(format!(
            "{name} must be true or false, got '{other}'"
        ))),
    }
}

fn protocol_label(p: RuleProtocol) -> &'static str {
    match p {
        RuleProtocol::Tcp => "tcp",
        RuleProtocol::Udp => "udp",
        RuleProtocol::Both => "both",
    }
}

fn action_label(a: RuleAction) -> &'static str {
    match a {
        RuleAction::Proxy => "proxy",
        RuleAction::Direct => "direct",
        RuleAction::Block => "block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_socks5_localhost_7898() {
        let cfg = Config::builtin();
        let p = cfg.primary();
        assert_eq!(p.kind, ProxyKind::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 7898);
        assert!(cfg.rules[0].enabled);
        assert_eq!(cfg.rules[0].action, RuleAction::Proxy);
        assert!(!cfg.dns_via_proxy);
    }

    #[test]
    fn partial_file_keeps_the_other_defaults() {
        let cfg = Config::from_toml_str("[proxy]\nport = 1\n").unwrap();
        let p = cfg.primary();
        assert_eq!(p.kind, ProxyKind::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1);
        assert_eq!(cfg.rules.len(), 1);
    }

    #[test]
    fn string_port_and_env_then_flag_order() {
        let mut cfg = Config::from_toml_str(
            "[proxy]\ntype = \"HTTP\"\nhost = \"proxy.example\"\nport = \"8080\"\nusername = \"a\"\npassword = \"secret\"\n",
        )
        .unwrap();
        assert_eq!(cfg.primary().kind, ProxyKind::Http);
        assert!(cfg.primary().has_auth());
        assert!(!format!("{:?}", cfg.primary()).contains("secret"));

        let env = overrides_from_pairs([
            ("PROXYBRIDGE_PROXY_TYPE", "socks5"),
            ("PROXYBRIDGE_PROXY_HOST", "10.0.0.8"),
            ("PROXYBRIDGE_PROXY_PORT", "7898"),
        ])
        .unwrap();
        cfg.apply_overrides(&env).unwrap();
        cfg.apply_overrides(&Overrides {
            proxy_port: Some(9000),
            ..Overrides::default()
        })
        .unwrap();
        assert_eq!(cfg.primary().kind, ProxyKind::Socks5);
        assert_eq!(cfg.primary().host, "10.0.0.8");
        assert_eq!(cfg.primary().port, 9000);
    }

    #[test]
    fn empty_rules_are_not_replaced_by_the_builtin() {
        let cfg = Config::from_toml_str("rules = []\n").unwrap();
        assert!(cfg.rules.is_empty());
        assert_eq!(cfg.primary().port, 7898);
    }

    #[test]
    fn named_proxy_must_exist() {
        let err = Config::from_toml_str(
            "[[rules]]\nname = \"x\"\naction = \"proxy\"\nproxy = \"missing\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn proxy_spec_parser() {
        assert_eq!(
            parse_proxy_spec("127.0.0.1:7898").unwrap(),
            (ProxyKind::Socks5, "127.0.0.1".into(), 7898)
        );
        assert_eq!(
            parse_proxy_spec("http://localhost:8080").unwrap(),
            (ProxyKind::Http, "localhost".into(), 8080)
        );
        assert_eq!(
            parse_proxy_spec("socks5://[::1]:1080").unwrap(),
            (ProxyKind::Socks5, "::1".into(), 1080)
        );
        assert!(parse_proxy_spec("socks5://user:pass@127.0.0.1:1").is_err());
        assert!(parse_proxy_spec("127.0.0.1:0").is_err());
    }

    #[test]
    fn example_file_uses_the_coded_default() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proxybridge.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let cfg = Config::from_toml_str(&text).unwrap();
        assert_eq!(cfg.primary().kind, ProxyKind::Socks5);
        assert_eq!(cfg.primary().host, DEFAULT_PROXY_HOST);
        assert_eq!(cfg.primary().port, DEFAULT_PROXY_PORT);
        assert!(cfg.summary().contains("socks5://127.0.0.1:7898"));
    }
}
