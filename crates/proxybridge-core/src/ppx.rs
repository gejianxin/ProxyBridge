//! Proxifier `.ppx` profile import (XML, profile version 102 and nearby).
//!
//! Rule order, enabled flags, and the SOCKS5 or HTTP endpoint are kept.
//! `Udp mode="mode_bypass"` becomes [`Config::udp_bypass`].
//! `Resolve/ViaProxy enabled="false"` resolves names on this machine.
//! Proxy chains, encryption, and "other users / services" filters have no
//! equivalent here and are not applied.

use std::path::Path;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::config::{Config, ProxyEndpoint, ProxyKind};
use crate::error::{Error, Result};
use crate::rules::{compile_rule, RuleAction, RuleInput, RuleProtocol};

impl Config {
    /// Load a `.ppx` or `.toml` file based on the extension.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::Config(format!("could not read {}: {err}", path.display())))?;
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "ppx" {
            Self::from_ppx_str(&text)
        } else {
            Self::from_toml_str(&text)
        }
    }

    /// Import a Proxifier profile.
    pub fn from_ppx_str(text: &str) -> Result<Self> {
        parse_ppx(text)?.into_config()
    }
}

struct Parsed {
    via_proxy: bool,
    udp_bypass: bool,
    exclusion: Vec<String>,
    proxies: Vec<PpxProxy>,
    rules: Vec<PpxRule>,
}

struct PpxProxy {
    id: String,
    kind: String,
    address: String,
    port: u16,
    username: String,
    password: String,
}

struct PpxRule {
    enabled: bool,
    name: String,
    action: String,
    proxy_id: String,
    targets: String,
    applications: String,
}

impl Parsed {
    fn into_config(self) -> Result<Config> {
        if self.proxies.is_empty() {
            return Err(Error::Config("Proxifier profile has no proxy".into()));
        }
        let mut proxies = Vec::new();
        let mut id_to_name = Vec::new();
        for (index, proxy) in self.proxies.iter().enumerate() {
            let name = if index == 0 {
                "default".to_string()
            } else {
                format!("proxy-{}", proxy.id)
            };
            id_to_name.push((proxy.id.clone(), name.clone()));
            let kind = match proxy.kind.to_ascii_lowercase().as_str() {
                "socks5" | "socks" => ProxyKind::Socks5,
                "http" | "https" => ProxyKind::Http,
                other => {
                    return Err(Error::Config(format!(
                        "Proxifier proxy type '{other}' is not supported (use SOCKS5 or HTTP)"
                    )))
                }
            };
            if proxy.address.is_empty() || proxy.port == 0 {
                return Err(Error::Config(format!(
                    "Proxifier proxy {} is missing an address or port",
                    proxy.id
                )));
            }
            proxies.push(ProxyEndpoint {
                name,
                kind,
                host: proxy.address.clone(),
                port: proxy.port,
                username: blank(&proxy.username),
                password: blank(&proxy.password),
                send_domain: self.via_proxy,
            });
        }
        let known: Vec<String> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
        let mut rules = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            let mut targets = rule.targets.clone();
            if rule.name.eq_ignore_ascii_case("localhost") {
                for extra in &self.exclusion {
                    if !list_contains(&targets, extra) {
                        if !targets.trim().is_empty() {
                            targets.push(';');
                        }
                        targets.push_str(extra);
                    }
                }
            }
            let action = match rule.action.to_ascii_lowercase().as_str() {
                "direct" => RuleAction::Direct,
                "block" => RuleAction::Block,
                "proxy" => RuleAction::Proxy,
                other => {
                    return Err(Error::Rule(format!(
                        "Proxifier action '{other}' is not supported"
                    )))
                }
            };
            let proxy_name = if action == RuleAction::Proxy {
                let id = rule.proxy_id.trim();
                let found = id_to_name.iter().find(|(pid, _)| pid == id);
                let Some((_, name)) = found else {
                    return Err(Error::Rule(format!(
                        "Proxifier rule '{}' points at missing proxy {id}",
                        rule.name
                    )));
                };
                if name == "default" {
                    None
                } else {
                    Some(name.clone())
                }
            } else {
                None
            };
            let protocol = if action == RuleAction::Proxy && self.udp_bypass {
                RuleProtocol::Tcp
            } else {
                RuleProtocol::Both
            };
            let name = if rule.name.trim().is_empty() {
                format!("rule-{}", index + 1)
            } else {
                rule.name.trim().to_string()
            };
            rules.push(compile_rule(
                RuleInput {
                    name,
                    process: unquote_list(&rule.applications),
                    hosts: targets,
                    ports: "*".into(),
                    protocol,
                    action,
                    proxy_name,
                    localhost: false,
                    enabled: rule.enabled,
                },
                &known,
            )?);
        }
        Ok(Config {
            enabled: true,
            dns_via_proxy: self.via_proxy,
            udp_bypass: self.udp_bypass,
            log_every_connection: false,
            proxies,
            rules,
            case_insensitive_process: cfg!(windows),
        })
    }
}

struct ParseState {
    stack: Vec<String>,
    saw_root: bool,
    via_proxy: bool,
    udp_bypass: bool,
    exclusion: Vec<String>,
    proxies: Vec<PpxProxy>,
    current_proxy: Option<PpxProxy>,
    rules: Vec<PpxRule>,
    current_rule: Option<PpxRule>,
}

fn parse_ppx(text: &str) -> Result<Parsed> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut state = ParseState {
        stack: Vec::new(),
        saw_root: false,
        via_proxy: false,
        udp_bypass: false,
        exclusion: Vec::new(),
        proxies: Vec::new(),
        current_proxy: None,
        rules: Vec::new(),
        current_rule: None,
    };

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|err| Error::Config(format!("could not parse Proxifier profile: {err}")))?;
        match event {
            Event::Start(element) => on_tag(&element, false, &mut state)?,
            Event::Empty(element) => on_tag(&element, true, &mut state)?,
            Event::Text(text) => {
                let value = text
                    .unescape()
                    .map_err(|err| Error::Config(format!("Proxifier text: {err}")))?
                    .into_owned();
                if value.is_empty() {
                    buf.clear();
                    continue;
                }
                let parent = state.stack.last().map(String::as_str).unwrap_or("");
                match parent {
                    "Port" => {
                        if let Some(proxy) = state.current_proxy.as_mut() {
                            proxy.port = value.trim().parse().map_err(|_| {
                                Error::Config(format!("invalid Proxifier port '{value}'"))
                            })?;
                        }
                    }
                    "Address" => {
                        if let Some(proxy) = state.current_proxy.as_mut() {
                            proxy.address = value.trim().to_string();
                        }
                    }
                    "Username" => {
                        if let Some(proxy) = state.current_proxy.as_mut() {
                            proxy.username = value;
                        }
                    }
                    "Password" => {
                        if let Some(proxy) = state.current_proxy.as_mut() {
                            proxy.password = value;
                        }
                    }
                    "Targets" => {
                        if let Some(rule) = state.current_rule.as_mut() {
                            rule.targets = value;
                        }
                    }
                    "Applications" => {
                        if let Some(rule) = state.current_rule.as_mut() {
                            rule.applications = value;
                        }
                    }
                    "Name" => {
                        if let Some(rule) = state.current_rule.as_mut() {
                            rule.name = value;
                        }
                    }
                    "Action" => {
                        if let Some(rule) = state.current_rule.as_mut() {
                            rule.proxy_id = value.trim().to_string();
                        }
                    }
                    "ExclusionList" => {
                        state.exclusion = split_list(&value);
                    }
                    _ => {}
                }
            }
            Event::End(element) => {
                let name = local_name(element.name().as_ref());
                if state.stack.last().map(String::as_str) == Some(name.as_str()) {
                    state.stack.pop();
                }
                if name == "Proxy" {
                    if let Some(proxy) = state.current_proxy.take() {
                        state.proxies.push(proxy);
                    }
                }
                if name == "Rule" {
                    if let Some(rule) = state.current_rule.take() {
                        state.rules.push(rule);
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !state.saw_root {
        return Err(Error::Config(
            "file is not a ProxifierProfile document".into(),
        ));
    }
    Ok(Parsed {
        via_proxy: state.via_proxy,
        udp_bypass: state.udp_bypass,
        exclusion: state.exclusion,
        proxies: state.proxies,
        rules: state.rules,
    })
}

fn on_tag(element: &BytesStart<'_>, empty: bool, state: &mut ParseState) -> Result<()> {
    let name = local_name(element.name().as_ref());
    let attrs = attributes(element);
    match name.as_str() {
        "ProxifierProfile" => state.saw_root = true,
        "ViaProxy" => {
            state.via_proxy = attr_bool(&attrs, "enabled");
        }
        "Udp" => {
            state.udp_bypass = attr(&attrs, "mode").eq_ignore_ascii_case("mode_bypass");
        }
        "Proxy" => {
            state.current_proxy = Some(PpxProxy {
                id: attr(&attrs, "id"),
                kind: attr(&attrs, "type"),
                address: String::new(),
                port: 0,
                username: String::new(),
                password: String::new(),
            });
        }
        "Rule" => {
            state.current_rule = Some(PpxRule {
                enabled: attr_bool(&attrs, "enabled"),
                name: String::new(),
                action: String::new(),
                proxy_id: String::new(),
                targets: String::new(),
                applications: String::new(),
            });
        }
        "Action" => {
            if let Some(rule) = state.current_rule.as_mut() {
                rule.action = attr(&attrs, "type");
            }
        }
        _ => {}
    }
    if empty {
        if name == "Proxy" {
            if let Some(proxy) = state.current_proxy.take() {
                state.proxies.push(proxy);
            }
        }
        if name == "Rule" {
            if let Some(rule) = state.current_rule.take() {
                state.rules.push(rule);
            }
        }
    } else {
        state.stack.push(name);
    }
    Ok(())
}

fn attributes(element: &BytesStart<'_>) -> Vec<(String, String)> {
    element
        .attributes()
        .flatten()
        .filter_map(|attr| {
            let key = local_name(attr.key.as_ref());
            let value = attr.unescape_value().ok()?.into_owned();
            Some((key, value))
        })
        .collect()
}

fn attr(attrs: &[(String, String)], key: &str) -> String {
    attrs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

fn attr_bool(attrs: &[(String, String)], key: &str) -> bool {
    matches!(
        attr(attrs, key).to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or("").to_string()
}

fn blank(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn split_list(text: &str) -> Vec<String> {
    text.split([';', ','])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn list_contains(list: &str, token: &str) -> bool {
    list.split([';', ','])
        .any(|item| item.trim().eq_ignore_ascii_case(token.trim()))
}

fn unquote_list(text: &str) -> String {
    text.split(';')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            let bytes = item.as_bytes();
            if bytes.len() >= 2
                && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
                    || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
            {
                item[1..item.len() - 1].to_string()
            } else {
                item.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionAction, Flow, Transport};
    use crate::rules::TEST_COMPUTER_NAMES;
    use std::net::IpAddr;

    fn flow(
        process: &str,
        host: Option<&str>,
        ip: Option<&str>,
        port: u16,
        proto: Transport,
    ) -> Flow {
        Flow {
            process_path: Some(process.into()),
            dest_ip: ip.map(|value| value.parse::<IpAddr>().unwrap()),
            dest_host: host.map(str::to_string),
            learned_names: Vec::new(),
            dest_port: port,
            protocol: proto,
        }
    }

    #[test]
    fn unquote_keeps_spaces_inside_quotes() {
        assert_eq!(
            unquote_list(r#"antigravity.exe; "antigravity ide.exe"; node.exe"#),
            "antigravity.exe;antigravity ide.exe;node.exe"
        );
    }

    #[test]
    fn attached_profile_keeps_proxy_order_and_udp_bypass() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../profiles/user-proxifier-profile.ppx");
        let cfg = Config::from_path(&path).unwrap();
        let proxy = cfg.primary();
        assert_eq!(proxy.kind, ProxyKind::Socks5);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 7898);
        assert!(!proxy.send_domain);
        assert!(!cfg.dns_via_proxy);
        assert!(cfg.udp_bypass);
        let antigravity = cfg
            .rules
            .iter()
            .find(|rule| rule.name == "Antigravity")
            .unwrap();
        assert!(!antigravity.enabled);

        let names = TEST_COMPUTER_NAMES.lock().unwrap();
        drop(names);
        *TEST_COMPUTER_NAMES.lock().unwrap() = Some(vec!["DESKTOP-TEST".into()]);
        let local = cfg.decide(&flow(
            "curl.exe",
            Some("DESKTOP-TEST"),
            None,
            443,
            Transport::Tcp,
        ));
        assert_eq!(local.action, DecisionAction::Direct);
        assert_eq!(local.rule.as_deref(), Some("Localhost"));
        *TEST_COMPUTER_NAMES.lock().unwrap() = None;

        assert_eq!(
            cfg.decide(&flow(
                "svchost.exe",
                Some("api.github.com"),
                None,
                443,
                Transport::Tcp,
            ))
            .rule
            .as_deref(),
            Some("svchost.exe [auto-created]")
        );
        assert_eq!(
            cfg.decide(&flow(
                "verge-mihomo.exe",
                Some("api.openai.com"),
                None,
                443,
                Transport::Tcp,
            ))
            .action,
            DecisionAction::Direct
        );
        assert_eq!(
            cfg.decide(&flow(
                "msedge.exe",
                Some("www.google.com"),
                None,
                443,
                Transport::Tcp,
            ))
            .rule
            .as_deref(),
            Some("Edge")
        );
        let dev = cfg.decide(&flow(
            "curl.exe",
            Some("api.github.com"),
            None,
            443,
            Transport::Tcp,
        ));
        assert!(matches!(dev.action, DecisionAction::Proxy(_)));
        assert_eq!(dev.rule.as_deref(), Some("Dev"));
        let ai = cfg.decide(&flow(
            "curl.exe",
            Some("api.openai.com"),
            None,
            443,
            Transport::Tcp,
        ));
        assert_eq!(ai.rule.as_deref(), Some("AI"));
        let game = cfg.decide(&flow(
            "curl.exe",
            Some("store.steampowered.com"),
            None,
            443,
            Transport::Tcp,
        ));
        assert_eq!(game.rule.as_deref(), Some("Game"));
        assert_eq!(
            cfg.decide(&flow(
                "curl.exe",
                Some("api.github.com"),
                None,
                443,
                Transport::Udp,
            ))
            .reason,
            "udp bypass"
        );
        assert_eq!(
            cfg.decide(&flow(
                "antigravity.exe",
                Some("example.com"),
                None,
                443,
                Transport::Tcp,
            ))
            .rule
            .as_deref(),
            Some("Default")
        );
        assert_eq!(
            cfg.decide(&flow(
                "curl.exe",
                Some("example.com"),
                None,
                80,
                Transport::Tcp
            ))
            .rule
            .as_deref(),
            Some("Default")
        );

        let toml = Config::from_path(&path.with_file_name("user-proxifier-profile.toml")).unwrap();
        assert_eq!(toml.primary().port, 7898);
        assert!(toml.udp_bypass);
        assert!(
            !toml
                .rules
                .iter()
                .find(|rule| rule.name == "Antigravity")
                .unwrap()
                .enabled
        );
        assert_eq!(
            toml.decide(&flow(
                "curl.exe",
                Some("api.github.com"),
                None,
                443,
                Transport::Tcp,
            ))
            .rule
            .as_deref(),
            Some("Dev")
        );
    }
}
