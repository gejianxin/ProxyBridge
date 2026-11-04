//! First-match rule evaluation plus the implicit direct exceptions.

use std::net::IpAddr;

use crate::config::{Config, ProxyEndpoint};
use crate::rules::{is_hard_implicit, is_loopback, rule_matches, RuleAction};

/// TCP or UDP. Rule lists say "both" when they apply to either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Transport::Tcp),
            "udp" => Some(Transport::Udp),
            _ => None,
        }
    }
}

/// One flow presented to the matcher.
#[derive(Debug, Clone)]
pub struct Flow {
    pub process_path: Option<String>,
    pub dest_ip: Option<IpAddr>,
    pub dest_host: Option<String>,
    /// Names learned from DNS replies for `dest_ip`. Domain rules match any of them.
    pub learned_names: Vec<String>,
    pub dest_port: u16,
    pub protocol: Transport,
}

impl Flow {
    pub fn dest_display(&self) -> String {
        let host = if let Some(host) = &self.dest_host {
            host.clone()
        } else if let Some(ip) = self.dest_ip {
            ip.to_string()
        } else {
            "-".into()
        };
        format!("{host}:{}", self.dest_port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionAction {
    Direct,
    Block,
    Proxy(ProxyEndpoint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: DecisionAction,
    pub rule: Option<String>,
    pub reason: String,
}

impl Config {
    pub fn decide(&self, flow: &Flow) -> Decision {
        if !self.enabled {
            return direct(None, "bridge disabled");
        }
        if self.is_proxy_dest(flow.dest_port, flow.dest_ip, flow.dest_host.as_deref()) {
            return direct(None, "destination is the configured proxy");
        }
        if is_hard_implicit(flow.dest_ip) {
            return direct(None, "implicit direct");
        }
        if flow.protocol == Transport::Udp && (flow.dest_port == 67 || flow.dest_port == 68) {
            return direct(None, "implicit direct");
        }
        if flow.dest_port == 53 && !self.dns_via_proxy {
            return direct(None, "implicit direct");
        }
        if self.udp_bypass && flow.protocol == Transport::Udp {
            return direct(None, "udp bypass");
        }

        let tcp = flow.protocol == Transport::Tcp;
        let matched = self.rules.iter().find(|rule| {
            rule_matches(
                rule,
                flow.process_path.as_deref(),
                flow.dest_ip,
                crate::rules::NameSet {
                    host: flow.dest_host.as_deref(),
                    extra: &flow.learned_names,
                },
                flow.dest_port,
                tcp,
                self.case_insensitive_process,
            )
        });

        let loopback = is_loopback(flow.dest_ip, flow.dest_host.as_deref());
        let Some(rule) = matched else {
            if loopback {
                return direct(None, "loopback");
            }
            return direct(None, "no matching rule");
        };

        if loopback && !(rule.action == RuleAction::Proxy && rule.localhost) {
            return direct(Some(rule.name.clone()), "loopback");
        }

        match rule.action {
            RuleAction::Direct => direct(Some(rule.name.clone()), "rule"),
            RuleAction::Block => Decision {
                action: DecisionAction::Block,
                rule: Some(rule.name.clone()),
                reason: "rule".into(),
            },
            RuleAction::Proxy => {
                let proxy = self.proxy_named(rule.proxy_name.as_deref()).clone();
                Decision {
                    action: DecisionAction::Proxy(proxy),
                    rule: Some(rule.name.clone()),
                    reason: "rule".into(),
                }
            }
        }
    }
}

fn direct(rule: Option<String>, reason: &str) -> Decision {
    Decision {
        action: DecisionAction::Direct,
        rule,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ProxyKind};

    fn flow(ip: &str, port: u16, proto: Transport) -> Flow {
        Flow {
            process_path: Some("curl".into()),
            dest_ip: Some(ip.parse().unwrap()),
            dest_host: None,
            learned_names: Vec::new(),
            dest_port: port,
            protocol: proto,
        }
    }

    #[test]
    fn default_proxies_public_tcp_and_keeps_exceptions_direct() {
        let cfg = Config::builtin();
        let d = cfg.decide(&flow("8.8.8.8", 443, Transport::Tcp));
        match d.action {
            DecisionAction::Proxy(p) => {
                assert_eq!(p.kind, ProxyKind::Socks5);
                assert_eq!(p.host, "127.0.0.1");
                assert_eq!(p.port, 7898);
            }
            other => panic!("expected proxy, got {other:?}"),
        }
        assert_eq!(
            cfg.decide(&flow("127.0.0.1", 80, Transport::Tcp)).action,
            DecisionAction::Direct
        );
        assert_eq!(
            cfg.decide(&flow("127.0.0.1", 7898, Transport::Tcp)).reason,
            "destination is the configured proxy"
        );
        assert_eq!(
            cfg.decide(&flow("224.0.0.1", 9, Transport::Udp)).reason,
            "implicit direct"
        );
        assert_eq!(
            cfg.decide(&flow("1.1.1.1", 53, Transport::Udp)).reason,
            "implicit direct"
        );
        assert_eq!(
            cfg.decide(&flow("255.255.255.255", 9, Transport::Udp))
                .reason,
            "implicit direct"
        );
    }

    #[test]
    fn localhost_flag_and_dns_switch_and_first_match() {
        let cfg = Config::from_toml_str(
            r#"
dns_via_proxy = true
[[rules]]
name = "block-browser"
process = "chrome,firefox"
action = "block"
[[rules]]
name = "lan"
hosts = "10.0.0.0/8"
action = "direct"
[[rules]]
name = "rest"
localhost = true
action = "proxy"
"#,
        )
        .unwrap();

        let mut browser = flow("8.8.8.8", 443, Transport::Tcp);
        browser.process_path = Some("/usr/bin/firefox".into());
        assert_eq!(cfg.decide(&browser).action, DecisionAction::Block);

        assert_eq!(
            cfg.decide(&flow("10.1.2.3", 22, Transport::Tcp)).action,
            DecisionAction::Direct
        );
        assert!(matches!(
            cfg.decide(&flow("127.0.0.1", 9, Transport::Tcp)).action,
            DecisionAction::Proxy(_)
        ));
        assert!(matches!(
            cfg.decide(&flow("1.1.1.1", 53, Transport::Tcp)).action,
            DecisionAction::Proxy(_)
        ));

        let mut off = cfg.clone();
        off.enabled = false;
        assert_eq!(
            off.decide(&flow("8.8.8.8", 443, Transport::Tcp)).reason,
            "bridge disabled"
        );
    }

    #[test]
    fn domain_rule_matches_the_name_when_the_address_is_also_known() {
        let cfg = Config::from_toml_str(
            r#"
[[rules]]
name = "example"
hosts = "*.example.com"
ports = "443"
action = "proxy"
[[rules]]
name = "other"
action = "direct"
"#,
        )
        .unwrap();
        let flow = Flow {
            process_path: Some("app".into()),
            dest_ip: Some("93.184.216.34".parse().unwrap()),
            dest_host: Some("www.example.com".into()),
            learned_names: Vec::new(),
            dest_port: 443,
            protocol: Transport::Tcp,
        };
        let d = cfg.decide(&flow);
        assert_eq!(d.rule.as_deref(), Some("example"));
        assert!(matches!(d.action, DecisionAction::Proxy(_)));
    }

    #[test]
    fn learned_dns_name_matches_a_domain_rule() {
        let cfg = Config::from_toml_str(
            r#"
[[rules]]
name = "example"
hosts = "*.example.com"
action = "proxy"
[[rules]]
name = "other"
action = "direct"
"#,
        )
        .unwrap();
        let flow = Flow {
            process_path: Some("app".into()),
            dest_ip: Some("93.184.216.34".parse().unwrap()),
            dest_host: None,
            learned_names: vec!["www.example.com".into()],
            dest_port: 443,
            protocol: Transport::Tcp,
        };
        let d = cfg.decide(&flow);
        assert_eq!(d.rule.as_deref(), Some("example"));
        assert!(matches!(d.action, DecisionAction::Proxy(_)));
    }
}
