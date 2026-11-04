use std::net::IpAddr;

use proxybridge_core::LINUX_FW_MARK;

/// Shell snippet that diverts locally generated IPv4 TCP into the redirect listener.
///
/// The mark rule is the loop brake: ProxyBridge sets `SO_MARK` on sockets it
/// opens, and those packets RETURN before REDIRECT. IPv6 and UDP are not covered.
pub fn iptables_script(listen_port: u16, proxy_host: &str, proxy_port: u16) -> String {
    let mark = LINUX_FW_MARK;
    let mut out = String::new();
    out.push_str(
        "# IPv4 TCP redirect for ProxyBridge. IPv6 and transparent UDP are not generated.\n",
    );
    out.push_str(
        "# Apply as root. The mark keeps ProxyBridge's own sockets out of the redirect.\n",
    );
    out.push_str(&format!(
        "iptables -t nat -C OUTPUT -p tcp -m mark --mark {mark} -j RETURN 2>/dev/null || iptables -t nat -A OUTPUT -p tcp -m mark --mark {mark} -j RETURN\n"
    ));
    if proxy_host.parse::<IpAddr>().is_ok() {
        out.push_str(&format!(
            "iptables -t nat -C OUTPUT -p tcp -d {proxy_host} --dport {proxy_port} -j RETURN 2>/dev/null || iptables -t nat -A OUTPUT -p tcp -d {proxy_host} --dport {proxy_port} -j RETURN\n"
        ));
    } else {
        out.push_str(&format!(
            "# Proxy host {proxy_host} is a name, not an address. The mark rule is what prevents a tunnel loop.\n"
        ));
    }
    out.push_str(&format!(
        "iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports {listen_port}\n"
    ));
    out.push_str("\n# Remove with:\n");
    out.push_str(&format!(
        "# iptables -t nat -D OUTPUT -p tcp -m mark --mark {mark} -j RETURN\n"
    ));
    if proxy_host.parse::<IpAddr>().is_ok() {
        out.push_str(&format!(
            "# iptables -t nat -D OUTPUT -p tcp -d {proxy_host} --dport {proxy_port} -j RETURN\n"
        ));
    }
    out.push_str(&format!(
        "# iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports {listen_port}\n"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_mentions_the_default_proxy_and_mark() {
        let text = iptables_script(34010, "127.0.0.1", 7898);
        assert!(text.contains("--to-ports 34010"));
        assert!(text.contains("-d 127.0.0.1"));
        assert!(text.contains("--dport 7898"));
        assert!(text.contains("--mark 1"));
        assert!(text.contains("REDIRECT"));
    }
}
