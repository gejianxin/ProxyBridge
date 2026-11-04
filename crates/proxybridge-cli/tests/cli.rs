use std::process::Command;

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_proxybridge"));
    for key in [
        "PROXYBRIDGE_CONFIG",
        "PROXYBRIDGE_PROXY_TYPE",
        "PROXYBRIDGE_PROXY_HOST",
        "PROXYBRIDGE_PROXY_PORT",
        "PROXYBRIDGE_PROXY_USERNAME",
        "PROXYBRIDGE_PROXY_PASSWORD",
        "PROXYBRIDGE_SEND_DOMAIN",
        "PROXYBRIDGE_DNS_VIA_PROXY",
        "PROXYBRIDGE_ENABLED",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

#[test]
fn builtin_decision_is_socks5_on_127_0_0_1_7898() {
    let output = bin()
        .args([
            "decide",
            "--no-config",
            "--dest",
            "8.8.8.8:443",
            "--process",
            "curl",
            "--proto",
            "tcp",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("action=proxy"));
    assert!(text.contains("proxy=socks5://127.0.0.1:7898"));
    assert!(text.contains("rule=default"));
}

#[test]
fn environment_overrides_the_port_and_cli_wins() {
    let output = bin()
        .env("PROXYBRIDGE_PROXY_PORT", "7000")
        .args(["config", "--no-config"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{text}");
    assert!(text.contains("socks5://127.0.0.1:7000"), "{text}");

    let output = bin()
        .env("PROXYBRIDGE_PROXY_PORT", "7000")
        .args(["config", "--no-config", "--proxy-port", "7898"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{text}");
    assert!(text.contains("socks5://127.0.0.1:7898"), "{text}");
}

#[test]
fn example_file_and_loopback_stay_documented() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proxybridge.toml");
    let output = bin()
        .args(["config", "--config"])
        .arg(&root)
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("socks5://127.0.0.1:7898"), "{text}");

    let output = bin()
        .args([
            "decide",
            "--no-config",
            "--dest",
            "127.0.0.1:80",
            "--proto",
            "tcp",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("action=direct"), "{text}");
    assert!(text.contains("reason=loopback"), "{text}");
}

#[test]
fn backends_and_iptables_are_honest() {
    let output = bin().arg("backends").output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{text}");
    assert!(text.contains("windivert"));
    assert!(text.contains("stub"));
    assert!(text.contains("network-extension"));
    assert!(text.contains("socks"));

    let output = bin()
        .args(["iptables", "--no-config", "--listen-port", "34010"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--dport 7898"), "{text}");
    assert!(text.contains("--to-ports 34010"), "{text}");
}
