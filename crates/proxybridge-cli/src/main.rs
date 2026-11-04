//! ProxyBridge command line.
//!
//! Copyright (c) 2025 Anof-cyber/InterceptSuite, MIT License.
//! This Rust port is distributed under the same license.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use proxybridge_core::{
    overrides_from_env, parse_proxy_spec, Config, DecisionAction, Flow, Overrides, ProxyKind,
    Transport,
};
use proxybridge_platform::{backend_lines, iptables_script, LocalSocks, RedirectProxy};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "proxybridge",
    version,
    about = "Route application TCP/UDP through a SOCKS5 or HTTP proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen and apply proxy rules.
    Run(RunArgs),
    /// Print the decision for one destination.
    Decide(DecideArgs),
    /// Print the effective configuration. Passwords are omitted.
    Config(CommonArgs),
    /// Print Linux iptables REDIRECT rules for transparent TCP.
    Iptables(IptablesArgs),
    /// Show which backends this build actually implements.
    Backends,
}

#[derive(Args, Debug)]
struct CommonArgs {
    /// TOML configuration file. Defaults to ./proxybridge.toml when that file exists.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Ignore ./proxybridge.toml and PROXYBRIDGE_CONFIG; start from built-in defaults.
    #[arg(long)]
    no_config: bool,
    /// socks5://host:port, http://host:port, or host:port (SOCKS5).
    #[arg(long)]
    proxy: Option<String>,
    /// socks5 or http. Overrides the type in --proxy.
    #[arg(long)]
    proxy_type: Option<String>,
    #[arg(long)]
    proxy_host: Option<String>,
    #[arg(long)]
    proxy_port: Option<u16>,
    #[arg(long)]
    proxy_user: Option<String>,
    #[arg(long)]
    proxy_pass: Option<String>,
    /// Send domain names to the proxy (true) or resolve locally first (false).
    #[arg(long)]
    send_domain: Option<String>,
    /// Proxy DNS (port 53) instead of leaving it direct.
    #[arg(long)]
    dns_via_proxy: Option<String>,
}

#[derive(Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// socks (every OS) or redirect (Linux transparent TCP).
    #[arg(long, default_value = "socks")]
    mode: String,
    /// Listen address. Defaults to 127.0.0.1:2080 for socks and 127.0.0.1:34010 for redirect.
    #[arg(long)]
    listen: Option<String>,
    /// 0 warnings, 1-2 info (connections), 3 debug. RUST_LOG overrides this.
    #[arg(long, default_value_t = 1)]
    verbose: u8,
}

#[derive(Args, Debug)]
struct DecideArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Executable path or file name. Omit it to test rules that match any process.
    #[arg(long)]
    process: Option<String>,
    /// ip:port, [ipv6]:port, or host:port.
    #[arg(long)]
    dest: String,
    /// Optional domain learned for an IP destination.
    #[arg(long)]
    host: Option<String>,
    /// tcp or udp.
    #[arg(long, default_value = "tcp")]
    proto: String,
}

#[derive(Args, Debug)]
struct IptablesArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Port the redirect listener uses.
    #[arg(long, default_value_t = 34010)]
    listen_port: u16,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Run(args) => cmd_run(args).await?,
        Command::Decide(args) => {
            let config = load_config(&args.common)?;
            println!("{}", decide_line(&config, &args)?);
        }
        Command::Config(args) => {
            let config = load_config(&args)?;
            print!("{}", config.summary());
        }
        Command::Iptables(args) => {
            let config = load_config(&args.common)?;
            let proxy = config.primary();
            print!(
                "{}",
                iptables_script(args.listen_port, &proxy.host, proxy.port)
            );
        }
        Command::Backends => print!("{}", backend_lines()),
    }
    Ok(())
}

async fn cmd_run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.verbose > 3 {
        return Err("verbose must be 0, 1, 2, or 3".into());
    }
    init_tracing(args.verbose);
    let config = Arc::new(load_config(&args.common)?);
    let proxy = config.primary().label();
    match args.mode.as_str() {
        "socks" | "local-socks" => {
            let listen = parse_listen(args.listen.as_deref(), "127.0.0.1:2080")?;
            if !is_loopback(listen) {
                tracing::warn!(%listen, "SOCKS inbound is not limited to loopback");
            }
            let server = LocalSocks::spawn(listen, Arc::clone(&config)).await?;
            println!(
                "proxybridge listening on socks5://{} upstream {proxy}",
                server.local_addr()
            );
            wait_for_shutdown().await;
            server.shutdown().await?;
        }
        "redirect" | "transparent" => {
            let listen = parse_listen(args.listen.as_deref(), "127.0.0.1:34010")?;
            let server = RedirectProxy::spawn(listen, Arc::clone(&config)).await?;
            println!(
                "proxybridge redirect listening on {} upstream {proxy}",
                server.local_addr()
            );
            println!(
                "{}",
                iptables_script(
                    server.local_addr().port(),
                    &config.primary().host,
                    config.primary().port
                )
            );
            wait_for_shutdown().await;
            server.shutdown().await?;
        }
        other => {
            return Err(format!("unknown mode '{other}' (expected socks or redirect)").into());
        }
    }
    Ok(())
}

fn decide_line(config: &Config, args: &DecideArgs) -> Result<String, Box<dyn std::error::Error>> {
    let proto = Transport::parse(&args.proto)
        .ok_or_else(|| format!("unknown protocol '{}' (expected tcp or udp)", args.proto))?;
    let dest = parse_dest(&args.dest)?;
    let flow = Flow {
        process_path: args.process.clone(),
        dest_ip: dest.ip,
        dest_host: args.host.clone().or(dest.host),
        dest_port: dest.port,
        protocol: proto,
    };
    let decision = config.decide(&flow);
    let (action, proxy) = match &decision.action {
        DecisionAction::Direct => ("direct", "-".to_string()),
        DecisionAction::Block => ("block", "-".to_string()),
        DecisionAction::Proxy(endpoint) => ("proxy", endpoint.label()),
    };
    Ok(format!(
        "action={action} rule={} proxy={proxy} reason={} dest={} proto={}",
        decision.rule.as_deref().unwrap_or("-"),
        decision.reason,
        flow.dest_display(),
        proto.as_str()
    ))
}

fn load_config(args: &CommonArgs) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = match resolve_path(args)? {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|err| format!("could not read {}: {err}", path.display()))?;
            Config::from_toml_str(&text)?
        }
        None => Config::builtin(),
    };
    config.apply_overrides(&overrides_from_env()?)?;
    config.apply_overrides(&cli_overrides(args)?)?;
    Ok(config)
}

fn resolve_path(args: &CommonArgs) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    if args.no_config {
        return Ok(None);
    }
    if let Some(path) = &args.config {
        return Ok(Some(path.clone()));
    }
    if let Ok(path) = std::env::var("PROXYBRIDGE_CONFIG") {
        if !path.is_empty() {
            return Ok(Some(PathBuf::from(path)));
        }
    }
    let local = PathBuf::from("proxybridge.toml");
    if local.is_file() {
        return Ok(Some(local));
    }
    Ok(None)
}

fn cli_overrides(args: &CommonArgs) -> Result<Overrides, Box<dyn std::error::Error>> {
    let mut over = Overrides::default();
    if let Some(spec) = &args.proxy {
        let (kind, host, port) = parse_proxy_spec(spec)?;
        over.proxy_type = Some(kind);
        over.proxy_host = Some(host);
        over.proxy_port = Some(port);
    }
    if let Some(kind) = &args.proxy_type {
        over.proxy_type = Some(ProxyKind::parse(kind)?);
    }
    if let Some(host) = &args.proxy_host {
        over.proxy_host = Some(host.clone());
    }
    if let Some(port) = args.proxy_port {
        over.proxy_port = Some(port);
    }
    if let Some(user) = &args.proxy_user {
        over.proxy_username = Some(user.clone());
    }
    if let Some(pass) = &args.proxy_pass {
        over.proxy_password = Some(pass.clone());
    }
    if let Some(value) = &args.send_domain {
        over.send_domain = Some(parse_bool(value)?);
    }
    if let Some(value) = &args.dns_via_proxy {
        over.dns_via_proxy = Some(parse_bool(value)?);
    }
    Ok(over)
}

fn parse_bool(text: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("expected true or false, got '{other}'").into()),
    }
}

fn parse_listen(
    text: Option<&str>,
    default: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let text = text.unwrap_or(default);
    text.parse::<SocketAddr>()
        .map_err(|err| format!("invalid listen address '{text}': {err}").into())
}

fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

struct ParsedDest {
    ip: Option<std::net::IpAddr>,
    host: Option<String>,
    port: u16,
}

fn parse_dest(text: &str) -> Result<ParsedDest, Box<dyn std::error::Error>> {
    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(format!("invalid destination '{text}'").into());
        };
        (host.to_string(), port)
    } else {
        let Some((host, port)) = text.rsplit_once(':') else {
            return Err(format!("invalid destination '{text}' (expected host:port)").into());
        };
        (host.to_string(), port)
    };
    if host.is_empty() || !port_text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid destination '{text}'").into());
    }
    let port: u32 = port_text
        .parse()
        .map_err(|_| format!("invalid destination '{text}'"))?;
    if port == 0 || port > 65535 {
        return Err(format!("invalid port in '{text}'").into());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(ParsedDest {
            ip: Some(ip),
            host: None,
            port: port as u16,
        })
    } else {
        Ok(ParsedDest {
            ip: None,
            host: Some(host),
            port: port as u16,
        })
    }
}

fn init_tracing(verbose: u8) {
    let fallback = match verbose {
        0 => "warn",
        1 | 2 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn wait_for_shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(err) => {
                tracing::warn!(error = %err, "SIGTERM handler was not installed");
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            result = ctrl_c => {
                if let Err(err) = result {
                    tracing::warn!(error = %err, "ctrl-c handler failed");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = ctrl_c.await {
            tracing::warn!(error = %err, "ctrl-c handler failed");
        }
    }
}
