//! Shared connect-and-relay path used by the SOCKS inbound and Linux redirect.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proxybridge_core::{
    client_handshake, http_connect, splice_tcp, Config, Decision, DecisionAction, Flow, ProxyKind,
    SocksTarget, Transport, CMD_CONNECT,
};
use tokio::net::{lookup_host, TcpSocket, TcpStream};

use crate::process::lookup_peer_process;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("{0}")]
    Unavailable(&'static str),
    #[error(transparent)]
    Core(#[from] proxybridge_core::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("blocked by rule")]
    Blocked,
    #[error("connection refused: {0}")]
    Refused(String),
    #[error("unreachable: {0}")]
    Unreachable(String),
    #[error("{0}")]
    Failed(String),
}

impl OpenError {
    pub fn socks_rep(&self) -> u8 {
        match self {
            OpenError::Blocked => proxybridge_core::REP_NOT_ALLOWED,
            OpenError::Refused(_) => proxybridge_core::REP_REFUSED,
            OpenError::Unreachable(_) => proxybridge_core::REP_HOST_UNREACHABLE,
            OpenError::Failed(_) => 0x01,
        }
    }
}

pub struct Runtime {
    pub config: Arc<Config>,
    dedup: Mutex<HashSet<String>>,
    pub fwmark: bool,
}

impl Runtime {
    pub fn new(config: Arc<Config>, fwmark: bool) -> Self {
        Self {
            config,
            dedup: Mutex::new(HashSet::new()),
            fwmark,
        }
    }

    pub fn log_decision(&self, flow: &Flow, decision: &Decision) {
        let action = action_name(&decision.action);
        let proxy = match &decision.action {
            DecisionAction::Proxy(endpoint) => endpoint.label(),
            _ => "-".into(),
        };
        let key = format!(
            "{}|{}|{}|{action}|{proxy}",
            flow.process_path.as_deref().unwrap_or("-"),
            flow.dest_display(),
            flow.protocol.as_str()
        );
        if !self.config.log_every_connection {
            let mut seen = self.dedup.lock().unwrap_or_else(|err| err.into_inner());
            if !seen.insert(key) {
                return;
            }
        }
        tracing::info!(
            process = flow.process_path.as_deref().unwrap_or("-"),
            dest = %flow.dest_display(),
            proto = flow.protocol.as_str(),
            action,
            proxy = %proxy,
            rule = decision.rule.as_deref().unwrap_or("-"),
            reason = %decision.reason,
            "flow"
        );
    }

    pub async fn open_tcp(
        &self,
        decision: &Decision,
        target: &SocksTarget,
    ) -> Result<TcpStream, OpenError> {
        match &decision.action {
            DecisionAction::Block => Err(OpenError::Blocked),
            DecisionAction::Direct => connect_target(target, self.fwmark).await.map_err(map_io),
            DecisionAction::Proxy(proxy) => self.open_proxy(proxy, target).await,
        }
    }

    async fn open_proxy(
        &self,
        proxy: &proxybridge_core::ProxyEndpoint,
        target: &SocksTarget,
    ) -> Result<TcpStream, OpenError> {
        let mut stream = connect_host(&proxy.host, proxy.port, self.fwmark)
            .await
            .map_err(map_io)?;
        let via = tunnel_target(proxy, target).await?;
        match proxy.kind {
            ProxyKind::Socks5 => {
                client_handshake(&mut stream, proxy, &via, CMD_CONNECT)
                    .await
                    .map_err(map_core)?;
            }
            ProxyKind::Http => {
                let (host, port) = http_host(&via);
                http_connect(&mut stream, proxy, &host, port)
                    .await
                    .map_err(map_core)?;
            }
        }
        Ok(stream)
    }
}

pub async fn build_flow(
    config: &Config,
    process: Option<String>,
    target: &SocksTarget,
    protocol: Transport,
) -> Flow {
    let mut flow = Flow {
        process_path: process,
        dest_ip: target.ip(),
        dest_host: target.domain().map(str::to_string),
        dest_port: target.port(),
        protocol,
    };
    if flow.dest_ip.is_none() && config.needs_ip_for_domain_match() {
        if let Some(host) = flow.dest_host.clone() {
            if let Ok(addr) = lookup_first(&host, flow.dest_port).await {
                flow.dest_ip = Some(addr.ip());
            }
        }
    }
    flow
}

pub fn process_path_for(peer: SocketAddr) -> Option<String> {
    lookup_peer_process(peer).and_then(|info| {
        if info.exe.is_empty() {
            None
        } else {
            Some(info.exe)
        }
    })
}

pub async fn relay_tcp(
    rt: &Runtime,
    mut client: TcpStream,
    peer: SocketAddr,
    target: SocksTarget,
    socks_reply: bool,
) -> Result<(), BridgeError> {
    let flow = build_flow(&rt.config, process_path_for(peer), &target, Transport::Tcp).await;
    let decision = rt.config.decide(&flow);
    rt.log_decision(&flow, &decision);
    match rt.open_tcp(&decision, &target).await {
        Ok(mut upstream) => {
            if socks_reply {
                let bound = proxybridge_core::SocksAddr::Ip(SocketAddr::from((
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )));
                proxybridge_core::server_write_reply(&mut client, proxybridge_core::REP_OK, &bound)
                    .await?;
            }
            let (sent, received) = splice_tcp(&mut client, &mut upstream).await?;
            tracing::debug!(sent, received, "relay closed");
            Ok(())
        }
        Err(err) => {
            tracing::warn!(dest = %target.display(), error = %err, "could not open destination");
            if socks_reply {
                let bound = proxybridge_core::SocksAddr::Ip(SocketAddr::from((
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )));
                let _ = proxybridge_core::server_write_reply(&mut client, err.socks_rep(), &bound)
                    .await;
            }
            Ok(())
        }
    }
}

fn action_name(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Direct => "direct",
        DecisionAction::Block => "block",
        DecisionAction::Proxy(_) => "proxy",
    }
}

async fn tunnel_target(
    proxy: &proxybridge_core::ProxyEndpoint,
    target: &SocksTarget,
) -> Result<SocksTarget, OpenError> {
    match target {
        SocksTarget::Domain(host, port) if !proxy.send_domain => {
            let addr = lookup_first(host, *port).await.map_err(map_io)?;
            Ok(SocksTarget::from_socket_addr(addr))
        }
        other => Ok(other.clone()),
    }
}

fn http_host(target: &SocksTarget) -> (String, u16) {
    match target {
        SocksTarget::Domain(host, port) => (host.clone(), *port),
        SocksTarget::V4(ip, port) => (ip.to_string(), *port),
        SocksTarget::V6(ip, port) => (ip.to_string(), *port),
    }
}

pub async fn connect_host(host: &str, port: u16, fwmark: bool) -> io::Result<TcpStream> {
    connect_target(&SocksTarget::Domain(host.to_string(), port), fwmark).await
}

async fn connect_target(target: &SocksTarget, fwmark: bool) -> io::Result<TcpStream> {
    let addrs = match target {
        SocksTarget::V4(ip, port) => vec![SocketAddr::from((*ip, *port))],
        SocksTarget::V6(ip, port) => vec![SocketAddr::from((*ip, *port))],
        SocksTarget::Domain(host, port) => {
            let looked =
                tokio::time::timeout(Duration::from_secs(10), lookup_host((host.as_str(), *port)))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "dns lookup timed out")
                    })??;
            let addrs: Vec<SocketAddr> = looked.collect();
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no addresses for {host}"),
                ));
            }
            addrs
        }
    };
    let mut last = None;
    for addr in addrs {
        match connect_addr(addr, fwmark).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "connect failed")))
}

async fn connect_addr(addr: SocketAddr, fwmark: bool) -> io::Result<TcpStream> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let _ = sock.set_nodelay(true);
    #[cfg(target_os = "linux")]
    if fwmark {
        use std::os::fd::AsRawFd;
        crate::linux_net::set_fwmark(sock.as_raw_fd())?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fwmark;
    }
    match tokio::time::timeout(Duration::from_secs(10), sock.connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

async fn lookup_first(host: &str, port: u16) -> io::Result<SocketAddr> {
    let mut looked = tokio::time::timeout(Duration::from_secs(2), lookup_host((host, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns lookup timed out"))??;
    looked
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {host}")))
}

fn map_io(err: io::Error) -> OpenError {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => OpenError::Refused(err.to_string()),
        io::ErrorKind::TimedOut
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NotFound => OpenError::Unreachable(err.to_string()),
        _ => classify_text(err.to_string()),
    }
}

fn map_core(err: proxybridge_core::Error) -> OpenError {
    classify_text(err.to_string())
}

fn classify_text(text: String) -> OpenError {
    let lower = text.to_ascii_lowercase();
    if lower.contains("connection refused") {
        OpenError::Refused(text)
    } else if lower.contains("unreachable") || lower.contains("timed out") {
        OpenError::Unreachable(text)
    } else {
        OpenError::Failed(text)
    }
}
