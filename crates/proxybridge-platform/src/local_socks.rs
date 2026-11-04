//! Userspace SOCKS5 inbound. This is the backend that runs on every target.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use proxybridge_core::{
    encode_udp, parse_udp, server_negotiate, server_read_request, server_write_reply, Config,
    DecisionAction, ProxyKind, Socks5Udp, SocksAddr, SocksTarget, Transport, CMD_CONNECT,
    CMD_UDP_ASSOCIATE, REP_OK,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::bridge::{build_flow, connect_host, process_path_for, relay_tcp, BridgeError, Runtime};

pub struct LocalSocks {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), BridgeError>>>,
}

impl LocalSocks {
    pub async fn spawn(listen: SocketAddr, config: Arc<Config>) -> Result<Self, BridgeError> {
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let (tx, rx) = watch::channel(false);
        let runtime = Arc::new(Runtime::new(config, false));
        let task = tokio::spawn(async move { serve(listener, runtime, rx).await });
        tracing::info!(%local_addr, mode = "socks", "listening");
        Ok(Self {
            local_addr,
            shutdown_tx: tx,
            task: Some(task),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) -> Result<(), BridgeError> {
        let _ = self.shutdown_tx.send(true);
        let task = self.task.take();
        drop(self);
        match task {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(err) if err.is_cancelled() => Ok(()),
                Err(err) => Err(BridgeError::Failed(err.to_string())),
            },
            None => Ok(()),
        }
    }
}

impl Drop for LocalSocks {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn serve(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (sock, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "accept failed");
                        continue;
                    }
                };
                let runtime = Arc::clone(&runtime);
                clients.spawn(async move {
                    if let Err(err) = handle_client(sock, peer, runtime).await {
                        tracing::debug!(%peer, error = %err, "socks client ended");
                    }
                });
            }
        }
    }
    clients.abort_all();
    Ok(())
}

async fn handle_client(
    mut sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
) -> Result<(), BridgeError> {
    let _ = sock.set_nodelay(true);
    server_negotiate(&mut sock).await?;
    let request = server_read_request(&mut sock).await?;
    match request.command {
        CMD_CONNECT => relay_tcp(&runtime, sock, peer, request.target, true).await,
        CMD_UDP_ASSOCIATE => udp_associate(sock, peer, runtime).await,
        _ => {
            let bound = zero_bound();
            server_write_reply(&mut sock, 0x07, &bound).await?;
            Ok(())
        }
    }
}

fn zero_bound() -> SocksAddr {
    SocksAddr::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

struct AbortOnDrop(Vec<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

async fn udp_associate(
    mut tcp: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
) -> Result<(), BridgeError> {
    let bind_ip = match peer.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    server_write_reply(&mut tcp, REP_OK, &SocksAddr::Ip(udp.local_addr()?)).await?;

    let (tx, mut rx) = mpsc::channel::<(SocksTarget, Vec<u8>)>(32);
    let mut client_addr: Option<SocketAddr> = None;
    let mut session = UdpSession {
        direct_v4: None,
        direct_v6: None,
        upstream: None,
        readers: AbortOnDrop(Vec::new()),
        tx,
    };
    let mut buf = vec![0u8; 65535];
    let mut control_byte = [0u8; 1];

    loop {
        tokio::select! {
            read = tcp.read(&mut control_byte) => {
                let _ = read;
                break;
            }
            packet = udp.recv_from(&mut buf) => {
                let (n, src) = match packet {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::debug!(error = %err, "udp recv failed");
                        break;
                    }
                };
                if src.ip() != peer.ip() {
                    continue;
                }
                if client_addr.is_none() {
                    client_addr = Some(src);
                }
                if client_addr != Some(src) {
                    continue;
                }
                if let Err(err) = dispatch_udp(&runtime, peer, &buf[..n], &mut session).await {
                    tracing::debug!(error = %err, "udp datagram dropped");
                }
            }
            reply = rx.recv() => {
                let Some((target, payload)) = reply else { break };
                let Some(dest) = client_addr else { continue };
                if let Ok(packet) = encode_udp(&target, &payload) {
                    let _ = udp.send_to(&packet, dest).await;
                }
            }
        }
    }
    Ok(())
}

struct UdpSession {
    direct_v4: Option<Arc<UdpSocket>>,
    direct_v6: Option<Arc<UdpSocket>>,
    upstream: Option<Arc<Socks5Udp>>,
    readers: AbortOnDrop,
    tx: mpsc::Sender<(SocksTarget, Vec<u8>)>,
}

async fn dispatch_udp(
    runtime: &Runtime,
    peer: SocketAddr,
    packet: &[u8],
    session: &mut UdpSession,
) -> Result<(), BridgeError> {
    let header = parse_udp(packet)?;
    if header.frag != 0 {
        return Ok(());
    }
    let payload = &packet[header.header_len..];
    let flow = build_flow(
        &runtime.config,
        process_path_for(peer),
        &header.target,
        Transport::Udp,
    )
    .await;
    let decision = runtime.config.decide(&flow);
    runtime.log_decision(&flow, &decision);
    match decision.action {
        DecisionAction::Block => Ok(()),
        DecisionAction::Direct => send_direct(&header.target, payload, session).await,
        DecisionAction::Proxy(proxy) => {
            if proxy.kind != ProxyKind::Socks5 {
                tracing::warn!("HTTP proxies cannot carry UDP; datagram dropped");
                return Ok(());
            }
            let assoc = if let Some(existing) = session.upstream.clone() {
                existing
            } else {
                let control = connect_host(&proxy.host, proxy.port, runtime.fwmark).await?;
                let assoc = Arc::new(Socks5Udp::open(&proxy, control).await?);
                let reader = Arc::clone(&assoc);
                let tx = session.tx.clone();
                session.readers.0.push(tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    while let Ok((target, n)) = reader.recv_payload(&mut buf).await {
                        if tx.send((target, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }));
                session.upstream = Some(Arc::clone(&assoc));
                assoc
            };
            let target = match &header.target {
                SocksTarget::Domain(host, port) if !proxy.send_domain => {
                    let looked = tokio::net::lookup_host((host.as_str(), *port))
                        .await?
                        .next()
                        .ok_or_else(|| BridgeError::Failed(format!("no addresses for {host}")))?;
                    SocksTarget::from_socket_addr(looked)
                }
                other => other.clone(),
            };
            assoc.send_payload(&target, payload).await?;
            Ok(())
        }
    }
}

async fn send_direct(
    target: &SocksTarget,
    payload: &[u8],
    session: &mut UdpSession,
) -> Result<(), BridgeError> {
    let addr = resolve_target(target).await?;
    let slot = if addr.is_ipv4() {
        &mut session.direct_v4
    } else {
        &mut session.direct_v6
    };
    let sock = if let Some(existing) = slot.clone() {
        existing
    } else {
        let bind = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        let reader = Arc::clone(&sock);
        let tx = session.tx.clone();
        session.readers.0.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, src)) = reader.recv_from(&mut buf).await {
                let from = SocksTarget::from_socket_addr(src);
                if tx.send((from, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }));
        *slot = Some(Arc::clone(&sock));
        sock
    };
    sock.send_to(payload, addr).await?;
    Ok(())
}

async fn resolve_target(target: &SocksTarget) -> Result<SocketAddr, BridgeError> {
    match target {
        SocksTarget::V4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        SocksTarget::V6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        SocksTarget::Domain(host, port) => {
            let addr = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| BridgeError::Failed(format!("no addresses for {host}")))?;
            Ok(addr)
        }
    }
}
