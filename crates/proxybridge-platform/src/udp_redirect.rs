//! Transparent UDP after iptables NAT REDIRECT.
//!
//! `IP_RECVORIGDSTADDR` recovers the destination the application used.
//! Replies are sent with that address as the source when `IP_TRANSPARENT`
//! is allowed. DNS replies we forward are recorded so a later TCP flow can
//! match a domain rule.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use proxybridge_core::{DecisionAction, ProxyKind, Socks5Udp, SocksTarget, Transport};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

use crate::bridge::{build_flow, connect_host, udp_exchange, BridgeError, Runtime};
use crate::linux_net::{set_ip_transparent, set_recv_origdst, udp_recv_origdst, udp_send_from};
use crate::process::lookup_udp_process;

pub async fn serve(
    listen: SocketAddr,
    runtime: Arc<Runtime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let socket = std::net::UdpSocket::bind(listen)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    set_recv_origdst(fd, listen.is_ipv6())?;
    if let Err(err) = set_ip_transparent(fd) {
        tracing::warn!(
            error = %err,
            "IP_TRANSPARENT was not set; UDP replies cannot use the original source address without CAP_NET_ADMIN"
        );
    }
    let owned: OwnedFd = socket.into();
    // The socket is owned by `owned` and is not used anywhere else.
    let async_fd = unsafe { AsyncFd::register(owned) }
        .map_err(|err| std::io::Error::other(format!("udp redirect register failed: {err}")))?;
    let local = listen;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            ready = async_fd.readable() => {
                let mut guard = ready?;
                match udp_recv_origdst(async_fd.get_ref().as_raw_fd(), &mut buf) {
                    Ok((n, peer, orig)) => {
                        guard.retain_ready();
                        let Some(dest) = orig else { continue };
                        if dest.ip() == local.ip() && dest.port() == local.port() {
                            continue;
                        }
                        let payload = buf[..n].to_vec();
                        let runtime = Arc::clone(&runtime);
                        let send_fd = unsafe { libc::dup(async_fd.get_ref().as_raw_fd()) };
                        if send_fd < 0 {
                            continue;
                        }
                        let send_fd = unsafe { OwnedFd::from_raw_fd(send_fd) };
                        tokio::spawn(async move {
                            if let Err(err) = handle(runtime, peer, dest, payload, send_fd).await {
                                tracing::debug!(%peer, %dest, error = %err, "udp redirect dropped");
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "udp redirect recv failed");
                        return Err(err.into());
                    }
                }
            }
        }
    }
}

async fn handle(
    runtime: Arc<Runtime>,
    peer: SocketAddr,
    dest: SocketAddr,
    payload: Vec<u8>,
    send_fd: OwnedFd,
) -> Result<(), BridgeError> {
    let target = SocksTarget::from_socket_addr(dest);
    let flow = build_flow(
        &runtime.config,
        lookup_udp_process(peer).and_then(|info| {
            if info.exe.is_empty() {
                None
            } else {
                Some(info.exe)
            }
        }),
        &target,
        Transport::Udp,
        &runtime.dns,
    )
    .await;
    let decision = runtime.config.decide(&flow);
    runtime.log_decision(&flow, &decision);
    let reply = match decision.action {
        DecisionAction::Block => return Ok(()),
        DecisionAction::Direct => udp_exchange(&payload, dest, true).await?,
        DecisionAction::Proxy(proxy) => {
            if proxy.kind != ProxyKind::Socks5 {
                tracing::warn!("HTTP proxies cannot carry transparent UDP");
                return Ok(());
            }
            let control = connect_host(&proxy.host, proxy.port, true).await?;
            let assoc = Socks5Udp::open(&proxy, control).await?;
            let via = if proxy.send_domain {
                target
            } else {
                SocksTarget::from_socket_addr(dest)
            };
            assoc.send_payload(&via, &payload).await?;
            let mut buf = vec![0u8; 65535];
            let (_from, n) = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                assoc.recv_payload(&mut buf),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "socks udp timed out")
            })??;
            buf.truncate(n);
            buf
        }
    };
    runtime.dns.observe(&reply);
    if let Err(err) = udp_send_from(send_fd.as_raw_fd(), dest, peer, &reply) {
        tracing::debug!(
            error = %err,
            "could not spoof the UDP source; the application may ignore the reply"
        );
    }
    Ok(())
}
