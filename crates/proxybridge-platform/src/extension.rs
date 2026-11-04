//! Byte stream the macOS Network Extension hands an application flow to.
//!
//! The extension itself is Swift (`macos/NetworkExtension`) and has to be
//! signed on a Mac. This listener is the other half: ordinary TCP, every OS,
//! and tests drive it without an entitlement.
//!
//! Header, big-endian: `PB`, version 1, transport 1 (TCP), pid u32, path
//! length u16, path, kind (1 = IPv4, 2 = IPv6, 3 = domain), address, port u16.
//! The helper then writes one byte: 1 and the raw stream, or 0 if the flow
//! was blocked or could not be opened.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use proxybridge_core::{Config, Flow, SocksTarget, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::bridge::{build_flow, BridgeError, Runtime};

const MAX_PATH: usize = 1024;
const MAX_NAME: usize = 253;

pub struct ExtensionBridge {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), BridgeError>>>,
}

impl ExtensionBridge {
    pub async fn spawn(listen: SocketAddr, config: Arc<Config>) -> Result<Self, BridgeError> {
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let (tx, rx) = watch::channel(false);
        let runtime = Arc::new(Runtime::new(config, false));
        let task = tokio::spawn(async move { serve(listener, runtime, rx).await });
        tracing::info!(%local_addr, "network extension helper listening");
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

impl Drop for ExtensionBridge {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Header the Swift provider writes before the application bytes.
pub fn encode_header(pid: u32, path: &str, target: &SocksTarget) -> Vec<u8> {
    let path = &path.as_bytes()[..path.len().min(MAX_PATH)];
    let mut out = Vec::with_capacity(16 + path.len());
    out.extend_from_slice(b"PB");
    out.push(1);
    out.push(1);
    out.extend_from_slice(&pid.to_be_bytes());
    out.extend_from_slice(&(path.len() as u16).to_be_bytes());
    out.extend_from_slice(path);
    match target {
        SocksTarget::V4(ip, port) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::V6(ip, port) => {
            out.push(2);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::Domain(host, port) => {
            let host = &host.as_bytes()[..host.len().min(MAX_NAME)];
            out.push(3);
            out.push(host.len() as u8);
            out.extend_from_slice(host);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out
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
                        tracing::warn!(error = %err, "extension helper accept failed");
                        continue;
                    }
                };
                let runtime = Arc::clone(&runtime);
                clients.spawn(async move {
                    if let Err(err) = handle(sock, runtime).await {
                        tracing::debug!(%peer, error = %err, "extension flow ended");
                    }
                });
            }
        }
    }
    clients.abort_all();
    Ok(())
}

async fn handle(mut sock: TcpStream, runtime: Arc<Runtime>) -> Result<(), BridgeError> {
    let header = read_header(&mut sock, &runtime).await?;
    let decision = runtime.config.decide(&header.flow);
    runtime.log_decision(&header.flow, &decision);
    match runtime.open_tcp(&decision, &header.target).await {
        Ok(mut upstream) => {
            sock.write_all(&[1]).await?;
            let _ = proxybridge_core::splice_tcp(&mut sock, &mut upstream).await;
            Ok(())
        }
        Err(err) => {
            tracing::info!(
                path = header.flow.process_path.as_deref().unwrap_or("-"),
                dest = %header.target.display(),
                error = %err,
                "extension flow was not connected"
            );
            let _ = sock.write_all(&[0]).await;
            Ok(())
        }
    }
}

struct Header {
    target: SocksTarget,
    flow: Flow,
}

async fn read_header(sock: &mut TcpStream, runtime: &Runtime) -> Result<Header, BridgeError> {
    let mut magic = [0u8; 4];
    sock.read_exact(&mut magic).await?;
    if &magic[0..2] != b"PB" || magic[2] != 1 || magic[3] != 1 {
        return Err(BridgeError::Failed(
            "extension header was not ProxyBridge TCP version 1".into(),
        ));
    }
    let mut pid_buf = [0u8; 4];
    sock.read_exact(&mut pid_buf).await?;
    let _pid = u32::from_be_bytes(pid_buf);
    let mut len_buf = [0u8; 2];
    sock.read_exact(&mut len_buf).await?;
    let path_len = u16::from_be_bytes(len_buf) as usize;
    if path_len > MAX_PATH {
        return Err(BridgeError::Failed(
            "extension process path is too long".into(),
        ));
    }
    let mut path = vec![0u8; path_len];
    sock.read_exact(&mut path).await?;
    let path = String::from_utf8_lossy(&path).into_owned();
    let mut kind = [0u8; 1];
    sock.read_exact(&mut kind).await?;
    let target = match kind[0] {
        1 => {
            let mut addr = [0u8; 4];
            sock.read_exact(&mut addr).await?;
            SocksTarget::V4(Ipv4Addr::from(addr), read_port(sock).await?)
        }
        2 => {
            let mut addr = [0u8; 16];
            sock.read_exact(&mut addr).await?;
            SocksTarget::V6(Ipv6Addr::from(addr), read_port(sock).await?)
        }
        3 => {
            let mut n = [0u8; 1];
            sock.read_exact(&mut n).await?;
            if n[0] as usize > MAX_NAME {
                return Err(BridgeError::Failed("extension domain is too long".into()));
            }
            let mut host = vec![0u8; n[0] as usize];
            sock.read_exact(&mut host).await?;
            let host = String::from_utf8(host)
                .map_err(|_| BridgeError::Failed("extension domain is not UTF-8".into()))?;
            SocksTarget::Domain(host, read_port(sock).await?)
        }
        other => {
            return Err(BridgeError::Failed(format!(
                "extension address kind {other} is not supported"
            )))
        }
    };
    let flow = build_flow(
        &runtime.config,
        if path.is_empty() { None } else { Some(path) },
        &target,
        Transport::Tcp,
        &runtime.dns,
    )
    .await;
    Ok(Header { target, flow })
}

async fn read_port(sock: &mut TcpStream) -> Result<u16, BridgeError> {
    let mut buf = [0u8; 2];
    sock.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn helper_blocks_a_named_process_and_relays_direct() {
        let config = Config::from_toml_str(
            r#"
[[rules]]
name = "stop-browser"
process = "firefox"
action = "block"
[[rules]]
name = "rest"
action = "direct"
"#,
        )
        .unwrap();
        let bridge = ExtensionBridge::spawn("127.0.0.1:0".parse().unwrap(), Arc::new(config))
            .await
            .unwrap();

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = sock.into_split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });

        let blocked_target = SocksTarget::V4(Ipv4Addr::new(1, 2, 3, 4), 9);
        let mut blocked = TcpStream::connect(bridge.local_addr()).await.unwrap();
        blocked
            .write_all(&encode_header(
                42,
                "/Applications/Firefox.app/Contents/MacOS/firefox",
                &blocked_target,
            ))
            .await
            .unwrap();
        let mut status = [0u8; 1];
        blocked.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], 0);

        let echo_target = match echo_addr.ip() {
            IpAddr::V4(ip) => SocksTarget::V4(ip, echo_addr.port()),
            IpAddr::V6(ip) => SocksTarget::V6(ip, echo_addr.port()),
        };
        let mut ok = TcpStream::connect(bridge.local_addr()).await.unwrap();
        ok.write_all(&encode_header(7, "/usr/bin/curl", &echo_target))
            .await
            .unwrap();
        ok.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], 1);
        ok.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        ok.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        bridge.shutdown().await.unwrap();
    }
}
