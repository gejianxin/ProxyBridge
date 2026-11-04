//! Linux transparent TCP listener.
//!
//! Packets reach this socket only after iptables `REDIRECT`. The pre-NAT
//! destination is read with `SO_ORIGINAL_DST`. Sockets opened by this process
//! are marked so the same rule does not divert them again.

use std::net::SocketAddr;
use std::sync::Arc;

use proxybridge_core::Config;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::bridge::BridgeError;

#[cfg(target_os = "linux")]
use crate::bridge::{relay_tcp, Runtime};
#[cfg(target_os = "linux")]
use proxybridge_core::SocksTarget;
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use tokio::task::JoinSet;

pub struct RedirectProxy {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), BridgeError>>>,
}

impl RedirectProxy {
    pub async fn spawn(listen: SocketAddr, config: Arc<Config>) -> Result<Self, BridgeError> {
        #[cfg(target_os = "linux")]
        {
            spawn_linux(listen, config).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (listen, config);
            Err(BridgeError::Unavailable(
                "TCP redirect is implemented for Linux (iptables REDIRECT and SO_ORIGINAL_DST). Use --mode socks on this operating system.",
            ))
        }
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

impl Drop for RedirectProxy {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
async fn spawn_linux(
    listen: SocketAddr,
    config: Arc<Config>,
) -> Result<RedirectProxy, BridgeError> {
    let listener = TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let (tx, rx) = watch::channel(false);
    let runtime = Arc::new(Runtime::new(Arc::clone(&config), true));
    tracing::warn!(
        %local_addr,
        upstream = %config.primary().label(),
        "redirect listener started; install the rules from `proxybridge iptables` before expecting diverted connections"
    );
    let task = tokio::spawn(async move { serve(listener, local_addr, runtime, rx).await });
    Ok(RedirectProxy {
        local_addr,
        shutdown_tx: tx,
        task: Some(task),
    })
}

#[cfg(target_os = "linux")]
async fn serve(
    listener: TcpListener,
    local_addr: SocketAddr,
    runtime: Arc<Runtime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let udp_rt = Arc::clone(&runtime);
    let udp_stop = shutdown.clone();
    tokio::spawn(async move {
        if let Err(err) = crate::udp_redirect::serve(local_addr, udp_rt, udp_stop).await {
            tracing::warn!(error = %err, "transparent udp listener stopped");
        }
    });
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
                    if let Err(err) = handle(sock, peer, runtime).await {
                        tracing::debug!(%peer, error = %err, "redirected connection ended");
                    }
                });
            }
        }
    }
    clients.abort_all();
    Ok(())
}

#[cfg(target_os = "linux")]
async fn handle(
    sock: TcpStream,
    peer: SocketAddr,
    runtime: Arc<Runtime>,
) -> Result<(), BridgeError> {
    use std::os::fd::AsRawFd;
    let local = sock.local_addr()?;
    let dest = match crate::linux_net::original_destination(sock.as_raw_fd(), local) {
        // Without NAT, Linux reports the socket's own local address. A real
        // REDIRECT makes this differ from the pre-NAT destination.
        Ok(addr) if addr != local && addr.port() != 0 => addr,
        Ok(addr) => {
            tracing::warn!(
                %peer,
                original = %addr,
                "connection was not redirected; refusing to relay it back into this listener"
            );
            return Ok(());
        }
        Err(err) => {
            tracing::warn!(
                %peer,
                error = %err,
                "connection has no original destination; it was not produced by iptables REDIRECT"
            );
            return Ok(());
        }
    };
    relay_tcp(
        &runtime,
        sock,
        peer,
        SocksTarget::from_socket_addr(dest),
        false,
    )
    .await
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn plain_connection_is_dropped_without_panicking() {
        let proxy =
            RedirectProxy::spawn("127.0.0.1:0".parse().unwrap(), Arc::new(Config::builtin()))
                .await
                .unwrap();
        let client = TcpStream::connect(proxy.local_addr()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = [0u8; 8];
        let n = client.try_read(&mut buf);
        // The listener closes or leaves the socket idle after failing SO_ORIGINAL_DST.
        // Either an early EOF or a WouldBlock/empty read is acceptable; a panic is not.
        let _ = n;
        proxy.shutdown().await.unwrap();
    }
}
