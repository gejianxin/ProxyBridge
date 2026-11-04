//! Windows x64 transparent capture.
//!
//! The rewrite of IPv4 packets lives in `packet` and is tested on every OS.
//! Opening the driver is `WinDivertOpen` from `WinDivert.dll` (WinDivert 2.2).
//! This repository does not bundle the driver. On a Windows machine the DLL
//! and `WinDivert64.sys` must sit beside `proxybridge.exe`.

use std::net::SocketAddr;
use std::sync::Arc;

use proxybridge_core::Config;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::bridge::BridgeError;

pub struct WinDivertProxy {
    pub(crate) local_addr: SocketAddr,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) task: Option<JoinHandle<Result<(), BridgeError>>>,
}

impl WinDivertProxy {
    pub async fn spawn(listen: SocketAddr, config: Arc<Config>) -> Result<Self, BridgeError> {
        #[cfg(windows)]
        {
            crate::windivert_driver::spawn(listen, config).await
        }
        #[cfg(not(windows))]
        {
            let _ = (listen, config);
            Err(BridgeError::Unavailable(
                "WinDivert capture runs on Windows x64. The IPv4 TCP/UDP rewrite is implemented and tested; WinDivert.dll plus the driver must be installed beside proxybridge.exe. This host cannot load that driver.",
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

impl Drop for WinDivertProxy {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_windows_explains_the_driver_requirement() {
        #[cfg(not(windows))]
        {
            let text = match WinDivertProxy::spawn(
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(Config::builtin()),
            )
            .await
            {
                Err(err) => err.to_string(),
                Ok(_) => panic!("non-windows host should not open WinDivert"),
            };
            assert!(text.contains("WinDivert"));
            assert!(text.contains("driver"));
        }
    }
}
