//! WinDivert 2.2 capture loop. Loaded at runtime from WinDivert.dll.

use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::Arc;

use proxybridge_core::{Config, DecisionAction, Flow, SocksTarget, Transport};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use crate::bridge::{udp_exchange, BridgeError, Runtime};
use crate::packet::{classify_ipv4, windivert_filter, NatTable, NewFlow, PacketAction, L4};
use crate::process::lookup_udp_process;
use crate::windows::WinDivertProxy;
use crate::windows_proc::lookup_tcp;

const OUTBOUND: u32 = 1 << 17;
const LOOPBACK: u32 = 1 << 18;

#[repr(C)]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved2: u32,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

#[derive(Clone, Copy)]
struct Api {
    open: unsafe extern "system" fn(*const i8, i32, i16, u64) -> isize,
    recv: unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *mut Address) -> i32,
    send: unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const Address) -> i32,
    close: unsafe extern "system" fn(isize) -> i32,
    shutdown: unsafe extern "system" fn(isize, u64) -> i32,
}

pub async fn spawn(listen: SocketAddr, config: Arc<Config>) -> Result<WinDivertProxy, BridgeError> {
    let listener = TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let udp = UdpSocket::bind(local_addr).await?;
    let api = load_api()?;
    let filter = windivert_filter(&config.primary().host, config.primary().port);
    let filter_c = CString::new(filter)
        .map_err(|_| BridgeError::Failed("WinDivert filter contains a NUL".into()))?;
    let handle = unsafe { (api.open)(filter_c.as_ptr(), 0, 0, 0) };
    if handle == 0 || handle == -1 {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(BridgeError::Failed(format!(
            "WinDivertOpen failed (error {code}). Install WinDivert.dll and WinDivert64.sys next to proxybridge.exe and run it elevated."
        )));
    }
    let (tx, rx) = watch::channel(false);
    let runtime = Arc::new(Runtime::new(config, false));
    let nat = Arc::new(NatTable::new());
    let task = tokio::spawn(run(
        api, handle, listener, udp, local_addr, nat, runtime, rx,
    ));
    Ok(WinDivertProxy {
        local_addr,
        shutdown_tx: tx,
        task: Some(task),
    })
}

async fn run(
    api: Api,
    handle: isize,
    listener: TcpListener,
    udp: UdpSocket,
    local_addr: SocketAddr,
    nat: Arc<NatTable>,
    runtime: Arc<Runtime>,
    mut rx: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let capture_nat = Arc::clone(&nat);
    let capture_rt = Arc::clone(&runtime);
    let capture = tokio::task::spawn_blocking(move || {
        capture_loop(api, handle, local_addr, capture_nat, capture_rt)
    });
    let tcp_nat = Arc::clone(&nat);
    let tcp_rt = Arc::clone(&runtime);
    let tcp_rx = rx.clone();
    let tcp = tokio::spawn(async move { accept_tcp(listener, tcp_nat, tcp_rt, tcp_rx).await });
    let udp_rx = rx.clone();
    let udp_task = tokio::spawn(async move { accept_udp(udp, nat, runtime, udp_rx).await });
    tokio::select! {
        _ = rx.changed() => {}
        result = tcp => {
            result.map_err(|err| BridgeError::Failed(err.to_string()))??;
        }
        result = udp_task => {
            result.map_err(|err| BridgeError::Failed(err.to_string()))??;
        }
    }
    unsafe { (api.shutdown)(handle, 1) };
    let _ = capture.await;
    unsafe { (api.close)(handle) };
    Ok(())
}

fn capture_loop(
    api: Api,
    handle: isize,
    listen: SocketAddr,
    nat: Arc<NatTable>,
    runtime: Arc<Runtime>,
) -> Result<(), BridgeError> {
    let mut packet = vec![0u8; 65535];
    loop {
        let mut addr = Address {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            data: [0; 64],
        };
        let mut received = 0u32;
        let ok = unsafe {
            (api.recv)(
                handle,
                packet.as_mut_ptr(),
                packet.len() as u32,
                &mut received,
                &mut addr,
            )
        };
        if ok == 0 {
            return Ok(());
        }
        let len = received as usize;
        if len > packet.len() {
            continue;
        }
        let action = classify_ipv4(&packet[..len], listen, &nat, |src, dst, proto| {
            decide(&runtime, src, dst, proto)
        });
        match action {
            PacketAction::Drop => {}
            PacketAction::Pass => {
                let mut sent = 0u32;
                unsafe {
                    (api.send)(handle, packet.as_ptr(), len as u32, &mut sent, &addr);
                }
            }
            PacketAction::Rewrite {
                packet: rewritten,
                loopback,
            } => {
                if loopback {
                    addr.flags |= LOOPBACK | OUTBOUND;
                } else {
                    addr.flags &= !LOOPBACK;
                    addr.flags |= OUTBOUND;
                }
                let mut sent = 0u32;
                unsafe {
                    (api.send)(
                        handle,
                        rewritten.as_ptr(),
                        rewritten.len() as u32,
                        &mut sent,
                        &addr,
                    );
                }
            }
        }
    }
}

fn decide(runtime: &Runtime, src: SocketAddr, dst: SocketAddr, proto: L4) -> NewFlow {
    let process = if proto == L4::Tcp {
        lookup_tcp(src)
    } else {
        lookup_udp_process(src)
    };
    let names = dst.ip();
    let learned = runtime.dns.names(names);
    let flow = Flow {
        process_path: process.and_then(|info| {
            if info.exe.is_empty() {
                None
            } else {
                Some(info.exe)
            }
        }),
        dest_ip: Some(dst.ip()),
        dest_host: learned.first().cloned(),
        learned_names: learned,
        dest_port: dst.port(),
        protocol: if proto == L4::Tcp {
            Transport::Tcp
        } else {
            Transport::Udp
        },
    };
    runtime.log_decision(&flow, &runtime.config.decide(&flow));
    match runtime.config.decide(&flow).action {
        DecisionAction::Direct => NewFlow::Direct,
        DecisionAction::Block => NewFlow::Block,
        DecisionAction::Proxy(_) => NewFlow::Proxy,
    }
}

async fn accept_tcp(
    listener: TcpListener,
    nat: Arc<NatTable>,
    runtime: Arc<Runtime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                let Some(dest) = nat.lookup(peer) else {
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                tokio::spawn(async move {
                    let target = SocksTarget::from_socket_addr(dest);
                    let _ = crate::bridge::relay_tcp(&runtime, sock, peer, target, false).await;
                });
            }
        }
    }
}

async fn accept_udp(
    socket: UdpSocket,
    nat: Arc<NatTable>,
    runtime: Arc<Runtime>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            packet = socket.recv_from(&mut buf) => {
                let (n, peer) = packet?;
                let Some(dest) = nat.lookup(peer) else {
                    continue;
                };
                let payload = buf[..n].to_vec();
                let reply = match udp_exchange(&payload, dest, false).await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::debug!(%dest, error = %err, "windivert udp forward failed");
                        continue;
                    }
                };
                runtime.dns.observe(&reply);
                let _ = socket.send_to(&reply, peer).await;
                let _ = runtime;
            }
        }
    }
}

fn load_api() -> Result<Api, BridgeError> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    unsafe {
        let wide: Vec<u16> = "WinDivert.dll\0".encode_utf16().collect();
        let module = LoadLibraryW(wide.as_ptr());
        if module.is_null() {
            return Err(BridgeError::Failed(
                "WinDivert.dll was not found. Place WinDivert.dll and WinDivert64.sys next to proxybridge.exe. The capture loop is implemented; the driver is not bundled.".into(),
            ));
        }
        Ok(Api {
            open: load_fn(module, "WinDivertOpen")?,
            recv: load_fn(module, "WinDivertRecv")?,
            send: load_fn(module, "WinDivertSend")?,
            close: load_fn(module, "WinDivertClose")?,
            shutdown: load_fn(module, "WinDivertShutdown")?,
        })
    }
}

unsafe fn load_fn<T>(
    module: windows_sys::Win32::Foundation::HMODULE,
    name: &str,
) -> Result<T, BridgeError> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    let c = CString::new(name).expect("function name");
    let sym = GetProcAddress(module, c.as_ptr().cast());
    let Some(sym) = sym else {
        return Err(BridgeError::Failed(format!(
            "WinDivert.dll is missing {name}. Install WinDivert 2.2."
        )));
    };
    Ok(std::mem::transmute_copy(&sym))
}
