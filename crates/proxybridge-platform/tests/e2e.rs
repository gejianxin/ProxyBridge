use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxybridge_core::{
    encode_udp, parse_udp, server_negotiate, server_read_request, server_write_reply, splice_tcp,
    Config, SocksAddr, SocksTarget, CMD_CONNECT, REP_NOT_ALLOWED, REP_OK,
};
use proxybridge_platform::LocalSocks;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn socks_inbound_proxies_tcp_and_can_block() {
    let echo = echo_server().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = socks_upstream(Arc::clone(&hits)).await;

    let proxied = Config::from_toml_str(&format!(
        r#"
[proxy]
type = "socks5"
host = "127.0.0.1"
port = {}

[[rules]]
name = "loop"
localhost = true
action = "proxy"
"#,
        upstream.port()
    ))
    .unwrap();
    let server = LocalSocks::spawn("127.0.0.1:0".parse().unwrap(), Arc::new(proxied))
        .await
        .unwrap();

    let mut client = socks_connect(server.local_addr(), echo).await;
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut buf))
        .await
        .expect("timed out waiting for proxied echo")
        .unwrap();
    assert_eq!(&buf, b"ping");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(client);

    let blocked = Config::from_toml_str(
        r#"
[[rules]]
name = "nope"
action = "block"
"#,
    )
    .unwrap();
    let blocking = LocalSocks::spawn("127.0.0.1:0".parse().unwrap(), Arc::new(blocked))
        .await
        .unwrap();
    // Loopback is left direct even for a block rule, matching the C port.
    // A public address is blocked before any outbound connect.
    let blocked_dest: SocketAddr = "1.2.3.4:9".parse().unwrap();
    let reply = socks_reply(blocking.local_addr(), blocked_dest).await;
    assert_eq!(reply, REP_NOT_ALLOWED);

    server.shutdown().await.unwrap();
    blocking.shutdown().await.unwrap();
}

#[tokio::test]
async fn loopback_goes_direct_and_udp_echoes() {
    let echo = echo_server().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let upstream = socks_upstream(Arc::clone(&hits)).await;
    // Point at an upstream, but the built-in rule does not proxy loopback.
    let config = Config::from_toml_str(&format!(
        "[proxy]\ntype = \"socks5\"\nhost = \"127.0.0.1\"\nport = {}\n",
        upstream.port()
    ))
    .unwrap();
    assert_eq!(config.primary().port, upstream.port());
    let server = LocalSocks::spawn("127.0.0.1:0".parse().unwrap(), Arc::new(config))
        .await
        .unwrap();

    let mut client = socks_connect(server.local_addr(), echo).await;
    client.write_all(b"pong").await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "loopback must not reach the upstream"
    );

    let udp_echo = udp_echo_server().await;
    let payload = udp_roundtrip(server.local_addr(), udp_echo).await;
    assert_eq!(payload, b"hi");
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    server.shutdown().await.unwrap();
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = sock.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

async fn udp_echo_server() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

async fn socks_upstream(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                if server_negotiate(&mut sock).await.is_err() {
                    return;
                }
                let Ok(request) = server_read_request(&mut sock).await else {
                    return;
                };
                if request.command != CMD_CONNECT {
                    let _ = server_write_reply(&mut sock, 0x07, &zero()).await;
                    return;
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let target = match request.target {
                    SocksTarget::V4(ip, port) => SocketAddr::from((ip, port)).to_string(),
                    SocksTarget::V6(ip, port) => SocketAddr::from((ip, port)).to_string(),
                    SocksTarget::Domain(host, port) => format!("{host}:{port}"),
                };
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    let _ = server_write_reply(&mut sock, 0x05, &zero()).await;
                    return;
                };
                if server_write_reply(&mut sock, REP_OK, &zero())
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = splice_tcp(&mut sock, &mut upstream).await;
            });
        }
    });
    addr
}

fn zero() -> SocksAddr {
    SocksAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0)))
}

async fn socks_connect(proxy: SocketAddr, dest: SocketAddr) -> TcpStream {
    let mut sock = TcpStream::connect(proxy).await.unwrap();
    greet(&mut sock).await;
    let reply = write_connect(&mut sock, dest).await;
    assert_eq!(reply, REP_OK, "connect failed with rep {reply:#04x}");
    sock
}

async fn socks_reply(proxy: SocketAddr, dest: SocketAddr) -> u8 {
    let mut sock = TcpStream::connect(proxy).await.unwrap();
    greet(&mut sock).await;
    write_connect(&mut sock, dest).await
}

async fn greet(sock: &mut TcpStream) {
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    sock.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);
}

async fn write_connect(sock: &mut TcpStream, dest: SocketAddr) -> u8 {
    let SocketAddr::V4(dest) = dest else {
        panic!("test destinations are ipv4");
    };
    let mut req = vec![0x05, CMD_CONNECT, 0x00, 0x01];
    req.extend_from_slice(&dest.ip().octets());
    req.extend_from_slice(&dest.port().to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await.unwrap();
    reply[1]
}

async fn udp_roundtrip(proxy: SocketAddr, dest: SocketAddr) -> Vec<u8> {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    greet(&mut tcp).await;
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], REP_OK);
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = encode_udp(&SocksTarget::from_socket_addr(dest), b"hi").unwrap();
    udp.send_to(&packet, (ip, port)).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), udp.recv_from(&mut buf))
        .await
        .expect("udp reply timed out")
        .unwrap();
    let header = parse_udp(&buf[..n]).unwrap();
    buf[header.header_len..n].to_vec()
}
