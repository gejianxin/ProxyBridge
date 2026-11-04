//! SOCKS5 client and the framing used by the userspace inbound server.
//!
//! The handshake follows RFC 1928 and username/password authentication follows
//! RFC 1929. UDP datagrams use the RFC 1928 UDP request header.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::ProxyEndpoint;
use crate::error::{Error, Result};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const REP_OK: u8 = 0x00;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_REFUSED: u8 = 0x05;

const VERSION: u8 = 0x05;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Destination carried by a SOCKS5 request or UDP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl SocksTarget {
    pub fn port(&self) -> u16 {
        match self {
            SocksTarget::V4(_, p) | SocksTarget::V6(_, p) | SocksTarget::Domain(_, p) => *p,
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => SocksTarget::V4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => SocksTarget::V6(*v6.ip(), v6.port()),
        }
    }

    pub fn display(&self) -> String {
        match self {
            SocksTarget::V4(ip, port) => format!("{ip}:{port}"),
            SocksTarget::V6(ip, port) => format!("[{ip}]:{port}"),
            SocksTarget::Domain(host, port) => format!("{host}:{port}"),
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SocksTarget::V4(ip, _) => Some(IpAddr::V4(*ip)),
            SocksTarget::V6(ip, _) => Some(IpAddr::V6(*ip)),
            SocksTarget::Domain(_, _) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            SocksTarget::Domain(host, _) => Some(host.as_str()),
            _ => None,
        }
    }
}

/// Address returned in a SOCKS5 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl SocksAddr {
    pub fn socket_addr(&self, fallback_ip: IpAddr) -> SocketAddr {
        match self {
            SocksAddr::Ip(addr) => {
                let unspecified = match addr.ip() {
                    IpAddr::V4(ip) => ip.is_unspecified(),
                    IpAddr::V6(ip) => ip.is_unspecified(),
                };
                if unspecified {
                    SocketAddr::new(fallback_ip, addr.port())
                } else {
                    *addr
                }
            }
            SocksAddr::Domain { port, .. } => SocketAddr::new(fallback_ip, *port),
        }
    }
}

/// Parsed SOCKS5 UDP header. `header_len` is the index where the payload starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub frag: u8,
    pub target: SocksTarget,
    pub header_len: usize,
}

pub fn encode_udp(target: &SocksTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + payload.len() + 22);
    out.extend_from_slice(&[0, 0, 0]);
    write_target(&mut out, target)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn parse_udp(packet: &[u8]) -> Result<UdpHeader> {
    if packet.len() < 4 {
        return Err(Error::Socks5("udp header is too short".into()));
    }
    let frag = packet[2];
    let (target, header_len) =
        read_target(&packet[3..]).map_err(|e| Error::Socks5(format!("udp header: {e}")))?;
    let header_len = header_len + 3;
    if header_len > packet.len() {
        return Err(Error::Socks5("udp header is truncated".into()));
    }
    Ok(UdpHeader {
        frag,
        target,
        header_len,
    })
}

/// Perform a client handshake and return the proxy's bound address.
pub async fn client_handshake(
    stream: &mut TcpStream,
    proxy: &ProxyEndpoint,
    target: &SocksTarget,
    command: u8,
) -> Result<SocksAddr> {
    let result = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake_inner(stream, proxy, target, command),
    )
    .await;
    match result {
        Ok(inner) => inner,
        Err(_) => Err(Error::Socks5("timed out during handshake".into())),
    }
}

async fn client_handshake_inner(
    stream: &mut TcpStream,
    proxy: &ProxyEndpoint,
    target: &SocksTarget,
    command: u8,
) -> Result<SocksAddr> {
    let user = proxy.username.as_deref().filter(|u| !u.is_empty());
    if let Some(user) = user {
        let pass = proxy.password.as_deref().unwrap_or("");
        if user.len() > 255 || pass.len() > 255 {
            return Err(Error::Socks5(
                "username and password must be at most 255 bytes".into(),
            ));
        }
        stream
            .write_all(&[VERSION, 0x02, 0x00, 0x02])
            .await
            .map_err(io_err)?;
    } else {
        stream
            .write_all(&[VERSION, 0x01, 0x00])
            .await
            .map_err(io_err)?;
    }

    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.map_err(io_err)?;
    if method[0] != VERSION {
        return Err(Error::Socks5("proxy did not speak SOCKS5".into()));
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            let Some(user) = user else {
                return Err(Error::Socks5(
                    "proxy requires a username and password".into(),
                ));
            };
            let pass = proxy.password.as_deref().unwrap_or("");
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await.map_err(io_err)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await.map_err(io_err)?;
            if status[0] != 0x01 || status[1] != 0x00 {
                return Err(Error::Socks5("username/password rejected".into()));
            }
        }
        0xff => return Err(Error::Socks5("proxy rejected every auth method".into())),
        other => {
            return Err(Error::Socks5(format!(
                "proxy selected unsupported auth method {other:#04x}"
            )))
        }
    }

    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&[VERSION, command, 0x00]);
    write_target(&mut req, target)?;
    stream.write_all(&req).await.map_err(io_err)?;
    read_reply(stream).await
}

/// Read the client's greeting and accept the no-authentication method.
pub async fn server_negotiate(stream: &mut TcpStream) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != VERSION || head[1] == 0 {
        let _ = stream.write_all(&[VERSION, 0xff]).await;
        return Err(Error::Socks5("client greeting was not SOCKS5".into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await.map_err(io_err)?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[VERSION, 0xff]).await;
        return Err(Error::Socks5(
            "client did not offer no-authentication".into(),
        ));
    }
    stream.write_all(&[VERSION, 0x00]).await.map_err(io_err)?;
    Ok(())
}

pub struct ClientRequest {
    pub command: u8,
    pub target: SocksTarget,
}

pub async fn server_read_request(stream: &mut TcpStream) -> Result<ClientRequest> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != VERSION {
        return Err(Error::Socks5("client request was not SOCKS5".into()));
    }
    let (target, _) = read_target_from(stream, head[3]).await?;
    Ok(ClientRequest {
        command: head[1],
        target,
    })
}

pub async fn server_write_reply(stream: &mut TcpStream, rep: u8, bound: &SocksAddr) -> Result<()> {
    let mut buf = vec![VERSION, rep, 0x00];
    match bound {
        SocksAddr::Ip(SocketAddr::V4(addr)) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddr::Ip(SocketAddr::V6(addr)) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddr::Domain { host, port } => {
            if host.len() > 255 {
                return Err(Error::Socks5("bound domain is too long".into()));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&buf).await.map_err(io_err)?;
    Ok(())
}

/// A UDP association opened as a SOCKS5 client. The TCP stream is kept open
/// because closing it ends the association.
pub struct Socks5Udp {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl Socks5Udp {
    pub async fn open(proxy: &ProxyEndpoint, control: TcpStream) -> Result<Self> {
        let peer = control.peer_addr().map_err(io_err)?;
        let mut control = control;
        let bound = client_handshake(
            &mut control,
            proxy,
            &SocksTarget::V4(Ipv4Addr::UNSPECIFIED, 0),
            CMD_UDP_ASSOCIATE,
        )
        .await?;
        let relay = bound.socket_addr(peer.ip());
        let socket = UdpSocket::bind(unspecified(peer.ip()))
            .await
            .map_err(io_err)?;
        Ok(Self {
            _control: control,
            socket,
            relay,
        })
    }

    pub async fn send_payload(&self, target: &SocksTarget, payload: &[u8]) -> Result<()> {
        let packet = encode_udp(target, payload)?;
        self.socket
            .send_to(&packet, self.relay)
            .await
            .map_err(io_err)?;
        Ok(())
    }

    pub async fn recv_payload(&self, buf: &mut [u8]) -> Result<(SocksTarget, usize)> {
        let (n, _) = self.socket.recv_from(buf).await.map_err(io_err)?;
        let header = parse_udp(&buf[..n])?;
        if header.frag != 0 {
            return Err(Error::Socks5(
                "fragmented udp replies are not supported".into(),
            ));
        }
        let payload_len = n - header.header_len;
        buf.copy_within(header.header_len..n, 0);
        Ok((header.target, payload_len))
    }
}

fn unspecified(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

async fn read_reply(stream: &mut TcpStream) -> Result<SocksAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != VERSION {
        return Err(Error::Socks5("proxy reply was not SOCKS5".into()));
    }
    let (addr, _) = read_target_from(stream, head[3]).await?;
    if head[1] != REP_OK {
        return Err(Error::Socks5(format!(
            "CONNECT failed: {} ({:#04x})",
            rep_message(head[1]),
            head[1]
        )));
    }
    Ok(target_to_addr(addr))
}

fn target_to_addr(target: SocksTarget) -> SocksAddr {
    match target {
        SocksTarget::V4(ip, port) => SocksAddr::Ip(SocketAddr::from((ip, port))),
        SocksTarget::V6(ip, port) => SocksAddr::Ip(SocketAddr::from((ip, port))),
        SocksTarget::Domain(host, port) => SocksAddr::Domain { host, port },
    }
}

pub fn rep_message(rep: u8) -> &'static str {
    match rep {
        0x00 => "succeeded",
        0x01 => "general failure",
        0x02 => "not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

fn write_target(buf: &mut Vec<u8>, target: &SocksTarget) -> Result<()> {
    match target {
        SocksTarget::V4(ip, port) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::V6(ip, port) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        SocksTarget::Domain(host, port) => {
            if host.is_empty() || host.len() > 255 {
                return Err(Error::Socks5("domain name must be 1-255 bytes".into()));
            }
            if !host.is_ascii() {
                return Err(Error::Socks5(
                    "domain name must be ASCII in a SOCKS5 request".into(),
                ));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn read_target(buf: &[u8]) -> std::result::Result<(SocksTarget, usize), String> {
    if buf.is_empty() {
        return Err("missing address type".into());
    }
    match buf[0] {
        ATYP_V4 => {
            if buf.len() < 1 + 4 + 2 {
                return Err("truncated IPv4 address".into());
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((SocksTarget::V4(ip, port), 7))
        }
        ATYP_V6 => {
            if buf.len() < 1 + 16 + 2 {
                return Err("truncated IPv6 address".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((SocksTarget::V6(Ipv6Addr::from(octets), port), 19))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err("truncated domain address".into());
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err("truncated domain address".into());
            }
            let host = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| "domain is not UTF-8".to_string())?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((SocksTarget::Domain(host, port), 2 + len + 2))
        }
        other => Err(format!("unsupported address type {other:#04x}")),
    }
}

async fn read_target_from(stream: &mut TcpStream, atyp: u8) -> Result<(SocksTarget, usize)> {
    match atyp {
        ATYP_V4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await.map_err(io_err)?;
            let mut raw = vec![ATYP_V4];
            raw.extend_from_slice(&buf);
            read_target(&raw).map_err(Error::Socks5)
        }
        ATYP_V6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await.map_err(io_err)?;
            let mut raw = vec![ATYP_V6];
            raw.extend_from_slice(&buf);
            read_target(&raw).map_err(Error::Socks5)
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io_err)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await.map_err(io_err)?;
            let mut raw = vec![ATYP_DOMAIN, len[0]];
            raw.extend_from_slice(&rest);
            read_target(&raw).map_err(Error::Socks5)
        }
        other => Err(Error::Socks5(format!(
            "unsupported address type {other:#04x}"
        ))),
    }
}

fn io_err(err: std::io::Error) -> Error {
    Error::Socks5(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyKind;
    use tokio::net::TcpListener;

    fn proxy(user: Option<&str>, pass: Option<&str>) -> ProxyEndpoint {
        ProxyEndpoint {
            name: "t".into(),
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: 1,
            username: user.map(str::to_string),
            password: pass.map(str::to_string),
            send_domain: true,
        }
    }

    #[test]
    fn udp_header_round_trip() {
        let target = SocksTarget::Domain("dns.example".into(), 53);
        let packet = encode_udp(&target, b"abc").unwrap();
        let header = parse_udp(&packet).unwrap();
        assert_eq!(header.frag, 0);
        assert_eq!(header.target, target);
        assert_eq!(&packet[header.header_len..], b"abc");

        let v4 = SocksTarget::V4(Ipv4Addr::new(1, 2, 3, 4), 443);
        let packet = encode_udp(&v4, b"z").unwrap();
        assert_eq!(parse_udp(&packet).unwrap().target, v4);
    }

    #[tokio::test]
    async fn client_connects_with_and_without_a_password() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for expect_auth in [false, true] {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut greeting = [0u8; 2];
                sock.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[0], 0x05);
                let mut methods = vec![0u8; greeting[1] as usize];
                sock.read_exact(&mut methods).await.unwrap();
                if expect_auth {
                    assert!(methods.contains(&0x02));
                    sock.write_all(&[0x05, 0x02]).await.unwrap();
                    let mut ver = [0u8; 2];
                    sock.read_exact(&mut ver).await.unwrap();
                    let mut user = vec![0u8; ver[1] as usize];
                    sock.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    sock.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    sock.read_exact(&mut pass).await.unwrap();
                    assert_eq!(user, b"alice");
                    assert_eq!(pass, b"secret");
                    sock.write_all(&[0x01, 0x00]).await.unwrap();
                } else {
                    sock.write_all(&[0x05, 0x00]).await.unwrap();
                }
                let mut head = [0u8; 4];
                sock.read_exact(&mut head).await.unwrap();
                assert_eq!(head[1], CMD_CONNECT);
                assert_eq!(head[3], ATYP_DOMAIN);
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await.unwrap();
                let mut host = vec![0u8; len[0] as usize + 2];
                sock.read_exact(&mut host).await.unwrap();
                assert_eq!(&host[..len[0] as usize], b"example.com");
                sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                    .await
                    .unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let bound = client_handshake(
            &mut client,
            &proxy(None, None),
            &SocksTarget::Domain("example.com".into(), 443),
            CMD_CONNECT,
        )
        .await
        .unwrap();
        assert_eq!(
            bound,
            SocksAddr::Ip(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8080)))
        );

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_handshake(
            &mut client,
            &proxy(Some("alice"), Some("secret")),
            &SocksTarget::Domain("example.com".into(), 443),
            CMD_CONNECT,
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_associate_echoes_one_datagram() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], CMD_UDP_ASSOCIATE);
            let mut rest = [0u8; 6];
            sock.read_exact(&mut rest).await.unwrap();
            let octets = udp_addr.ip().to_string();
            let v4: Ipv4Addr = octets.parse().unwrap();
            let port = udp_addr.port().to_be_bytes();
            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&v4.octets());
            reply.extend_from_slice(&port);
            sock.write_all(&reply).await.unwrap();

            let mut buf = [0u8; 2048];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let header = parse_udp(&buf[..n]).unwrap();
            assert_eq!(&buf[header.header_len..n], b"ping");
            let back = encode_udp(&header.target, b"pong").unwrap();
            udp.send_to(&back, peer).await.unwrap();
            // Keep the control connection until the client finishes.
            let _ = sock.read(&mut buf).await;
        });

        let control = TcpStream::connect(addr).await.unwrap();
        let assoc = Socks5Udp::open(&proxy(None, None), control).await.unwrap();
        let target = SocksTarget::V4(Ipv4Addr::new(1, 2, 3, 4), 53);
        assoc.send_payload(&target, b"ping").await.unwrap();
        let mut buf = [0u8; 2048];
        let (got, n) = assoc.recv_payload(&mut buf).await.unwrap();
        assert_eq!(got, target);
        assert_eq!(&buf[..n], b"pong");
        drop(assoc);
        let _ = server.await;
    }
}
