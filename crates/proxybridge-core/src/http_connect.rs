//! HTTP CONNECT tunnels (RFC 7231) with optional Basic authentication.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::ProxyEndpoint;
use crate::error::{Error, Result};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Open a CONNECT tunnel on an already connected proxy socket.
pub async fn http_connect(
    stream: &mut TcpStream,
    proxy: &ProxyEndpoint,
    host: &str,
    port: u16,
) -> Result<()> {
    match tokio::time::timeout(TIMEOUT, http_connect_inner(stream, proxy, host, port)).await {
        Ok(inner) => inner,
        Err(_) => Err(Error::Http("timed out during CONNECT".into())),
    }
}

async fn http_connect_inner(
    stream: &mut TcpStream,
    proxy: &ProxyEndpoint,
    host: &str,
    port: u16,
) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == b' ' || b == b'\0')
    {
        return Err(Error::Http(format!("refusing CONNECT host '{host}'")));
    }
    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(user) = proxy.username.as_deref().filter(|u| !u.is_empty()) {
        let pass = proxy.password.as_deref().unwrap_or("");
        if user.bytes().any(|b| b == b'\r' || b == b'\n')
            || pass.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            return Err(Error::Http(
                "username and password cannot contain newlines".into(),
            ));
        }
        let token = base64(format!("{user}:{pass}").as_bytes());
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&token);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    let header_end = loop {
        if buf.len() > 16 * 1024 {
            return Err(Error::Http("proxy response headers are too large".into()));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if n == 0 {
            return Err(Error::Http("proxy closed during CONNECT".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
    };
    let header = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| Error::Http("proxy response is not UTF-8".into()))?;
    let status = header
        .lines()
        .next()
        .ok_or_else(|| Error::Http("empty proxy response".into()))?;
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| Error::Http(format!("unrecognized status line '{status}'")))?;
    if !(200..300).contains(&code) {
        return Err(Error::Http(format!("CONNECT rejected with status {code}")));
    }
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let rem = data.len() - i;
        let mut n = (data[i] as u32) << 16;
        if rem == 2 {
            n |= (data[i + 1] as u32) << 8;
        }
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if rem == 2 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyKind;
    use tokio::net::TcpListener;

    #[test]
    fn base64_known_vector() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    #[tokio::test]
    async fn connect_sends_basic_auth_and_accepts_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(text.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let proxy = ProxyEndpoint {
            name: "h".into(),
            kind: ProxyKind::Http,
            host: "127.0.0.1".into(),
            port: addr.port(),
            username: Some("user".into()),
            password: Some("pass".into()),
            send_domain: true,
        };
        http_connect(&mut stream, &proxy, "example.com", 443)
            .await
            .unwrap();
        server.await.unwrap();
    }
}
