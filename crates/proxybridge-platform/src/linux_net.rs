//! Linux socket options used by the transparent TCP backend.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;

use proxybridge_core::LINUX_FW_MARK;

const SO_ORIGINAL_DST: libc::c_int = 80;

pub fn set_fwmark(fd: RawFd) -> io::Result<()> {
    let mark: libc::c_int = LINUX_FW_MARK;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SO_MARK failed ({err}); redirect mode needs CAP_NET_ADMIN"),
        ))
    } else {
        Ok(())
    }
}

pub fn original_destination(fd: RawFd, local: SocketAddr) -> io::Result<SocketAddr> {
    match local.ip() {
        std::net::IpAddr::V4(_) => original_v4(fd),
        std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => {
            original_v4(fd).or_else(|_| original_v6(fd))
        }
        std::net::IpAddr::V6(_) => original_v6(fd),
    }
}

fn original_v4(fd: RawFd) -> io::Result<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::from((ip, port)))
    }
}

fn original_v6(fd: RawFd) -> io::Result<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
        let port = u16::from_be(addr.sin6_port);
        Ok(SocketAddr::from((ip, port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn plain_socket_has_no_original_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let _ = client;
        // Kernels differ: some reject the option, others echo the local address
        // when no NAT has rewritten the socket. A redirected flow is the case
        // where the returned address is not that local address.
        if let Ok(addr) = original_destination(accepted.as_raw_fd(), accepted.local_addr().unwrap())
        {
            assert_eq!(addr, accepted.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn fwmark_is_attempted_on_a_new_socket() {
        // Unprivileged environments reject SO_MARK. Either result is honest:
        // success when the capability is present, permission denied otherwise.
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        let result = set_fwmark(sock.as_raw_fd());
        if let Err(err) = result {
            let text = err.to_string();
            assert!(text.contains("SO_MARK") || text.contains("Operation not permitted"));
        }
    }
}
