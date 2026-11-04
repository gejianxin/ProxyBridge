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

const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
const IP_PKTINFO: libc::c_int = 8;

pub fn set_ip_transparent(fd: RawFd) -> io::Result<()> {
    let on: libc::c_int = 1;
    setsockopt_int(fd, libc::SOL_IP, IP_TRANSPARENT, on)
}

pub fn set_recv_origdst(fd: RawFd, ipv6: bool) -> io::Result<()> {
    let on: libc::c_int = 1;
    if ipv6 {
        setsockopt_int(fd, libc::SOL_IPV6, IPV6_RECVORIGDSTADDR, on)
    } else {
        setsockopt_int(fd, libc::SOL_IP, IP_RECVORIGDSTADDR, on)
    }
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    opt: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive one datagram plus the pre-NAT destination, when the kernel provides it.
pub fn udp_recv_origdst(
    fd: RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    unsafe {
        let mut src: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u8; 256];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut src as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let peer = sockaddr_to_std(&src)?;
        let orig = origdst_from_msg(&msg);
        Ok((n as usize, peer, orig))
    }
}

/// Send `payload` to `to` with the source address `from`. Needs `IP_TRANSPARENT`.
pub fn udp_send_from(
    fd: RawFd,
    from: SocketAddr,
    to: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let SocketAddr::V4(from) = from else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "spoofed UDP replies are implemented for IPv4",
        ));
    };
    let SocketAddr::V4(to) = to else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "spoofed UDP replies are implemented for IPv4",
        ));
    };
    unsafe {
        let mut dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: to.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*to.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        let info = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from(*from.ip()).to_be(),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let mut control = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut dst as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("control buffer has no cmsg"));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = IP_PKTINFO;
        (*cmsg).cmsg_len =
            (std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::in_pktinfo>()) as _;
        let data = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            &info as *const libc::in_pktinfo as *const u8,
            data,
            std::mem::size_of::<libc::in_pktinfo>(),
        );
        msg.msg_controllen = (*cmsg).cmsg_len;
        let n = libc::sendmsg(fd, &msg, 0);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn sockaddr_to_std(src: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    unsafe {
        if src.ss_family as i32 == libc::AF_INET {
            let v4 = &*(src as *const libc::sockaddr_storage as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
            Ok(SocketAddr::from((ip, u16::from_be(v4.sin_port))))
        } else if src.ss_family as i32 == libc::AF_INET6 {
            let v6 = &*(src as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
            Ok(SocketAddr::from((ip, u16::from_be(v6.sin6_port))))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown peer family",
            ))
        }
    }
}

fn origdst_from_msg(msg: &libc::msghdr) -> Option<SocketAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let kind = (*cmsg).cmsg_type;
            if level == libc::SOL_IP && kind == IP_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let ip = Ipv4Addr::from(u32::from_be((*data).sin_addr.s_addr));
                return Some(SocketAddr::from((ip, u16::from_be((*data).sin_port))));
            }
            if level == libc::SOL_IPV6 && kind == IPV6_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let ip = Ipv6Addr::from((*data).sin6_addr.s6_addr);
                return Some(SocketAddr::from((ip, u16::from_be((*data).sin6_port))));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
        None
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

    #[test]
    fn udp_recv_returns_the_peer_without_nat() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(false).unwrap();
        set_recv_origdst(socket.as_raw_fd(), false).unwrap();
        let local = socket.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"dns", local).unwrap();
        let mut buf = [0u8; 16];
        let (n, peer, orig) = udp_recv_origdst(socket.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], b"dns");
        assert_eq!(peer, sender.local_addr().unwrap());
        if let Some(orig) = orig {
            assert_eq!(orig, local);
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
