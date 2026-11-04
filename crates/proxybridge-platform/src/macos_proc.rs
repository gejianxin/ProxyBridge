//! Match a TCP/UDP local port to a process using libproc.
//!
//! The structs follow `bsd/sys/proc_info.h` in Apple's xnu (64-bit). Both
//! Intel and Apple Silicon are LP64, so one layout covers both targets.
//! A Mac is still required to confirm a live socket lookup; `cargo check`
//! only proves the calls typecheck.

use std::net::{IpAddr, SocketAddr};

use crate::process::ProcessInfo;

const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROC_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;

const _: () = assert!(std::mem::size_of::<In4In6>() == 16);

#[derive(Clone, Copy)]
#[repr(C)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
struct In4In6 {
    pad: [u32; 3],
    addr4: [u8; 4],
}

#[repr(C)]
struct InSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    _pad: u16,
    rfu_1: u32,
    insi_faddr: In4In6,
    insi_laddr: In4In6,
}

#[repr(C)]
struct SocketInfoPrefix {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    pri_in: InSockInfo,
}

#[repr(C)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfoPrefix,
}

extern "C" {
    fn proc_listpids(
        kind: u32,
        typeinfo: u32,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidfdinfo(
        pid: i32,
        fd: i32,
        flavor: i32,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
}

pub fn lookup(peer: SocketAddr) -> Option<ProcessInfo> {
    let pids = all_pids()?;
    for pid in pids {
        if let Some(info) = socket_owned_by(pid, peer) {
            return Some(info);
        }
    }
    None
}

fn all_pids() -> Option<Vec<i32>> {
    unsafe {
        let bytes = proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if bytes <= 0 {
            return None;
        }
        let mut buf = vec![0i32; (bytes as usize / 4) + 8];
        let wrote = proc_listpids(
            PROC_ALL_PIDS,
            0,
            buf.as_mut_ptr().cast(),
            (buf.len() * 4) as i32,
        );
        if wrote <= 0 {
            return None;
        }
        let n = wrote as usize / 4;
        Some(buf.into_iter().take(n).filter(|pid| *pid > 0).collect())
    }
}

fn socket_owned_by(pid: i32, peer: SocketAddr) -> Option<ProcessInfo> {
    unsafe {
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        if bytes <= 0 {
            return None;
        }
        let count = bytes as usize / std::mem::size_of::<ProcFdInfo>();
        let mut fds = vec![
            ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            count + 1
        ];
        let wrote = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            (fds.len() * std::mem::size_of::<ProcFdInfo>()) as i32,
        );
        if wrote <= 0 {
            return None;
        }
        let n = wrote as usize / std::mem::size_of::<ProcFdInfo>();
        for fd in fds.into_iter().take(n) {
            if fd.proc_fdtype != PROC_FDTYPE_SOCKET {
                continue;
            }
            // The kernel struct is larger than the prefix we interpret.
            // An 8 KiB buffer keeps the write inside the allocation.
            let mut buf = vec![0u8; 8192];
            let got = proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                buf.as_mut_ptr().cast(),
                buf.len() as i32,
            );
            if got < std::mem::size_of::<SocketFdInfo>() as i32 {
                continue;
            }
            let info = &*(buf.as_ptr() as *const SocketFdInfo);
            let kind = info.psi.soi_kind;
            if kind != SOCKINFO_IN && kind != SOCKINFO_TCP {
                continue;
            }
            if socket_matches(&info.psi.pri_in, peer) {
                return Some(ProcessInfo {
                    pid: pid as u32,
                    exe: pid_path(pid).unwrap_or_default(),
                });
            }
        }
        None
    }
}

fn socket_matches(info: &InSockInfo, peer: SocketAddr) -> bool {
    let port = u16::from_be(info.insi_lport as u16);
    if port != peer.port() {
        return false;
    }
    match peer.ip() {
        IpAddr::V4(ip) => info.insi_laddr.addr4 == ip.octets(),
        IpAddr::V6(ip) => {
            if info.insi_vflag & 0x2 == 0 {
                return false;
            }
            let mut raw = [0u8; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&info.insi_laddr) as *const In4In6 as *const u8,
                    raw.as_mut_ptr(),
                    16,
                );
            }
            raw == ip.octets()
        }
    }
}

fn pid_path(pid: i32) -> Option<String> {
    unsafe {
        let mut buf = vec![0u8; 4096];
        let n = proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32);
        if n <= 0 {
            return None;
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
        }
        Some(
            String::from_utf8_lossy(&buf)
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}
