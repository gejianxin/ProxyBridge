//! Map a local TCP or UDP port to a process image via the IP helper tables.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::process::ProcessInfo;

pub fn lookup_tcp(peer: SocketAddr) -> Option<ProcessInfo> {
    let rows = tcp_rows()?;
    let pid = rows.into_iter().find_map(|row| {
        let addr = SocketAddr::from((ipv4(row.dwLocalAddr), port(row.dwLocalPort)));
        (addr == peer).then_some(row.dwOwningPid)
    })?;
    Some(info(pid))
}

pub fn lookup_udp(local: SocketAddr) -> Option<ProcessInfo> {
    let rows = udp_rows()?;
    let pid = rows.into_iter().find_map(|row| {
        let addr = SocketAddr::from((ipv4(row.dwLocalAddr), port(row.dwLocalPort)));
        (addr == local).then_some(row.dwOwningPid)
    })?;
    Some(info(pid))
}

fn info(pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        exe: image_path(pid).unwrap_or_default(),
    }
}

fn ipv4(value: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from_be(value)))
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn tcp_rows() -> Option<Vec<MIB_TCPROW_OWNER_PID>> {
    unsafe {
        let mut size = 0u32;
        let first = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if rc != NO_ERROR || buf.len() < 4 {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        if count == 0 {
            return Some(Vec::new());
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);
        Some(rows.to_vec())
    }
}

fn udp_rows() -> Option<Vec<MIB_UDPROW_OWNER_PID>> {
    unsafe {
        let mut size = 0u32;
        let first = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            UDP_TABLE_OWNER_PID,
            0,
        );
        if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            u32::from(AF_INET),
            UDP_TABLE_OWNER_PID,
            0,
        );
        if rc != NO_ERROR || buf.len() < 4 {
            return None;
        }
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        if count == 0 {
            return Some(Vec::new());
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), count);
        Some(rows.to_vec())
    }
}

fn image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}
