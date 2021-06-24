use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

use tokio::io;
use tokio::net::UdpSocket;

use nix::{
    errno::Errno,
    sys::{
        socket::{recvmsg, setsockopt, sockopt::Ipv4PacketInfo, ControlMessageOwned, MsgFlags},
        uio::IoVec,
    },
};

pub use nm::*;

mod nm;

pub fn udp_enable_pktinfo(socket: &UdpSocket) -> io::Result<()> {
    setsockopt(socket.as_raw_fd(), Ipv4PacketInfo, &true)
        .map_err(|e| e.as_errno().unwrap_or(Errno::UnknownErrno))?;
    Ok(())
}

pub async fn udp_read(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, Option<NetIfIndex>)> {
    let mut cmsg_buf = Vec::with_capacity(128);
    loop {
        socket.readable().await?;

        match recvmsg(
            socket.as_raw_fd(),
            &[IoVec::from_mut_slice(buffer)],
            Some(&mut cmsg_buf),
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(r) => {
                let mut ifindex: Option<NetIfIndex> = None;
                for c in r.cmsgs() {
                    if let ControlMessageOwned::Ipv4PacketInfo(i) = c {
                        ifindex = Some(i.ipi_ifindex as NetIfIndex);
                        break;
                    }
                }
                return Ok((r.bytes, ifindex));
            }
            Err(e) => {
                let errno = e.as_errno().unwrap_or(Errno::UnknownErrno);
                if errno == Errno::EAGAIN {
                    continue;
                } else {
                    return Err(io::Error::from(errno));
                }
            }
        }
    }
}

#[allow(dead_code)]
pub fn if_index_to_name(ifindex: NetIfIndex) -> Option<String> {
    let mut buf: MaybeUninit<[MaybeUninit<u8>; nix::libc::IF_NAMESIZE]> =
        unsafe { MaybeUninit::uninit().assume_init() };
    unsafe {
        if nix::libc::if_indextoname(ifindex as u32, buf.as_mut_ptr() as *mut i8)
            == buf.as_mut_ptr() as *mut i8
        {
            let n = nix::libc::strlen(buf.as_ptr() as *const i8);
            let s = std::slice::from_raw_parts(buf.as_ptr() as *const u8, n);
            Some(String::from_utf8_lossy(s).to_string())
        } else {
            None
        }
    }
}
