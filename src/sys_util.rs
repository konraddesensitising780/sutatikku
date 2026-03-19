use anyhow::{Context, Result, bail};
use nix::cmsg_space;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub struct UnixSocket {
    fd: OwnedFd,
}

impl UnixSocket {
    pub fn ping(&self) -> Result<()> {
        let buf = [0u8];
        unistd::write(&self.fd, &buf).context("Sync write failed")?;
        Ok(())
    }

    pub fn pong(&self) -> Result<()> {
        let mut buf = [0u8];
        let n = unistd::read(self.fd.as_raw_fd(), &mut buf).context("Sync read failed")?;
        if n == 0 { bail!("Peer disconnected during sync"); }
        Ok(())
    }

    pub fn send_fd(&self, fd: RawFd) -> Result<()> {
        let iov = [IoSlice::new(&[0u8])];
        let fds = [fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];
        sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None).context("send_fd failed")?;
        Ok(())
    }

    pub fn recv_fd(&self) -> Result<Vec<OwnedFd>> {
        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_space = cmsg_space!([RawFd; 1]);

        let msg = recvmsg::<()>(self.fd.as_raw_fd(), &mut iov, Some(&mut cmsg_space), MsgFlags::empty()).context("recv_fd failed")?;
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                if !fds.is_empty() {
                    return Ok(fds.into_iter().map(|f| unsafe { OwnedFd::from_raw_fd(f) }).collect());
                }
            }
        }
        bail!("No FD received in cmsg");
    }
}

pub fn create_unix_socketpair() -> Result<(UnixSocket, UnixSocket)> {
    let (a, b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC).context("socketpair failed")?;
    Ok((UnixSocket { fd: a }, UnixSocket { fd: b }))
}
