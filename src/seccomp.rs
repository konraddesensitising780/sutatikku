use anyhow::{Context, Result, anyhow};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpNotifReq};
use log::warn;
use nix::errno::Errno;
use nix::ioctl_write_ptr;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::PathBuf;
use thiserror::Error;
use std::fs::{File, OpenOptions};

use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::unistd::Pid;
use std::io::IoSliceMut;

#[derive(Debug, Error)]
pub enum PeekError {
    #[error("Syscall error: {0}")]
    SyscallError(Errno),
    #[error("Memory access denied for pid {0}")]
    MemoryDenied(u32),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

pub fn read_process_string(pid: u32, addr: u64) -> Result<Vec<u8>, PeekError> {
    const MAX_LEN: usize = 4096;
    const CHUNK_SIZE: usize = 256;
    let mut result = Vec::new();
    let mut offset = 0;

    while result.len() < MAX_LEN {
        let current_chunk_size = CHUNK_SIZE.min(MAX_LEN - result.len());
        let mut buffer = vec![0u8; current_chunk_size];
        let mut local_iovec = [IoSliceMut::new(&mut buffer)];
        let remote_iovec = [RemoteIoVec {
            base: (addr as usize).saturating_add(offset),
            len: current_chunk_size,
        }];

        let bytes_read = process_vm_readv(Pid::from_raw(pid as i32), &mut local_iovec, &remote_iovec).map_err(|e| {
            match e {
                Errno::EPERM => PeekError::MemoryDenied(pid),
                Errno::ESRCH => PeekError::SyscallError(Errno::EINVAL),
                _ => PeekError::SyscallError(e),
            }
        })?;

        let actual_data = &buffer[..bytes_read.min(buffer.len())];
        if let Some(nul_pos) = actual_data.iter().position(|&b| b == 0) {
            result.extend_from_slice(&actual_data[..nul_pos]);
            return Ok(result);
        } else {
            result.extend_from_slice(actual_data);
            offset = offset.saturating_add(actual_data.len());
        }
    }

    Err(PeekError::SyscallError(Errno::ENAMETOOLONG))
}

pub fn read_process_path(pid: u32, addr: u64) -> Result<PathBuf, PeekError> {
    let bytes = read_process_string(pid, addr)?;
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

pub struct ProcessMemory(File);

impl ProcessMemory {
    pub fn open(pid: u32) -> Result<Self, PeekError> {
        let path = format!("/proc/{}/mem", pid);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => PeekError::SyscallError(Errno::EINVAL),
                std::io::ErrorKind::PermissionDenied => PeekError::MemoryDenied(pid),
                _ => PeekError::Unexpected(anyhow!(e).context(format!("Opening {} failed", path))),
            })?;
        Ok(ProcessMemory(file))
    }

    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), PeekError> {
        let mut written = 0;
        while written < data.len() {
            let n = match nix::sys::uio::pwrite(
                &self.0,
                &data[written..],
                (addr + written as u64) as i64,
            ) {
                Ok(n) => n,
                Err(e) => match e {
                    Errno::EFAULT | Errno::EINVAL => return Err(PeekError::SyscallError(e)),
                    Errno::EAGAIN | Errno::EINTR => continue,
                    _ => return Err(PeekError::Unexpected(anyhow!(e).context("pwrite failed"))),
                },
            };
            written += n;
        }
        Ok(())
    }

    pub fn write<T: bytemuck::NoUninit>(&mut self, addr: u64, value: &T) -> Result<(), PeekError> {
        self.write_bytes(addr, bytemuck::bytes_of(value))
    }
}

pub fn setup_seccomp_hook(syscalls: &[i32]) -> Result<RawFd> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow).context("Failed to init seccomp")?;
    for &nr in syscalls {
        filter.add_rule(ScmpAction::Notify, nr).with_context(|| format!("Failed to add notify rule for syscall {nr}"))?;
    }
    filter.load().context("Failed to load seccomp filter")?;
    Ok(filter.get_notify_fd()?)
}

pub fn run_seccomp_monitor<F>(notif_fd: BorrowedFd, handler: F) -> Result<()>
where
    F: Fn(ScmpNotifReq),
{
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).context("Epoll init failed")?;
    let event = EpollEvent::new(EpollFlags::EPOLLIN, notif_fd.as_raw_fd() as u64);
    epoll.add(&notif_fd, event).context("Epoll add failed")?;

    let mut events = vec![EpollEvent::new(EpollFlags::empty(), 0); 16];
    loop {
        match epoll.wait(&mut events, 100u16) {
            Ok(0) => continue,
            Ok(n) => {
                for e in events.iter().take(n) {
                    if e.events().intersects(EpollFlags::EPOLLHUP | EpollFlags::EPOLLERR) {
                        return Ok(());
                    }
                    if e.events().contains(EpollFlags::EPOLLIN) {
                        match ScmpNotifReq::receive(notif_fd.as_raw_fd()) {
                            Ok(req) => handler(req),
                            Err(e) => {
                                warn!("Failed to receive seccomp notification: {:?}", e);
                                return Ok(());
                            }
                        }
                    }
                }
            }
            Err(e) if e == Errno::EINTR => continue,
            Err(e) => return Err(anyhow::Error::from(e).context("Epoll wait error")),
        }
    }
}

const SECCOMP_IOC_MAGIC: u8 = b'!';
const SECCOMP_IOCTL_NOTIF_ADDFD_MODE: u8 = 3;
ioctl_write_ptr!(
    seccomp_notif_addfd_ioctl,
    SECCOMP_IOC_MAGIC,
    SECCOMP_IOCTL_NOTIF_ADDFD_MODE,
    libseccomp_sys::seccomp_notif_addfd
);

pub fn inject_fd_and_respond(notif_fd: BorrowedFd, req_id: u64, source_fd: RawFd, flags: u32) -> Result<i32> {
    let addfd_data = libseccomp_sys::seccomp_notif_addfd {
        id: req_id,
        flags: libseccomp_sys::SECCOMP_ADDFD_FLAG_SEND,
        srcfd: source_fd as u32,
        newfd: 0,
        newfd_flags: flags,
    };
    let res = unsafe { seccomp_notif_addfd_ioctl(notif_fd.as_raw_fd(), &addfd_data) };
    res.map_err(|e| anyhow!(e).context("Failed to inject FD via seccomp ioctl"))
}
