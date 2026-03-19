use anyhow::Result;
use libseccomp::{ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use log::{debug, warn};
use nix::errno::Errno;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::ffi::CString;
use bytemuck::NoUninit;

use crate::seccomp::{read_process_path, inject_fd_and_respond, ProcessMemory};

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct StatBytes(libc::stat);
unsafe impl NoUninit for StatBytes {}

pub struct RedirectionMonitor {
    bundle_root: PathBuf,
}

impl RedirectionMonitor {
    pub fn new(bundle_root: PathBuf) -> Self {
        Self { bundle_root }
    }

    pub fn handle_notification(&self, req: &ScmpNotifReq, notif_fd: RawFd) {
        let res = self.dispatch_syscall(req, notif_fd);
        match res {
            Ok(handled) => {
                if !handled {
                    let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
                    let _ = resp.respond(notif_fd);
                }
            }
            Err(e) => {
                warn!("Error handling syscall: {:?}", e);
                let resp = ScmpNotifResp::new_error(req.id, libc::EINVAL, ScmpNotifRespFlags::empty());
                let _ = resp.respond(notif_fd);
            }
        }
    }

    fn dispatch_syscall(&self, req: &ScmpNotifReq, notif_fd: RawFd) -> Result<bool> {
        let nr = req.data.syscall.as_raw_syscall() as i64;
        if nr == libc::SYS_open {
            self.handle_open(req, notif_fd, 0, 1, 2)
        } else if nr == libc::SYS_openat {
            self.handle_openat(req, notif_fd, 0, 1, 2, 3)
        } else if nr == libc::SYS_newfstatat {
            self.handle_statat(req, notif_fd, 0, 1, 2, 3)
        } else if nr == libc::SYS_access {
            self.handle_access(req, notif_fd, 0, 1)
        } else if nr == libc::SYS_faccessat || nr == libc::SYS_faccessat2 {
            self.handle_accessat(req, notif_fd, 0, 1, 2, 3)
        } else {
            Ok(false)
        }
    }

    fn handle_open(&self, req: &ScmpNotifReq, notif_fd: RawFd, path_arg: usize, flags_arg: usize, mode_arg: usize) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if let Some(redirected) = self.should_redirect(&path) {
            debug!("Redirecting open {:?} -> {:?}", path, redirected);
            let oflags = req.data.args[flags_arg] as i32;
            let mode = req.data.args[mode_arg] as u32;
            
            let fd = nix::fcntl::open(&redirected, nix::fcntl::OFlag::from_bits_truncate(oflags), nix::sys::stat::Mode::from_bits_truncate(mode))?;
            inject_fd_and_respond(unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) }, req.id, fd, 0)?;
            let _ = unsafe { libc::close(fd) };
            return Ok(true);
        }
        Ok(false)
    }

    fn handle_openat(&self, req: &ScmpNotifReq, notif_fd: RawFd, _dirfd_arg: usize, path_arg: usize, flags_arg: usize, mode_arg: usize) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(redirected) = self.should_redirect(&path) {
                debug!("Redirecting openat {:?} -> {:?}", path, redirected);
                let oflags = req.data.args[flags_arg] as i32;
                let mode = req.data.args[mode_arg] as u32;
                
                let fd = nix::fcntl::open(&redirected, nix::fcntl::OFlag::from_bits_truncate(oflags), nix::sys::stat::Mode::from_bits_truncate(mode))?;
                inject_fd_and_respond(unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) }, req.id, fd, 0)?;
                let _ = unsafe { libc::close(fd) };
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn handle_statat(&self, req: &ScmpNotifReq, notif_fd: RawFd, _dirfd_arg: usize, path_arg: usize, statbuf_arg: usize, _flags_arg: usize) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(redirected) = self.should_redirect(&path) {
                debug!("Redirecting stat {:?} -> {:?}", path, redirected);
                let mut statbuf = std::mem::MaybeUninit::<libc::stat>::uninit();
                let res = unsafe { libc::stat(CString::new(redirected.to_str().unwrap())?.as_ptr(), statbuf.as_mut_ptr()) };
                if res == 0 {
                    let mut mem = ProcessMemory::open(req.pid)?;
                    mem.write(req.data.args[statbuf_arg], &StatBytes(unsafe { statbuf.assume_init() }))?;
                    let resp = ScmpNotifResp::new(req.id, 0, 0, ScmpNotifRespFlags::empty().bits());
                    resp.respond(notif_fd)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn handle_access(&self, req: &ScmpNotifReq, notif_fd: RawFd, path_arg: usize, mode_arg: usize) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if let Some(redirected) = self.should_redirect(&path) {
            let mode = req.data.args[mode_arg] as i32;
            let res = unsafe { libc::access(CString::new(redirected.to_str().unwrap())?.as_ptr(), mode) };
            let errno = if res == -1 { Errno::last_raw() } else { 0 };
            let resp = ScmpNotifResp::new(req.id, res as i64, (-errno).into(), ScmpNotifRespFlags::empty().bits());
            resp.respond(notif_fd)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn handle_accessat(&self, req: &ScmpNotifReq, notif_fd: RawFd, _dirfd_arg: usize, path_arg: usize, mode_arg: usize, flags_arg: usize) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(redirected) = self.should_redirect(&path) {
                let mode = req.data.args[mode_arg] as i32;
                let flags = req.data.args[flags_arg] as i32;
                let res = unsafe { libc::faccessat(libc::AT_FDCWD, CString::new(redirected.to_str().unwrap())?.as_ptr(), mode, flags) };
                let errno = if res == -1 { Errno::last_raw() } else { 0 };
                let resp = ScmpNotifResp::new(req.id, res as i64, (-errno).into(), ScmpNotifRespFlags::empty().bits());
                resp.respond(notif_fd)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn should_redirect(&self, path: &Path) -> Option<PathBuf> {
        if !path.is_absolute() { return None; }
        let relative = path.strip_prefix("/").ok()?;
        let bundle_path = self.bundle_root.join(relative);
        if bundle_path.exists() {
            Some(bundle_path)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::{self, File};

    #[test]
    fn test_should_redirect() {
        let temp = tempdir().unwrap();
        let bundle_root = temp.path().to_path_buf();
        let monitor = RedirectionMonitor::new(bundle_root.clone());

        let test_file = bundle_root.join("etc/test.txt");
        fs::create_dir_all(test_file.parent().unwrap()).unwrap();
        File::create(&test_file).unwrap();

        assert_eq!(
            monitor.should_redirect(Path::new("/etc/test.txt")),
            Some(test_file)
        );
        assert_eq!(
            monitor.should_redirect(Path::new("/etc/not_exists.txt")),
            None
        );
        assert_eq!(
            monitor.should_redirect(Path::new("relative/path")),
            None
        );
    }
}
