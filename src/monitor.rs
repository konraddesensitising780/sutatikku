use anyhow::Result;
use bytemuck::NoUninit;
use libseccomp::{ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use log::{debug, warn};
use nix::errno::Errno;
use std::ffi::CString;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::runner::BundleRoot;
use crate::seccomp::{inject_fd_and_respond, read_process_path};
use std::collections::HashSet;
use std::sync::Mutex;

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct StatBytes(nix::sys::stat::FileStat);
unsafe impl NoUninit for StatBytes {}

pub struct RecordingMonitor {
    pub target_pid: u32,
    pub opened_paths: Mutex<HashSet<PathBuf>>,
}

impl RecordingMonitor {
    pub fn new(target_pid: u32) -> Self {
        Self {
            target_pid,
            opened_paths: Mutex::new(HashSet::new()),
        }
    }

    pub fn handle_notification(&self, req: &ScmpNotifReq, notif_fd: RawFd) {
        if req.pid != self.target_pid {
            let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
            let _ = resp.respond(notif_fd);
            return;
        }

        let nr = req.data.syscall.as_raw_syscall() as i64;
        let path_arg_idx = if nr == libc::SYS_open {
            Some(0)
        } else if nr == libc::SYS_openat {
            Some(1)
        } else {
            None
        };

        if let Some(idx) = path_arg_idx {
            if let Ok(path) = read_process_path(req.pid, req.data.args[idx]) {
                if path.is_absolute() && path.exists() {
                    self.opened_paths.lock().unwrap().insert(path);
                }
            }
        }

        let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        let _ = resp.respond(notif_fd);
    }
}

pub struct RedirectionMonitor {
    pub target_pid: u32,
    bundle_root: BundleRoot,
    prefer_host: HashSet<PathBuf>,
}

impl RedirectionMonitor {
    pub fn new_with_root(
        target_pid: u32,
        bundle_root: BundleRoot,
        prefer_host: HashSet<PathBuf>,
    ) -> Self {
        Self {
            target_pid,
            bundle_root,
            prefer_host,
        }
    }

    pub fn handle_notification(&self, req: &ScmpNotifReq, notif_fd: RawFd) {
        if req.pid != self.target_pid {
            let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
            let _ = resp.respond(notif_fd);
            return;
        }

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
                let resp =
                    ScmpNotifResp::new_error(req.id, libc::EINVAL, ScmpNotifRespFlags::empty());
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
        } else if nr == libc::SYS_getdents || nr == libc::SYS_getdents64 {
            self.handle_getdents(req, notif_fd)
        } else {
            Ok(false)
        }
    }

    fn handle_getdents(&self, req: &ScmpNotifReq, notif_fd: RawFd) -> Result<bool> {
        if let BundleRoot::InMemory(_) = &self.bundle_root {
            debug!("Blocking getdents for in-memory bundle (not implemented)");
            let resp = ScmpNotifResp::new_error(req.id, libc::ENOSYS, ScmpNotifRespFlags::empty());
            resp.respond(notif_fd)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn handle_open(
        &self,
        req: &ScmpNotifReq,
        notif_fd: RawFd,
        path_arg: usize,
        flags_arg: usize,
        mode_arg: usize,
    ) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if let Some(relative) = self.get_redirection_path(&path) {
            match &self.bundle_root {
                BundleRoot::TempDir(td) => {
                    let redirected = td.path().join(&relative);
                    if redirected.exists() {
                        debug!("Redirecting open {:?} -> {:?}", path, redirected);
                        let oflags = req.data.args[flags_arg] as i32;
                        let mode = req.data.args[mode_arg] as u32;
                        let fd = nix::fcntl::open(
                            &redirected,
                            nix::fcntl::OFlag::from_bits_truncate(oflags),
                            nix::sys::stat::Mode::from_bits_truncate(mode),
                        )?;
                        inject_fd_and_respond(
                            unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) },
                            req.id,
                            fd,
                            0,
                        )?;
                        let _ = unsafe { libc::close(fd) };
                        return Ok(true);
                    }
                }
                BundleRoot::InMemory(_) => {
                    if let Some(data) = self.bundle_root.get_file(&relative) {
                        debug!(
                            "Redirecting open {:?} to in-memory data ({} bytes)",
                            path,
                            data.len()
                        );
                        let mem_fd = nix::sys::memfd::memfd_create(
                            &CString::new("bundled_file")?,
                            nix::sys::memfd::MemFdCreateFlag::MFD_CLOEXEC,
                        )?;
                        nix::unistd::write(&mem_fd, data)?;
                        nix::unistd::lseek(mem_fd.as_raw_fd(), 0, nix::unistd::Whence::SeekSet)?;
                        inject_fd_and_respond(
                            unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) },
                            req.id,
                            mem_fd.as_raw_fd(),
                            0,
                        )?;
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_openat(
        &self,
        req: &ScmpNotifReq,
        notif_fd: RawFd,
        _dirfd_arg: usize,
        path_arg: usize,
        flags_arg: usize,
        mode_arg: usize,
    ) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(relative) = self.get_redirection_path(&path) {
                match &self.bundle_root {
                    BundleRoot::TempDir(td) => {
                        let redirected = td.path().join(&relative);
                        if redirected.exists() {
                            debug!("Redirecting openat {:?} -> {:?}", path, redirected);
                            let oflags = req.data.args[flags_arg] as i32;
                            let mode = req.data.args[mode_arg] as u32;
                            let fd = nix::fcntl::open(
                                &redirected,
                                nix::fcntl::OFlag::from_bits_truncate(oflags),
                                nix::sys::stat::Mode::from_bits_truncate(mode),
                            )?;
                            inject_fd_and_respond(
                                unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) },
                                req.id,
                                fd,
                                0,
                            )?;
                            let _ = unsafe { libc::close(fd) };
                            return Ok(true);
                        }
                    }
                    BundleRoot::InMemory(_) => {
                        if let Some(data) = self.bundle_root.get_file(&relative) {
                            debug!(
                                "Redirecting openat {:?} to in-memory data ({} bytes)",
                                path,
                                data.len()
                            );
                            let mem_fd = nix::sys::memfd::memfd_create(
                                &CString::new("bundled_file")?,
                                nix::sys::memfd::MemFdCreateFlag::MFD_CLOEXEC,
                            )?;
                            nix::unistd::write(&mem_fd, data)?;
                            nix::unistd::lseek(
                                mem_fd.as_raw_fd(),
                                0,
                                nix::unistd::Whence::SeekSet,
                            )?;
                            inject_fd_and_respond(
                                unsafe { std::os::fd::BorrowedFd::borrow_raw(notif_fd) },
                                req.id,
                                mem_fd.as_raw_fd(),
                                0,
                            )?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_statat(
        &self,
        req: &ScmpNotifReq,
        notif_fd: RawFd,
        _dirfd_arg: usize,
        path_arg: usize,
        statbuf_arg: usize,
        _flags_arg: usize,
    ) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(relative) = self.get_redirection_path(&path) {
                match &self.bundle_root {
                    BundleRoot::TempDir(td) => {
                        let redirected = td.path().join(&relative);
                        if redirected.exists() {
                            debug!("Redirecting stat {:?} -> {:?}", path, redirected);
                            let stat_res = nix::sys::stat::stat(&redirected)?;
                            crate::seccomp::write_process_memory(
                                req.pid,
                                req.data.args[statbuf_arg],
                                bytemuck::bytes_of(&StatBytes(stat_res)),
                            )?;
                            let resp = ScmpNotifResp::new(req.id, 0, 0, 0);
                            resp.respond(notif_fd)?;
                            return Ok(true);
                        }
                    }
                    BundleRoot::InMemory(_) => {
                        if let Some(data) = self.bundle_root.get_file(&relative) {
                            debug!(
                                "Emulating stat for in-memory {:?} ({} bytes)",
                                path,
                                data.len()
                            );
                            let mem_fd = nix::sys::memfd::memfd_create(
                                &CString::new("stat_fake")?,
                                nix::sys::memfd::MemFdCreateFlag::MFD_CLOEXEC,
                            )?;
                            nix::unistd::write(&mem_fd, data)?;
                            let stat_res = nix::sys::stat::fstat(mem_fd.as_raw_fd())?;
                            crate::seccomp::write_process_memory(
                                req.pid,
                                req.data.args[statbuf_arg],
                                bytemuck::bytes_of(&StatBytes(stat_res)),
                            )?;
                            let resp = ScmpNotifResp::new(req.id, 0, 0, 0);
                            resp.respond(notif_fd)?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_access(
        &self,
        req: &ScmpNotifReq,
        notif_fd: RawFd,
        path_arg: usize,
        mode_arg: usize,
    ) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if let Some(relative) = self.get_redirection_path(&path) {
            match &self.bundle_root {
                BundleRoot::TempDir(td) => {
                    let redirected = td.path().join(&relative);
                    if redirected.exists() {
                        debug!("Redirecting access {:?} to bundled file", path);
                        let mode = req.data.args[mode_arg] as i32;
                        let res = unsafe {
                            libc::access(CString::new(redirected.to_str().unwrap())?.as_ptr(), mode)
                        };
                        let errno = if res == -1 { Errno::last_raw() } else { 0 };
                        let resp = ScmpNotifResp::new(req.id, res as i64, (-errno).into(), 0);
                        resp.respond(notif_fd)?;
                        return Ok(true);
                    }
                }
                BundleRoot::InMemory(_) => {
                    if self.bundle_root.get_file(&relative).is_some() {
                        debug!("Emulating access for in-memory {:?}", path);
                        let resp = ScmpNotifResp::new(req.id, 0, 0, 0);
                        resp.respond(notif_fd)?;
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_accessat(
        &self,
        req: &ScmpNotifReq,
        notif_fd: RawFd,
        _dirfd_arg: usize,
        path_arg: usize,
        mode_arg: usize,
        flags_arg: usize,
    ) -> Result<bool> {
        let path = read_process_path(req.pid, req.data.args[path_arg])?;
        if path.is_absolute() {
            if let Some(relative) = self.get_redirection_path(&path) {
                match &self.bundle_root {
                    BundleRoot::TempDir(td) => {
                        let redirected = td.path().join(&relative);
                        if redirected.exists() {
                            debug!("Redirecting accessat {:?} to bundled file", path);
                            let mode = req.data.args[mode_arg] as i32;
                            let flags = req.data.args[flags_arg] as i32;
                            let res = unsafe {
                                libc::faccessat(
                                    libc::AT_FDCWD,
                                    CString::new(redirected.to_str().unwrap())?.as_ptr(),
                                    mode,
                                    flags,
                                )
                            };
                            let errno = if res == -1 { Errno::last_raw() } else { 0 };
                            let resp = ScmpNotifResp::new(req.id, res as i64, (-errno).into(), 0);
                            resp.respond(notif_fd)?;
                            return Ok(true);
                        }
                    }
                    BundleRoot::InMemory(_) => {
                        if self.bundle_root.get_file(&relative).is_some() {
                            debug!("Emulating accessat for in-memory {:?}", path);
                            let resp = ScmpNotifResp::new(req.id, 0, 0, 0);
                            resp.respond(notif_fd)?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn get_redirection_path(&self, path: &Path) -> Option<PathBuf> {
        if !path.is_absolute() {
            return None;
        }

        if self.prefer_host.contains(path) && path.exists() {
            debug!("Preferring host version for {:?}", path);
            return None;
        }

        path.strip_prefix("/").ok().map(|p| p.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    fn test_get_redirection_path_prefer_host() {
        let temp = tempdir().unwrap();
        let mut prefer = HashSet::new();
        let test_path = PathBuf::from("/etc/hosts");
        prefer.insert(test_path.clone());

        let monitor = RedirectionMonitor::new_with_root(1234, BundleRoot::TempDir(temp), prefer);

        assert_eq!(monitor.get_redirection_path(&test_path), None);
        assert_eq!(
            monitor.get_redirection_path(Path::new("/bin/ls")),
            Some(PathBuf::from("bin/ls"))
        );
    }
}
