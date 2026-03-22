use anyhow::{anyhow, bail, Context, Result};
use flate2::read::GzDecoder;
use log::debug;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{self, fork, ForkResult};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;
use tempfile::tempdir;

use crate::builder::BundleConfig;
use crate::monitor::RedirectionMonitor;
use crate::seccomp::{run_seccomp_monitor, setup_seccomp_hook};

pub struct Runner {
    exe_path: PathBuf,
}

pub enum BundleRoot {
    TempDir(tempfile::TempDir),
    InMemory(HashMap<PathBuf, Vec<u8>>),
}

impl BundleRoot {
    pub fn path(&self) -> PathBuf {
        match self {
            BundleRoot::TempDir(td) => td.path().to_path_buf(),
            BundleRoot::InMemory(_) => PathBuf::from("/bundle"), // Virtual path
        }
    }

    pub fn get_file(&self, relative_path: &Path) -> Option<&[u8]> {
        match self {
            BundleRoot::TempDir(_) => None,
            BundleRoot::InMemory(map) => map.get(relative_path).map(|v| v.as_slice()),
        }
    }
}

impl Runner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            exe_path: std::env::current_exe()?,
        })
    }

    pub fn is_runner(&self) -> Result<bool> {
        let mut file = fs::File::open(&self.exe_path)?;
        if file.metadata()?.len() < 16 {
            return Ok(false);
        }
        file.seek(SeekFrom::End(-8))?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        Ok(&magic == b"SUTATIKU")
    }

    pub fn run_with_monitor(&self) -> Result<()> {
        let (payload_offset, payload_size) = self.find_payload()?;

        let config = {
            let mut file = fs::File::open(&self.exe_path)?;
            file.seek(SeekFrom::Start(payload_offset))?;
            let mut take = file.take(payload_size);
            let gz = GzDecoder::new(&mut take);
            let mut tar = Archive::new(gz);
            let mut config = None;
            for entry in tar.entries()? {
                let mut entry = entry?;
                if entry.path()? == Path::new(".sutatikku/config.json") {
                    let mut data = Vec::new();
                    entry.read_to_end(&mut data)?;
                    config = Some(serde_json::from_slice::<BundleConfig>(&data)?);
                    break;
                }
            }
            config.ok_or_else(|| anyhow!("Config not found in bundle"))?
        };

        let bundle_root = if config.use_tempdir {
            let temp_dir = tempdir().context("Failed to create temp dir")?;
            self.extract_payload(payload_offset, payload_size, temp_dir.path())?;
            BundleRoot::TempDir(temp_dir)
        } else {
            BundleRoot::InMemory(self.extract_to_memory(payload_offset, payload_size)?)
        };

        let bundle_root_path = bundle_root.path();
        let relative_entry = config.entry_path.strip_prefix("/").unwrap();

        let (parent_sock, child_sock) = crate::sys_util::create_unix_socketpair()?;

        match unsafe { fork()? } {
            ForkResult::Child => {
                drop(parent_sock);

                let syscalls_to_hook = vec![
                    libc::SYS_open as i32,
                    libc::SYS_openat as i32,
                    libc::SYS_newfstatat as i32,
                    libc::SYS_access as i32,
                    libc::SYS_faccessat as i32,
                    libc::SYS_faccessat2 as i32,
                ];

                let notif_fd = setup_seccomp_hook(&syscalls_to_hook)?;
                child_sock.send_fd(notif_fd)?;
                child_sock.pong()?;

                for env_str in &config.env {
                    if let Some((k, v)) = env_str.split_once('=') {
                        std::env::set_var(k, v);
                    }
                }

                if !config.use_tempdir {
                    debug!("Runner: Preparing in-memory exec...");
                    let interp_data = if let Some(ref interp) = config.interpreter_path {
                        let relative_interp = interp.strip_prefix("/").unwrap();
                        Some(
                            bundle_root
                                .get_file(relative_interp)
                                .ok_or_else(|| anyhow!("Interpreter not found in memory"))?,
                        )
                    } else {
                        None
                    };

                    let entry_data = bundle_root
                        .get_file(relative_entry)
                        .ok_or_else(|| anyhow!("Entry binary not found in memory"))?;
                    let entry_fd = nix::sys::memfd::memfd_create(
                        &CString::new("entry")?,
                        nix::sys::memfd::MemFdCreateFlag::empty(),
                    )?;
                    unistd::write(&entry_fd, entry_data)?;

                    if let Some(data) = interp_data {
                        let interp_fd = nix::sys::memfd::memfd_create(
                            &CString::new("interpreter")?,
                            nix::sys::memfd::MemFdCreateFlag::empty(),
                        )?;
                        unistd::write(&interp_fd, data)?;

                        let interp_path = format!("/proc/self/fd/{}", interp_fd.as_raw_fd());
                        let entry_path = format!("/proc/self/fd/{}", entry_fd.as_raw_fd());
                        debug!("Runner: Execing {} {}", interp_path, entry_path);

                        let mut c = Command::new(&interp_path);
                        c.arg(&entry_path);
                        c.args(&config.entry_args);
                        let args: Vec<String> = std::env::args().skip(1).collect();
                        c.args(args);

                        let err = c.exec();
                        debug!("Runner: exec failed: {:?}", err);
                        std::process::exit(1);
                    } else {
                        let mut c = Command::new(format!("/proc/self/fd/{}", entry_fd.as_raw_fd()));
                        c.args(&config.entry_args);
                        let args: Vec<String> = std::env::args().skip(1).collect();
                        c.args(args);
                        let _ = c.exec();
                        std::process::exit(1);
                    }
                } else {
                    let bundled_entry_path = bundle_root_path.join(relative_entry);
                    let mut cmd = if let Some(ref interp) = config.interpreter_path {
                        let relative_interp = interp.strip_prefix("/").unwrap();
                        let bundled_interp_path = bundle_root_path.join(relative_interp);
                        let mut c = Command::new(bundled_interp_path);
                        c.arg(&bundled_entry_path);
                        c
                    } else {
                        Command::new(bundled_entry_path)
                    };

                    cmd.args(&config.entry_args);
                    let args: Vec<String> = std::env::args().skip(1).collect();
                    cmd.args(args);
                    let _ = cmd.exec();
                    std::process::exit(1);
                }
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                let fds = parent_sock.recv_fd()?;
                let notif_fd = fds
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("No FD received"))?;

                let monitor = RedirectionMonitor::new_with_root(
                    child.as_raw() as u32,
                    bundle_root,
                    config.prefer_host,
                );
                parent_sock.ping()?;

                let _ = run_seccomp_monitor(notif_fd.as_fd(), |req| {
                    monitor.handle_notification(&req, notif_fd.as_raw_fd());
                });

                let status = waitpid(child, None)?;
                match status {
                    WaitStatus::Exited(_, code) => {
                        if code != 0 {
                            bail!("Child exited with non-zero code: {}", code);
                        }
                        Ok(())
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        bail!("Child killed by signal: {:?}", sig);
                    }
                    _ => bail!("Unexpected child status: {:?}", status),
                }
            }
        }
    }

    fn find_payload(&self) -> Result<(u64, u64)> {
        let mut file = fs::File::open(&self.exe_path)?;
        let total_size = file.metadata()?.len();
        file.seek(SeekFrom::End(-16))?;

        let mut size_bytes = [0u8; 8];
        file.read_exact(&mut size_bytes)?;
        let payload_size = u64::from_le_bytes(size_bytes);

        let payload_offset = total_size - 16 - payload_size;
        Ok((payload_offset, payload_size))
    }

    fn extract_payload(&self, offset: u64, size: u64, dest: &Path) -> Result<()> {
        let mut file = fs::File::open(&self.exe_path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut take = file.take(size);
        let gz = GzDecoder::new(&mut take);
        let mut tar = Archive::new(gz);
        tar.unpack(dest).context("Failed to unpack bundle")?;
        Ok(())
    }

    fn extract_to_memory(&self, offset: u64, size: u64) -> Result<HashMap<PathBuf, Vec<u8>>> {
        let mut file = fs::File::open(&self.exe_path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut take = file.take(size);
        let gz = GzDecoder::new(&mut take);
        let mut tar = Archive::new(gz);
        let mut map = HashMap::new();
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            map.insert(path, data);
        }
        Ok(map)
    }
}
