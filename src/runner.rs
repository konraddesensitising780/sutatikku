use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tar::Archive;
use flate2::read::GzDecoder;
use std::os::unix::process::CommandExt;
use std::process::Command;
use nix::unistd::{fork, ForkResult};
use nix::sys::wait::waitpid;
use log::{debug, error};
use std::os::fd::{AsFd, AsRawFd};

use crate::builder::BundleConfig;
use crate::seccomp::{setup_seccomp_hook, run_seccomp_monitor};
use crate::monitor::RedirectionMonitor;

pub struct Runner {
    exe_path: PathBuf,
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
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let bundle_root = temp_dir.path().to_path_buf();

        debug!("Extracting bundle to {:?}", bundle_root);
        self.extract_payload(payload_offset, payload_size, &bundle_root)?;

        let config_path = bundle_root.join(".sutatikku/config.json");
        let config_data = fs::read(config_path)?;
        let config: BundleConfig = serde_json::from_slice(&config_data)?;

        let relative_entry = config.entry_path.strip_prefix("/").unwrap();
        let bundled_entry_path = bundle_root.join(relative_entry);

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

                let mut cmd = if let Some(ref interp) = config.interpreter_path {
                    let relative_interp = interp.strip_prefix("/").unwrap();
                    let bundled_interp_path = bundle_root.join(relative_interp);
                    let mut c = Command::new(bundled_interp_path);
                    c.arg(bundled_entry_path);
                    c
                } else {
                    Command::new(bundled_entry_path)
                };

                let args: Vec<String> = std::env::args().skip(1).collect();
                cmd.args(args);
                
                let err = cmd.exec();
                error!("Failed to exec bundled binary: {:?}", err);
                std::process::exit(1);
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                let fds = parent_sock.recv_fd()?;
                let notif_fd = fds.into_iter().next().ok_or_else(|| anyhow!("No FD received"))?;
                
                let monitor = RedirectionMonitor::new(bundle_root);
                parent_sock.ping()?;

                let _ = run_seccomp_monitor(notif_fd.as_fd(), |req| {
                    monitor.handle_notification(&req, notif_fd.as_raw_fd());
                });

                let _ = waitpid(child, None)?;
                Ok(())
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
}
