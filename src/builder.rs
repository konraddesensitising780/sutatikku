use anyhow::{Context, Result, anyhow};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Builder as TarBuilder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Serialize, Deserialize};
use log::debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BundleConfig {
    pub entry_path: PathBuf,
    #[serde(default)]
    pub entry_args: Vec<String>,
    pub interpreter_path: Option<PathBuf>,
    pub use_tempdir: bool,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub prefer_host: HashSet<PathBuf>,
}

pub struct Builder {
    entry: PathBuf,
    entry_args: Vec<String>,
    output: PathBuf,
    use_tempdir: bool,
    extra_files: Vec<ExtraFile>,
    env: Vec<String>,
    prefer_host: HashSet<PathBuf>,
    ignore_paths: HashSet<PathBuf>,
}

pub struct ExtraFile {
    pub source: PathBuf,
    pub dest: PathBuf,
    pub prefer_host: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigYaml {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<EntryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_tempdir: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntryConfig {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum FileEntry {
    Simple(PathBuf),
    Full(FileSpec),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileSpec {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map_to: Option<PathBuf>,
    #[serde(default)]
    pub prefer_host: bool,
}

pub const DEFAULT_PREFER_HOST_PATHS: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/hostname",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/ssl/certs",
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",
    "/etc/pki/tls/certs",
];

pub const DEFAULT_IGNORE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
];

use crate::monitor::RecordingMonitor;
use crate::seccomp::{setup_seccomp_hook, run_seccomp_monitor};
use nix::unistd::{fork, ForkResult};
use nix::sys::wait::waitpid;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;

fn to_absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

impl Builder {
    pub fn record_open_paths(input: &Path, args: &[String]) -> Result<HashSet<PathBuf>> {
        let (parent_sock, child_sock) = crate::sys_util::create_unix_socketpair()?;
        let _monitor = std::sync::Arc::new(RecordingMonitor::new(0));

        match unsafe { fork()? } {
            ForkResult::Child => {
                drop(parent_sock);
                let syscalls = vec![libc::SYS_open as i32, libc::SYS_openat as i32];
                let notif_fd = setup_seccomp_hook(&syscalls)?;
                child_sock.send_fd(notif_fd)?;
                child_sock.pong()?;

                let mut cmd = Command::new(input);
                cmd.args(args);
                let _ = cmd.exec();
                std::process::exit(1);
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                let fds = parent_sock.recv_fd()?;
                let notif_fd = fds.into_iter().next().ok_or_else(|| anyhow!("No FD received"))?;
                parent_sock.ping()?;

                let monitor = std::sync::Arc::new(RecordingMonitor::new(child.as_raw() as u32));
                let m = monitor.clone();
                let notif_fd_raw = notif_fd.as_raw_fd();
                let _ = run_seccomp_monitor(notif_fd.as_fd(), move |req| {
                    m.handle_notification(&req, notif_fd_raw);
                });

                let _ = waitpid(child, None)?;
                
                let paths = std::sync::Arc::try_unwrap(monitor)
                    .map_err(|_| anyhow!("Arc unwrap failed"))?
                    .opened_paths.into_inner().unwrap();
                Ok(paths)
            }
        }
    }

    fn should_ignore(&self, path: &Path) -> bool {
        let p_str = path.to_string_lossy();
        if p_str.starts_with("/proc") || p_str.starts_with("/sys") || p_str.starts_with("/dev") {
            return true;
        }
        self.ignore_paths.contains(path)
    }

    pub fn generate_config(input: PathBuf, analyze_libs: bool, record: bool, record_args: &[String], prefer_host_override: Option<HashSet<PathBuf>>, ignore_override: Option<HashSet<PathBuf>>) -> Result<ConfigYaml> {
        let input_abs = to_absolute(&input)
            .with_context(|| format!("Failed to resolve input path {:?}", input))?;
        
        let mut dummy = Self::new(input_abs.clone(), PathBuf::new(), false);
        if let Some(p) = prefer_host_override { dummy.set_prefer_host(p); }
        if let Some(i) = ignore_override { dummy.set_ignore_paths(i); }

        let mut yaml = ConfigYaml {
            entry: Some(EntryConfig { path: input_abs.clone(), args: None }),
            files: None,
            use_tempdir: None,
            env: None,
        };

        let mut file_set = HashSet::new();

        if record {
            let recorded = Self::record_open_paths(&input_abs, record_args)?;
            for p in recorded {
                if !dummy.should_ignore(&p) {
                    file_set.insert(p);
                }
            }
        }

        if analyze_libs {
            let (deps, _) = dummy.resolve_dependencies_recursive(&input_abs)?;
            for d in deps {
                if !dummy.should_ignore(&d) {
                    file_set.insert(d);
                }
            }
        }

        if !file_set.is_empty() {
            let mut paths: Vec<_> = file_set.into_iter().collect();
            paths.sort();
            
            let entries = paths.into_iter().map(|p| {
                let is_prefer = dummy.prefer_host.contains(&p);
                if is_prefer {
                    FileEntry::Full(FileSpec {
                        path: p,
                        map_to: None,
                        prefer_host: true,
                    })
                } else {
                    FileEntry::Simple(p)
                }
            }).collect();
            
            yaml.files = Some(entries);
        }

        Ok(yaml)
    }

    pub fn new(entry: PathBuf, output: PathBuf, use_tempdir: bool) -> Self {
        let mut prefer_host = HashSet::new();
        for p in DEFAULT_PREFER_HOST_PATHS {
            prefer_host.insert(PathBuf::from(p));
        }

        let mut ignore_paths = HashSet::new();
        for p in DEFAULT_IGNORE_PATHS {
            ignore_paths.insert(PathBuf::from(p));
        }

        Self {
            entry,
            entry_args: Vec::new(),
            output,
            use_tempdir,
            extra_files: Vec::new(),
            env: Vec::new(),
            prefer_host,
            ignore_paths,
        }
    }

    pub fn set_entry_args(&mut self, args: Vec<String>) {
        self.entry_args = args;
    }

    pub fn set_prefer_host(&mut self, paths: HashSet<PathBuf>) {
        self.prefer_host = paths;
    }

    pub fn set_ignore_paths(&mut self, paths: HashSet<PathBuf>) {
        self.ignore_paths = paths;
    }

    pub fn add_file(&mut self, source: PathBuf, dest: PathBuf, prefer_host: bool) {
        self.extra_files.push(ExtraFile { source, dest, prefer_host });
    }

    pub fn add_env(&mut self, env: String) {
        self.env.push(env);
    }

    pub fn from_yaml(config_path: &Path, output: PathBuf) -> Result<Self> {
        let content = fs::read_to_string(config_path)?;
        let yaml: ConfigYaml = serde_yaml::from_str(&content)?;
        
        let entry_config = yaml.entry.ok_or_else(|| anyhow!("Entry path is missing in config"))?;
        let mut builder = Self::new(entry_config.path, output, yaml.use_tempdir.unwrap_or(false));
        if let Some(args) = entry_config.args {
            builder.set_entry_args(args);
        }
        
        if let Some(files) = yaml.files {
            for f in files {
                match f {
                    FileEntry::Simple(p) => {
                        if !builder.should_ignore(&p) {
                            builder.add_file(p.clone(), p, false);
                        }
                    }
                    FileEntry::Full(spec) => {
                        let dest = spec.map_to.unwrap_or_else(|| spec.path.clone());
                        if !builder.should_ignore(&spec.path) {
                            builder.add_file(spec.path, dest, spec.prefer_host);
                        }
                    }
                }
            }
        }

        if let Some(envs) = yaml.env {
            for e in envs {
                builder.add_env(e);
            }
        }
        
        Ok(builder)
    }

    pub fn build(&self) -> Result<()> {
        let entry_abs = to_absolute(&self.entry)
            .with_context(|| format!("Failed to resolve entry path {:?}", self.entry))?;
        
        let mut all_deps = HashSet::new();
        let mut interpreter = None;
        let mut prefer_host_paths = self.prefer_host.clone();

        let (deps, interp) = self.resolve_dependencies_recursive(&entry_abs)?;
        for d in deps {
            if !self.should_ignore(&d) {
                all_deps.insert(d);
            }
        }
        if let Some(i) = interp {
            interpreter = Some(i);
        }

        for extra in &self.extra_files {
            if extra.source == extra.dest {
                let (deps, _) = self.resolve_dependencies_recursive(&extra.source)?;
                for d in deps {
                    if !self.should_ignore(&d) {
                        all_deps.insert(d);
                    }
                }
            }
            if extra.prefer_host {
                prefer_host_paths.insert(extra.dest.clone());
            }
        }
        
        let mut bundle_data = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut bundle_data, Compression::default());
            let mut tar = TarBuilder::new(&mut encoder);

            tar.append_path_with_name(&entry_abs, entry_abs.strip_prefix("/").unwrap())?;

            for dep in &all_deps {
                if dep.exists() {
                    tar.append_path_with_name(dep, dep.strip_prefix("/").unwrap())?;
                }
            }

            for extra in &self.extra_files {
                let dest_rel = extra.dest.strip_prefix("/").unwrap_or(&extra.dest);
                if extra.source.is_dir() {
                    tar.append_dir_all(dest_rel, &extra.source)?;
                } else {
                    if extra.source == extra.dest && all_deps.contains(&extra.source) {
                        continue;
                    }
                    tar.append_path_with_name(&extra.source, dest_rel)?;
                }
            }

            let config = BundleConfig {
                entry_path: entry_abs.clone(),
                entry_args: self.entry_args.clone(),
                interpreter_path: interpreter,
                use_tempdir: self.use_tempdir,
                env: self.env.clone(),
                prefer_host: prefer_host_paths,
            };
            let config_json = serde_json::to_vec(&config)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(config_json.len() as u64);
            header.set_path(".sutatikku/config.json")?;
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, &config_json[..])?;

            tar.finish()?;
        }

        let mut out_file = fs::File::create(&self.output)?;
        let self_exe = std::env::current_exe()?;
        let mut self_exe_file = fs::File::open(self_exe)?;
        std::io::copy(&mut self_exe_file, &mut out_file)?;

        use std::io::Write;
        out_file.write_all(&bundle_data)?;
        
        let footer = (bundle_data.len() as u64).to_le_bytes();
        out_file.write_all(&footer)?;
        out_file.write_all(b"SUTATIKU")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.output)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&self.output, perms)?;
        }

        debug!("Successfully built standalone binary at {:?}", self.output);
        Ok(())
    }

    pub fn resolve_dependencies_recursive(&self, binary: &Path) -> Result<(HashSet<PathBuf>, Option<PathBuf>)> {
        let mut all_deps = HashSet::new();
        let mut queue = vec![to_absolute(binary)?];
        let mut interpreter = None;

        while let Some(current) = queue.pop() {
            let output = Command::new("ldd")
                .arg(&current)
                .output()
                .context("Failed to run ldd")?;

            if !output.status.success() {
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }

                let mut path = None;
                if let Some(arrow_idx) = line.find("=>") {
                    let path_part = &line[arrow_idx + 2..].trim();
                    let end_idx = path_part.find('(').unwrap_or(path_part.len());
                    let path_str = path_part[..end_idx].trim();
                    if !path_str.is_empty() && path_str != "not found" {
                        path = Some(PathBuf::from(path_str));
                    }
                } else if line.starts_with('/') {
                    let end_idx = line.find('(').unwrap_or(line.len());
                    let path_str = line[..end_idx].trim();
                    path = Some(PathBuf::from(path_str));
                }

                if let Some(p) = path {
                    let p_abs = to_absolute(&p)?;
                    if !all_deps.contains(&p_abs) && !self.should_ignore(&p_abs) {
                        let p_str = p_abs.to_string_lossy();
                        if p_str.contains("/ld-linux") || p_str.contains("/ld-musl") {
                            if interpreter.is_none() {
                                interpreter = Some(p_abs.clone());
                            }
                        }
                        all_deps.insert(p_abs.clone());
                        queue.push(p_abs);
                    }
                }
            }
        }

        Ok((all_deps, interpreter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dependencies_recursive() {
        let input_bin = if fs::metadata("/bin/ls").is_ok() { "/bin/ls" } else { "/usr/bin/ls" };
        let builder = Builder::new(PathBuf::from(input_bin), PathBuf::from("output"), false);
        let (deps, interpreter) = builder.resolve_dependencies_recursive(Path::new(input_bin)).unwrap();
        assert!(!deps.is_empty());
        assert!(interpreter.is_some());
        
        let has_libc = deps.iter().any(|p| p.to_string_lossy().contains("libc.so"));
        assert!(has_libc, "Should have found libc in dependencies");

        let libselinux = Path::new("/lib/x86_64-linux-gnu/libselinux.so.1");
        if libselinux.exists() {
            let (selinux_deps, _) = builder.resolve_dependencies_recursive(libselinux).unwrap();
            let has_pcre = selinux_deps.iter().any(|p| p.to_string_lossy().contains("libpcre2"));
            assert!(has_pcre, "Should have found libpcre2 as a dependency of libselinux");
        }
    }
}
