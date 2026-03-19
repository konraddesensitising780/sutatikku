use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Builder as TarBuilder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BundleConfig {
    pub entry_path: PathBuf,
    pub interpreter_path: Option<PathBuf>,
}

pub struct Builder {
    input: PathBuf,
    output: PathBuf,
}

impl Builder {
    pub fn new(input: PathBuf, output: PathBuf) -> Self {
        Self { input, output }
    }

    pub fn build(&self) -> Result<()> {
        let input_abs = fs::canonicalize(&self.input)
            .with_context(|| format!("Failed to canonicalize input path {:?}", self.input))?;
        
        let (deps, interpreter) = self.resolve_dependencies(&input_abs)?;
        
        let mut bundle_data = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut bundle_data, Compression::default());
            let mut tar = TarBuilder::new(&mut encoder);

            tar.append_path_with_name(&input_abs, input_abs.strip_prefix("/").unwrap())?;

            for dep in deps {
                if dep.exists() {
                    tar.append_path_with_name(&dep, dep.strip_prefix("/").unwrap())?;
                }
            }

            let config = BundleConfig {
                entry_path: input_abs.clone(),
                interpreter_path: interpreter,
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

        Ok(())
    }

    fn resolve_dependencies(&self, binary: &Path) -> Result<(HashSet<PathBuf>, Option<PathBuf>)> {
        let output = Command::new("ldd")
            .arg(binary)
            .output()
            .context("Failed to run ldd")?;

        if !output.status.success() {
            bail!("ldd failed for {:?}", binary);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut deps = HashSet::new();
        let mut interpreter = None;

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }

            if let Some(arrow_idx) = line.find("=>") {
                let path_part = &line[arrow_idx + 2..].trim();
                let end_idx = path_part.find('(').unwrap_or(path_part.len());
                let path_str = path_part[..end_idx].trim();
                if !path_str.is_empty() && path_str != "not found" {
                    deps.insert(PathBuf::from(path_str));
                }
            } else if line.starts_with('/') {
                let end_idx = line.find('(').unwrap_or(line.len());
                let path_str = line[..end_idx].trim();
                let path = PathBuf::from(path_str);
                if path_str.contains("/ld-linux") || path_str.contains("/ld-musl") {
                    interpreter = Some(path.clone());
                }
                deps.insert(path);
            }
        }

        Ok((deps, interpreter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dependencies() {
        let input_bin = if fs::metadata("/bin/ls").is_ok() { "/bin/ls" } else { "/usr/bin/ls" };
        let builder = Builder::new(PathBuf::from(input_bin), PathBuf::from("output"));
        let (deps, interpreter) = builder.resolve_dependencies(Path::new(input_bin)).unwrap();
        assert!(!deps.is_empty());
        assert!(interpreter.is_some());
        let interp_str = interpreter.unwrap().to_str().unwrap().to_string();
        assert!(interp_str.contains("ld-linux") || interp_str.contains("ld-musl"));
    }
}
