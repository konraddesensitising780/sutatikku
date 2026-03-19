use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "sutatikku", about = "Turn dynamically linked ELF binaries into standalone executables")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build a standalone binary from a dynamically linked executable
    Build {
        #[arg(help = "Path to the dynamically linked ELF binary")]
        input: Option<PathBuf>,

        #[arg(short, long, help = "Output path for the self-contained binary")]
        output: PathBuf,

        #[arg(long, help = "Entry point within the bundle (defaults to the input binary)")]
        entry: Option<PathBuf>,

        #[arg(long, help = "Extract files to a temporary directory instead of serving from memory")]
        use_tempdir: bool,

        #[arg(long, help = "Additional files to include in the bundle (format: source[:dest])")]
        files: Vec<FileMapping>,

        #[arg(short, long, help = "Path to a YAML configuration file")]
        config: Option<PathBuf>,

        #[arg(long, help = "Environment variables to set (format: KEY=VALUE)")]
        env: Vec<String>,

        #[arg(long, help = "Paths that should prefer the host version if it exists")]
        prefer_host: Option<Vec<PathBuf>>,

        #[arg(long, help = "Paths to ignore and never bundle")]
        ignore: Option<Vec<PathBuf>>,
    },
    /// Generate a configuration YAML file from a dynamically linked ELF binary
    GenConfig {
        #[arg(help = "Path to the dynamically linked ELF binary")]
        input: PathBuf,

        #[arg(short, long, help = "Output path for the generated YAML config")]
        output: PathBuf,

        #[arg(long, help = "Analyze and include all resolved libraries in the config", default_value_t = true)]
        analyze_libs: bool,

        #[arg(long, help = "Execute the command and record all file open operations")]
        record: bool,

        #[arg(long, help = "Paths that should prefer the host version if it exists")]
        prefer_host: Option<Vec<PathBuf>>,

        #[arg(long, help = "Paths to ignore and never bundle")]
        ignore: Option<Vec<PathBuf>>,

        #[arg(last = true, help = "Arguments for the command to trace file accesses")]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct FileMapping {
    pub source: PathBuf,
    pub dest: PathBuf,
}

impl FromStr for FileMapping {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((source, dest)) = s.split_once(':') {
            Ok(FileMapping {
                source: PathBuf::from(source),
                dest: PathBuf::from(dest),
            })
        } else {
            let path = PathBuf::from(s);
            Ok(FileMapping {
                source: path.clone(),
                dest: path,
            })
        }
    }
}
