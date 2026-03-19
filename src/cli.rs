use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
        input: PathBuf,

        #[arg(short, long, help = "Output path for the self-contained binary")]
        output: PathBuf,

        #[arg(long, help = "Entry point within the bundle (defaults to the input binary)")]
        entry: Option<String>,
    },
}
