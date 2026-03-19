mod builder;
mod cli;
mod runner;
mod monitor;
mod seccomp;
mod sys_util;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use builder::Builder;
use runner::Runner;

fn main() -> Result<()> {
    env_logger::init();

    let runner = Runner::new()?;
    if runner.is_runner()? {
        return runner.run_with_monitor();
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Build { input, output, .. } => {
            let builder = Builder::new(input, output);
            builder.build()?;
            println!("Successfully built standalone binary.");
        }
    }

    Ok(())
}
