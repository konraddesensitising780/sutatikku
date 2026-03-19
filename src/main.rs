mod builder;
mod cli;
mod runner;
mod monitor;
mod seccomp;
mod sys_util;

use anyhow::{Result, anyhow};
use clap::Parser;
use cli::{Cli, Commands};
use builder::Builder;
use log::info;
use runner::Runner;
use std::collections::HashSet;

fn main() -> Result<()> {
    env_logger::init();

    let runner = Runner::new()?;
    if runner.is_runner()? {
        return runner.run_with_monitor();
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Build { 
            input, 
            output, 
            entry, 
            use_tempdir, 
            files, 
            config,
            env,
            prefer_host,
            ignore,
        } => {
            let mut builder = if let Some(config_path) = config {
                Builder::from_yaml(&config_path, output)?
            } else {
                let entry_path = entry.or(input).ok_or_else(|| anyhow!("No input or entry specified"))?;
                Builder::new(entry_path, output, use_tempdir)
            };

            if let Some(p) = prefer_host {
                builder.set_prefer_host(p.into_iter().collect());
            }
            if let Some(i) = ignore {
                builder.set_ignore_paths(i.into_iter().collect());
            }

            for mapping in files {
                builder.add_file(mapping.source, mapping.dest, false);
            }

            for e in env {
                builder.add_env(e);
            }

            builder.build()?;
            info!("Successfully built standalone binary.");
        }
        Commands::GenConfig { input, output, analyze_libs, record, prefer_host, ignore, args } => {
            let p_host = prefer_host.map(|v| v.into_iter().collect::<HashSet<_>>());
            let i_paths = ignore.map(|v| v.into_iter().collect::<HashSet<_>>());
            let config = Builder::generate_config(input, analyze_libs, record, &args, p_host, i_paths)?;
            let content = serde_yaml::to_string(&config)?;
            std::fs::write(&output, content)?;
            info!("Successfully generated config file at {:?}", output);
        }
    }

    Ok(())
}
