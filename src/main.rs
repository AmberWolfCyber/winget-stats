mod app;
mod cve;
mod db;
mod index;
mod inspect;
mod manifest;
mod pe;
mod probe;
mod serve;
mod unpack;
mod version;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use crate::app::App;
use crate::probe::ProbeOptions;
use crate::unpack::UnpackOptions;

#[derive(Parser)]
#[command(version, about = "Download and analyse NSIS installers from the winget community repository")]
struct Cli {
    /// Show debug output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Folder for the database, the manifest archive and the saved installer heads
    #[arg(short, long, global = true, default_value = "data")]
    data_dir: PathBuf,

    /// HTTP proxy as ip:port. TLS certificate checks are off when you set a proxy
    #[arg(short, long, global = true)]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read the winget-pkgs manifests into the database
    Index {
        /// Use this winget-pkgs .tar.gz instead of the copy in the data folder
        #[arg(short, long)]
        tarball: Option<PathBuf>,

        /// Download a new copy of the winget-pkgs archive
        #[arg(short, long)]
        refresh: bool,
    },
    /// Fetch the start of each installer with range requests and read its NSIS version
    Probe {
        /// Number of requests open at the same time
        #[arg(short, long, default_value_t = 32)]
        concurrency: usize,

        /// Number of requests open at the same time to one host
        #[arg(long, default_value_t = 8)]
        per_host: usize,

        /// Try failed files again until they reach this number of runs
        #[arg(short, long, default_value_t = 3)]
        max_attempts: u32,

        /// Probe at most this number of files
        #[arg(short, long)]
        limit: Option<usize>,
    },
    /// Read the NSIS version of installers inside 7-Zip self-extracting archives and zip files with range requests
    Unpack {
        /// Number of files to unpack at the same time
        #[arg(short, long, default_value_t = 4)]
        concurrency: usize,

        /// Stop a file after fetching this many megabytes
        #[arg(long, default_value_t = 200)]
        max_mb: u64,

        /// Try failed files again until they reach this number of runs
        #[arg(short, long, default_value_t = 3)]
        max_attempts: u32,

        /// Unpack at most this number of files
        #[arg(short, long)]
        limit: Option<usize>,
    },
    /// Run the detection again on the saved head files, with no network requests
    Inspect,
    /// Show counts from the database
    Status,
    /// Write the dashboard and its data as static files for a web host
    Export {
        /// Folder to write index.html and api/*.json to
        #[arg(short, long, default_value = "public")]
        output: PathBuf,
    },
    /// Serve a dashboard with the results
    Serve {
        /// Address and port to listen on
        #[arg(short, long, default_value = "127.0.0.1:8642")]
        listen: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = if cli.verbose { LevelFilter::DEBUG } else { LevelFilter::INFO };
    let filter = EnvFilter::default()
        .add_directive(LevelFilter::INFO.into())
        .add_directive(format!("{}={level}", env!("CARGO_CRATE_NAME")).parse().expect("valid log directive"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let result = App::new(cli.data_dir, cli.proxy.as_deref()).and_then(|mut app| match cli.command {
        Command::Index { tarball, refresh } => app.index(tarball, refresh),
        Command::Probe { concurrency, per_host, max_attempts, limit } => {
            app.probe(ProbeOptions { concurrency, per_host, max_attempts, limit })
        }
        Command::Unpack { concurrency, max_mb, max_attempts, limit } => {
            app.unpack(UnpackOptions { concurrency, max_mb, max_attempts, limit })
        }
        Command::Inspect => app.inspect(),
        Command::Status => app.status(),
        Command::Serve { listen } => app.serve(&listen),
        Command::Export { output } => app.export(&output),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
