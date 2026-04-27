use std::path::PathBuf;
use std::process::ExitCode;

use mhrv_rs::config::{Config, Mode};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        "mhrv-drive-node {} — Google Drive queue tunnel server

USAGE:
    mhrv-drive-node [OPTIONS]

OPTIONS:
    -c, --config PATH    Path to config.json (default: ./config.json)
    -h, --help           Show this message
    -V, --version        Show version

ENV:
    RUST_LOG             Override log level (e.g. info, debug)
",
        VERSION
    );
}

fn parse_args() -> Result<Option<PathBuf>, String> {
    let mut config_path = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("mhrv-drive-node {}", VERSION);
                std::process::exit(0);
            }
            "-c" | "--config" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--config needs a path".to_string())?;
                config_path = Some(PathBuf::from(v));
            }
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    Ok(config_path)
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config_path = match parse_args() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{}", e);
            print_help();
            return ExitCode::from(2);
        }
    };
    let config_path = mhrv_rs::data_dir::resolve_config_path(config_path.as_deref());
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    init_logging(&config.log_level);

    if config.mode_kind().ok() != Some(Mode::GoogleDrive) {
        eprintln!("mhrv-drive-node requires config mode \"google_drive\"");
        return ExitCode::from(2);
    }

    tracing::warn!("mhrv-drive-node {} starting", VERSION);
    let run = mhrv_rs::drive_tunnel::run_server(&config);
    tokio::select! {
        r = run => {
            if let Err(e) = r {
                eprintln!("drive node error: {}", e);
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("Ctrl+C — shutting down drive node.");
        }
    }
    ExitCode::SUCCESS
}
