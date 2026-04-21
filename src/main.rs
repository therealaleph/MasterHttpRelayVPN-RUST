#![allow(dead_code)]

mod cache;
mod cert_installer;
mod config;
mod domain_fronter;
mod mitm;
mod proxy_server;
mod scan_ips;
mod test_cmd;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use crate::cert_installer::{install_ca, is_ca_trusted};
use crate::config::Config;
use crate::mitm::{MitmCertManager, CA_CERT_FILE};
use crate::proxy_server::ProxyServer;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    config_path: PathBuf,
    install_cert: bool,
    no_cert_check: bool,
    command: Command,
}

enum Command {
    Serve,
    Test,
    ScanIps,
}

fn print_help() {
    println!(
        "mhrv-rs {} — Rust port of MasterHttpRelayVPN (apps_script mode only)

USAGE:
    mhrv-rs [OPTIONS]                  Start the proxy server (default)
    mhrv-rs test [OPTIONS]             Probe the Apps Script relay end-to-end
    mhrv-rs scan-ips [OPTIONS]         Scan Google frontend IPs for reachability + latency

OPTIONS:
    -c, --config PATH    Path to config.json (default: ./config.json)
    --install-cert       Install the MITM CA certificate and exit
    --no-cert-check      Skip the auto-install-if-untrusted check on startup
    -h, --help           Show this message
    -V, --version        Show version

ENV:
    RUST_LOG             Override log level (e.g. info, debug)
",
        VERSION
    );
}

fn parse_args() -> Result<Args, String> {
    let mut config_path = PathBuf::from("config.json");
    let mut install_cert = false;
    let mut no_cert_check = false;
    let mut command = Command::Serve;

    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    if let Some(first) = raw.first() {
        match first.as_str() {
            "test" => {
                command = Command::Test;
                raw.remove(0);
            }
            "scan-ips" => {
                command = Command::ScanIps;
                raw.remove(0);
            }
            _ => {}
        }
    }

    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("mhrv-rs {}", VERSION);
                std::process::exit(0);
            }
            "-c" | "--config" => {
                let v = it.next().ok_or_else(|| "--config needs a path".to_string())?;
                config_path = PathBuf::from(v);
            }
            "--install-cert" => install_cert = true,
            "--no-cert-check" => no_cert_check = true,
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    Ok(Args {
        config_path,
        install_cert,
        no_cert_check,
        command,
    })
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    // Install default rustls crypto provider (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            print_help();
            return ExitCode::from(2);
        }
    };

    // --install-cert can run without a valid config — only needs the CA file.
    if args.install_cert {
        init_logging("info");
        // Ensure the CA exists.
        let base = Path::new(".");
        if let Err(e) = MitmCertManager::new_in(base) {
            eprintln!("failed to initialize CA: {}", e);
            return ExitCode::FAILURE;
        }
        let ca_path = base.join(CA_CERT_FILE);
        match install_ca(&ca_path) {
            Ok(()) => {
                tracing::info!("CA installed. You may need to restart your browser.");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("install failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    let config = match Config::load(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("Copy config.example.json to config.json and fill in your values.");
            return ExitCode::FAILURE;
        }
    };

    init_logging(&config.log_level);

    match args.command {
        Command::Test => {
            let ok = test_cmd::run(&config).await;
            return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
        }
        Command::ScanIps => {
            let ok = scan_ips::run(&config).await;
            return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
        }
        Command::Serve => {}
    }

    tracing::warn!("mhrv-rs {} starting (mode: apps_script)", VERSION);
    tracing::info!(
        "Apps Script relay: SNI={} -> script.google.com (via {})",
        config.front_domain,
        config.google_ip
    );
    let sids = config.script_ids_resolved();
    if sids.len() > 1 {
        tracing::info!("Script IDs: {} (round-robin)", sids.len());
    } else {
        tracing::info!("Script ID: {}", sids[0]);
    }

    // Initialize MITM manager (generates CA on first run).
    let base = Path::new(".");
    let mitm = match MitmCertManager::new_in(base) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to init MITM CA: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let ca_path = base.join(CA_CERT_FILE);

    if !args.no_cert_check {
        if !is_ca_trusted(&ca_path) {
            tracing::warn!("MITM CA is not (obviously) trusted — attempting install...");
            match install_ca(&ca_path) {
                Ok(()) => tracing::info!("CA installed."),
                Err(e) => tracing::error!(
                    "Auto-install failed ({}). Run with --install-cert (may need sudo) \
                     or install ca/ca.crt manually as a trusted root.",
                    e
                ),
            }
        } else {
            tracing::info!("MITM CA appears to be trusted.");
        }
    }

    let mitm = Arc::new(Mutex::new(mitm));
    let server = match ProxyServer::new(&config, mitm) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to build proxy server: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let run = server.run();
    tokio::select! {
        r = run => {
            if let Err(e) = r {
                eprintln!("server error: {}", e);
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("Ctrl+C — shutting down.");
        }
    }
    ExitCode::SUCCESS
}
