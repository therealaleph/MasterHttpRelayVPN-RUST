#![allow(dead_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use mhrv_rs::cert_installer::{install_ca, is_ca_trusted, reconcile_sudo_environment, remove_ca};
use mhrv_rs::config::Config;
use mhrv_rs::mitm::{MitmCertManager, CA_CERT_FILE};
use mhrv_rs::proxy_server::ProxyServer;
use mhrv_rs::{scan_ips, scan_sni, test_cmd};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    config_path: Option<PathBuf>,
    install_cert: bool,
    remove_cert: bool,
    no_cert_check: bool,
    command: Command,
}

enum Command {
    Serve,
    Test,
    ScanIps,
    TestSni,
    ScanSni,
}

fn print_help() {
    println!(
        "mhrv-rs {} — Rust port of MasterHttpRelayVPN (apps_script mode only)

USAGE:
    mhrv-rs [OPTIONS]                  Start the proxy server (default)
    mhrv-rs test [OPTIONS]             Probe the Apps Script relay end-to-end
    mhrv-rs scan-ips [OPTIONS]         Scan Google frontend IPs for reachability + latency
    mhrv-rs scan-sni         Scan Google SNI name using Google frontend IPs found in 'scan-ips' command
    mhrv-rs test-sni [OPTIONS]         Probe each SNI name in the rotation pool against google_ip

OPTIONS:
    -c, --config PATH    Path to config.json (default: ./config.json)
    --install-cert       Install the MITM CA certificate and exit
    --remove-cert        Remove the MITM CA from the OS trust store (verified by
                         name), then delete the on-disk ca/ directory and exit.
                         NSS cleanup (Firefox/Chrome) is best-effort. A fresh CA
                         is generated on next run. config.json and your Apps
                         Script deployment are untouched.
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
    let mut config_path: Option<PathBuf> = None;
    let mut install_cert = false;
    let mut remove_cert = false;
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
            "scan-sni" => {
                command = Command::ScanSni;
                raw.remove(0);
            }
            "test-sni" => {
                command = Command::TestSni;
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
                let v = it
                    .next()
                    .ok_or_else(|| "--config needs a path".to_string())?;
                config_path = Some(PathBuf::from(v));
            }
            "--install-cert" => install_cert = true,
            "--remove-cert" => remove_cert = true,
            "--no-cert-check" => no_cert_check = true,
            other => return Err(format!("unknown argument: {}", other)),
        }
    }
    if install_cert && remove_cert {
        return Err("--install-cert and --remove-cert cannot be combined".into());
    }
    Ok(Args {
        config_path,
        install_cert,
        remove_cert,
        no_cert_check,
        command,
    })
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
    // Install default rustls crypto provider (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Must run before anything else reads HOME / USER / data_dir — if
    // the user ran `sudo ./mhrv-rs ...`, this re-points HOME at the
    // invoking user's home so user-scoped cert paths (Firefox profiles,
    // macOS login keychain, the mhrv-rs data dir) are not silently
    // operated against root's home. No-op on Windows and for non-sudo
    // invocations.
    reconcile_sudo_environment();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            print_help();
            return ExitCode::from(2);
        }
    };

    // --remove-cert runs without a valid config — the CA files may be
    // the only thing present in the data dir. `config.json` and the
    // Apps Script deployment are intentionally untouched: the user does
    // not have to redeploy Code.gs after regenerating the CA.
    if args.remove_cert {
        init_logging("info");
        let base = mhrv_rs::data_dir::data_dir();
        match remove_ca(&base) {
            Ok(outcome) => {
                tracing::info!("{}", outcome.summary());
                tracing::info!(
                    "A fresh CA will be generated next time the proxy starts — \
                     run --install-cert then to re-trust it."
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("remove failed: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    // --install-cert can run without a valid config — only needs the CA file.
    if args.install_cert {
        init_logging("info");
        let base = mhrv_rs::data_dir::data_dir();
        if let Err(e) = MitmCertManager::new_in(&base) {
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

    let config_path = mhrv_rs::data_dir::resolve_config_path(args.config_path.as_deref());
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!(
                "No valid config found. Copy config.example.json to either:\n  {}\nor run with --config <path>.",
                config_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    init_logging(&config.log_level);

    // Bump RLIMIT_NOFILE now that tracing is live — OpenWRT/Alpine hosts
    // often ship a default so low (issue #8, issue #18) that we run out
    // of fds under normal proxy load. This logs the before/after values
    // at info level so field reports tell us whether the kernel cap is
    // the real culprit.
    mhrv_rs::rlimit::raise_nofile_limit_best_effort();

    match args.command {
        Command::Test => {
            let ok = test_cmd::run(&config).await;
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Command::ScanIps => {
            let ok = scan_ips::run(&config).await;
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Command::ScanSni => {
            let ok = scan_sni::discover_snis_from_google_ips(&config).await;
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }

        Command::TestSni => {
            let ok = scan_sni::run(&config).await;
            return if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Command::Serve => {}
    }

    let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);
    let mode = match config.mode_kind() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("config: {}", e);
            return ExitCode::FAILURE;
        }
    };
    tracing::warn!("mhrv-rs {} starting (mode: {})", VERSION, mode.as_str());
    tracing::info!(
        "HTTP proxy   : {}:{}",
        config.listen_host,
        config.listen_port
    );
    tracing::info!("SOCKS5 proxy : {}:{}", config.listen_host, socks5_port);
    match mode {
        mhrv_rs::config::Mode::AppsScript => {
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
        }
        mhrv_rs::config::Mode::GoogleOnly => {
            tracing::warn!(
                "google_only bootstrap: direct SNI-rewrite tunnel to {} only. \
                 Open https://script.google.com in your browser (proxy set to \
                 {}:{}), deploy Code.gs, then switch to apps_script mode.",
                config.google_ip,
                config.listen_host,
                config.listen_port
            );
        }
        mhrv_rs::config::Mode::Full => {
            tracing::info!(
                "Full tunnel: SNI={} -> script.google.com (via {})",
                config.front_domain,
                config.google_ip
            );
            let sids = config.script_ids_resolved();
            if sids.len() > 1 {
                tracing::info!("Script IDs: {} (round-robin)", sids.len());
            } else {
                tracing::info!("Script ID: {}", sids[0]);
            }
            tracing::warn!(
                "Full tunnel mode: NO certificate installation needed. \
                 ALL traffic is tunneled end-to-end through Apps Script + tunnel node."
            );
        }
    }

    // Initialize MITM manager (generates CA on first run).
    let base = mhrv_rs::data_dir::data_dir();
    let mitm = match MitmCertManager::new_in(&base) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to init MITM CA: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let ca_path = base.join(CA_CERT_FILE);

    if !args.no_cert_check && mode != mhrv_rs::config::Mode::Full {
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

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let run = server.run(shutdown_rx);
    tokio::select! {
        r = run => {
            if let Err(e) = r {
                eprintln!("server error: {}", e);
                return ExitCode::FAILURE;
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::warn!("Ctrl+C — shutting down.");
            let _ = shutdown_tx.send(());
        }
    }
    ExitCode::SUCCESS
}
