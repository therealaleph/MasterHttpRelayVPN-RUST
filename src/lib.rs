#![allow(dead_code)]

pub mod cache;
pub mod cert_installer;
pub mod config;
pub mod data_dir;
pub mod domain_fronter;
pub mod mitm;
pub mod proxy_server;
pub mod rlimit;
pub mod tunnel_client;
pub mod scan_ips;
pub mod scan_sni;
pub mod test_cmd;
pub mod update_check;

// Desktop-only — Android delegates APK install to PackageInstaller, doesn't
// need the extract / sig-verify / binary-swap machinery. On Android the
// module still exists as a stub so `main.rs` can call
// `update_apply::finalize_pending_at_startup()` unconditionally.
pub mod update_apply;

#[cfg(target_os = "android")]
pub mod android_jni;
