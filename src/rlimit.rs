//! Best-effort file descriptor limit bump on Unix.
//!
//! Context (issues #8 + #18): on OpenWRT routers — and some minimal
//! Alpine / BSD installs — the default `RLIMIT_NOFILE` is so low
//! (often 1024 or even 256 / 128 on constrained devices) that a
//! browser's burst of ~30 parallel subresource requests, or a DNS-over-
//! SOCKS5 flood from a client like v2ray, fills the limit within seconds.
//! Once the limit is hit `accept(2)` returns `EMFILE` and the user sees:
//!
//! ```text
//! ERROR accept (socks): No file descriptors available (os error 24)
//! ```
//!
//! Approach:
//!   - Try to raise the SOFT limit to a generous target.
//!   - If the HARD limit is also low, try to raise THAT too — Linux lets
//!     a non-root process bump its hard limit up to `/proc/sys/fs/nr_open`.
//!   - Log what we ended up with so a user filing a bug report can tell
//!     us whether their kernel cap is below what a real proxy needs.

#[cfg(unix)]
pub fn raise_nofile_limit_best_effort() {
    // Ambitious target. 65536 is plenty for even heavy router use (a
    // whole LAN doing browser + DNS + Telegram over our SOCKS5). Costs
    // ~0 kernel memory until actually used.
    const DESIRED: u64 = 65_536;

    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("getrlimit(RLIMIT_NOFILE) failed: {}", err);
            return;
        }
        let original_soft = rl.rlim_cur as u64;
        let original_hard = rl.rlim_max as u64;

        // Figure out an absolute ceiling. On Linux, /proc/sys/fs/nr_open
        // is the highest the kernel will ever let a process set its
        // RLIMIT_NOFILE. Read it and use it as our hard-limit target.
        // On macOS/BSD this file doesn't exist — we just keep the
        // existing hard limit.
        let kernel_ceiling = read_nr_open().unwrap_or(original_hard);
        let want_hard = DESIRED.max(original_hard).min(kernel_ceiling);

        // Step 1: raise the hard limit if it's below what we want. This
        // can only go UP on non-privileged processes (lowering it is
        // permanent and requires CAP_SYS_RESOURCE to undo).
        if want_hard > original_hard {
            rl.rlim_max = want_hard as libc::rlim_t;
            rl.rlim_cur = want_hard as libc::rlim_t;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                let err = std::io::Error::last_os_error();
                tracing::debug!(
                    "setrlimit raising hard {}→{} failed: {} (trying soft-only)",
                    original_hard,
                    want_hard,
                    err
                );
                // Fall through to step 2 with the unmodified hard limit.
                rl.rlim_max = original_hard as libc::rlim_t;
            }
        }

        // Step 2: raise soft up to whatever hard allows.
        let effective_hard = rl.rlim_max as u64;
        let want_soft = DESIRED.min(effective_hard);
        if want_soft > original_soft {
            rl.rlim_cur = want_soft as libc::rlim_t;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    "setrlimit raising soft {}→{} failed: {}",
                    original_soft,
                    want_soft,
                    err
                );
                return;
            }
        }

        // Re-read and report.
        let mut now = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::getrlimit(libc::RLIMIT_NOFILE, &mut now);
        let soft = now.rlim_cur as u64;
        let hard = now.rlim_max as u64;

        if soft < 4096 {
            // This is genuinely too low for a local proxy under LAN load.
            // Log loudly so the user knows their system is the bottleneck,
            // not us.
            tracing::warn!(
                "RLIMIT_NOFILE is {}/{} (soft/hard). This is likely too low for a \
                 proxy under any real load and WILL cause 'No file descriptors \
                 available' errors. On OpenWRT, ensure you're starting via the \
                 shipped procd init script (which sets nofile=16384), or add \
                 `ulimit -n 65536` to your startup script.",
                soft,
                hard,
            );
        } else {
            tracing::info!(
                "RLIMIT_NOFILE = {}/{} (soft/hard), was {}/{} at startup",
                soft,
                hard,
                original_soft,
                original_hard,
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn read_nr_open() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_nr_open() -> Option<u64> {
    None
}

#[cfg(not(unix))]
pub fn raise_nofile_limit_best_effort() {}
