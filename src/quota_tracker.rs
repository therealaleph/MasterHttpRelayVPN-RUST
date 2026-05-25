// Quota tracking for Apps Script mode.
//
// Model assumption: each script_id in the configured list represents one
// separate Google account. Apps Script's UrlFetchApp quota is per-user/account,
// not per-script-deployment. This tool treats each configured deployment as a
// distinct account bucket so quotas are tracked independently. The structure is
// flexible enough for future refinement if a single account has multiple
// deployments.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use portable_atomic::AtomicU64;
use portable_atomic::Ordering;
use serde::{Deserialize, Serialize};

use crate::data_dir;

// ── Persisted per-account state ──────────────────────────────────────────────

/// State for one Apps Script account bucket (one configured script_id).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountBucket {
    /// Masked script id for log output (first 4 + "..." + last 4 chars).
    pub masked_id: String,
    /// Requests used in the current 24-hour window.
    pub requests_used: u64,
    /// Failed requests in the current 24-hour window.
    pub failed_requests: u64,
    /// Bytes of JSON payload uploaded to Apps Script (all attempts).
    pub bytes_up: u64,
    /// Bytes of response body received from Apps Script (successful only).
    pub bytes_down: u64,
    /// Total bytes transferred (bytes_up + bytes_down).
    pub bytes_total: u64,
    /// Unix timestamp of the last recorded request for this account.
    pub last_request_at: Option<u64>,
    /// Unix timestamp when this bucket's 24-hour window resets.
    /// Set to first_request_time + 86400 on first use in each window.
    /// Follows Apps Script's actual quota model: resets 24 h after first
    /// request, not at a fixed midnight boundary.
    pub next_reset_at: Option<u64>,
    /// Whether this account has been flagged as quota-exhausted.
    pub exhausted: bool,
    /// Whether routing to this account is hard-stopped (no more dispatches).
    /// Once set, stays set across restarts until manually cleared in the JSON
    /// file or until the rolling window resets on the next recorded request.
    pub hard_stopped: bool,
    /// Human-readable reason this account was exhausted/stopped.
    pub exhaustion_reason: Option<String>,
    /// Count of responses with quota-like error messages from this account.
    /// Separate from failed_requests so callers can distinguish quota signals
    /// from generic upstream failures.
    pub quota_error_count: u64,
}

// ── In-memory aggregate summary (not persisted) ──────────────────────────────

/// Aggregate quota view across all account buckets.
/// Cheap to clone — used to pass a snapshot to the UI and terminal logs.
#[derive(Debug, Clone, Default)]
pub struct QuotaSummary {
    /// Number of tracked account buckets (= number of configured script_ids).
    pub account_count: usize,
    /// Total daily capacity across all accounts (account_count × daily_limit).
    pub daily_capacity_total: u64,
    /// Total requests used across all active windows.
    pub requests_used_total: u64,
    /// Total requests remaining before the aggregate safety reserve is hit.
    pub requests_remaining_total: u64,
    /// Total failed requests across all buckets.
    pub failed_requests_total: u64,
    /// Total bytes uploaded across all buckets.
    pub bytes_up_total: u64,
    /// Total bytes downloaded across all buckets.
    pub bytes_down_total: u64,
    /// Total bytes transferred (up + down) across all buckets.
    pub bytes_total: u64,
    /// Number of accounts currently marked exhausted.
    pub exhausted_count: usize,
    /// Number of accounts currently hard-stopped.
    pub hard_stopped_count: usize,
    /// Whether a global hard stop is active (all buckets exhausted, or
    /// aggregate remaining quota has crossed the collective safety threshold
    /// with confirmed quota error signals).
    pub global_hard_stop: bool,
    /// Unix timestamp of the soonest window reset across all non-exhausted buckets.
    pub next_reset_at: Option<u64>,
    /// Unix timestamp of the soonest window reset across ALL buckets, including
    /// hard-stopped ones. Used by the UI to show a meaningful reset time even
    /// when all accounts are exhausted.
    pub next_reset_at_any: Option<u64>,
    /// Total relay() calls today (all paths). Persisted across restarts.
    /// Resets at UTC midnight.
    pub total_relay_calls: u64,
}

// ── Disk state wrapper ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct QuotaState {
    buckets: HashMap<String, AccountBucket>,
    /// Total relay() calls today across all paths (exit node + Apps Script).
    /// Persisted so restarts don't reset the "fetches today" counter.
    #[serde(default)]
    total_relay_calls: u64,
    /// UTC day number (unix_secs / 86400) when total_relay_calls was last reset.
    /// When the day changes, total_relay_calls is zeroed on the next record_relay().
    #[serde(default)]
    relay_today_day: u64,
}

// ── Tracker ───────────────────────────────────────────────────────────────────

pub struct QuotaTracker {
    state: Mutex<QuotaState>,
    /// Ordered list of script_ids from config (determines account_count).
    script_ids: Vec<String>,
    /// Daily request limit per account. Default 20_000 (free tier).
    /// Set 100_000 for Google Workspace accounts.
    daily_limit: u64,
    /// Per-account safety buffer. An account is considered effectively done
    /// when its remaining requests drop below this value. This reserve keeps
    /// calls away from Google's hard quota edge, staying on the safer side
    /// of anti-abuse heuristics and ToS gray areas.
    /// Aggregate hard-stop reserve = account_count × safety_buffer.
    safety_buffer: u64,
    /// Incremented on every mutation; used to decide when to auto-flush.
    dirty_count: AtomicU64,
    state_path: PathBuf,
}

fn quota_state_path() -> PathBuf {
    data_dir::data_dir().join("quota_state.json")
}

/// Mark any bucket that is already past the safety buffer as hard-stopped.
/// Called at load time so accounts near the limit are blocked before the
/// first request arrives, not after it fires.
fn check_all_safety_buffers(qs: &mut QuotaState, daily_limit: u64, safety_buffer: u64) {
    for bucket in qs.buckets.values_mut() {
        if bucket.hard_stopped {
            continue;
        }
        let remaining = daily_limit.saturating_sub(bucket.requests_used);
        if remaining < safety_buffer {
            bucket.exhausted = true;
            bucket.hard_stopped = true;
            bucket.exhaustion_reason = Some(format!(
                "safety buffer crossed on load: {}/{} requests used (limit {}, buffer {})",
                bucket.requests_used, daily_limit, daily_limit, safety_buffer,
            ));
        }
    }
}

fn mask_id(id: &str) -> String {
    let n = id.chars().count();
    if n <= 8 {
        return "***".into();
    }
    let head: String = id.chars().take(4).collect();
    let tail: String = id.chars().skip(n - 4).collect();
    format!("{}...{}", head, tail)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl QuotaTracker {
    /// Load persisted quota state from disk, or create a fresh tracker if
    /// the file is absent or unreadable. Validates loaded buckets against
    /// the current script_id list and inserts missing entries.
    pub fn load(script_ids: &[String], daily_limit: u64, safety_buffer: u64) -> Self {
        let state_path = quota_state_path();
        let mut qs = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<QuotaState>(&raw).ok())
            .unwrap_or_default();

        // Ensure every configured script_id has a bucket entry.
        for sid in script_ids {
            qs.buckets.entry(sid.clone()).or_insert_with(|| AccountBucket {
                masked_id: mask_id(sid),
                ..Default::default()
            });
        }

        // Pre-check safety buffers on loaded state so accounts that are already
        // near the limit are marked hard_stopped before the first request arrives,
        // not after it fires.
        check_all_safety_buffers(&mut qs, daily_limit, safety_buffer);

        let tracker = Self {
            state: Mutex::new(qs),
            script_ids: script_ids.to_vec(),
            daily_limit,
            safety_buffer,
            dirty_count: AtomicU64::new(0),
            state_path,
        };
        // Always write on startup so the file exists and reflects current state
        // before any relay traffic arrives. Without this, the file is only created
        // after the first dirty_count increment (i.e. after real traffic).
        tracker.save();
        tracker
    }

    // ── Recording ────────────────────────────────────────────────────────────

    /// Record one Apps Script fetch attempt for `script_id`. Called once per
    /// `do_relay_once_with` call, including retries — every call here maps
    /// to one real `UrlFetchApp.fetch()` on Google's side.
    ///
    /// Rolls the 24-hour window forward if needed (rolling from first request,
    /// not from midnight — matches Apps Script's actual quota reset cadence).
    pub fn record_attempt(&self, script_id: &str, bytes_up: u64) {
        let now = now_unix();
        let mut st = self.state.lock().unwrap();
        let bucket = st.buckets.entry(script_id.to_string()).or_insert_with(|| {
            AccountBucket {
                masked_id: mask_id(script_id),
                ..Default::default()
            }
        });

        // Roll the window if the 24-hour period has elapsed.
        if let Some(reset_at) = bucket.next_reset_at {
            if now >= reset_at {
                bucket.requests_used = 0;
                bucket.failed_requests = 0;
                bucket.bytes_up = 0;
                bucket.bytes_down = 0;
                bucket.bytes_total = 0;
                bucket.next_reset_at = Some(now + 86_400);
                // Clear exhaustion flags on window reset so the account gets a
                // fresh chance in the new quota period.
                bucket.exhausted = false;
                bucket.hard_stopped = false;
                bucket.exhaustion_reason = None;
                bucket.quota_error_count = 0;
            }
        } else {
            // First request for this account — open the rolling window.
            bucket.next_reset_at = Some(now + 86_400);
        }

        // Check safety buffer BEFORE incrementing so the account is stopped on
        // the request that would exceed the limit, not the one after it.
        let next_used = bucket.requests_used + 1;
        let remaining = self.daily_limit.saturating_sub(next_used);
        if !bucket.hard_stopped && remaining < self.safety_buffer {
            bucket.exhausted = true;
            bucket.hard_stopped = true;
            bucket.exhaustion_reason = Some(format!(
                "safety buffer crossed: {}/{} requests used (limit {}, buffer {})",
                next_used, self.daily_limit,
                self.daily_limit, self.safety_buffer,
            ));
            tracing::warn!(
                "[quota] account {} safety buffer reached ({} remaining < {}): marking hard-stopped",
                bucket.masked_id, remaining, self.safety_buffer,
            );
        }

        bucket.requests_used = next_used;
        bucket.bytes_up += bytes_up;
        bucket.bytes_total += bytes_up;
        bucket.last_request_at = Some(now);

        drop(st);
        let n = self.dirty_count.fetch_add(1, Ordering::Relaxed);
        if n % 50 == 0 {
            self.save();
        }
    }

    /// Record that a relay attempt succeeded and the response body was `bytes_down` bytes.
    pub fn record_success(&self, script_id: &str, bytes_down: u64) {
        let mut st = self.state.lock().unwrap();
        if let Some(bucket) = st.buckets.get_mut(script_id) {
            bucket.bytes_down += bytes_down;
            bucket.bytes_total += bytes_down;
        }
        drop(st);
        self.dirty_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed relay attempt for `script_id`.
    /// `is_quota_error` should be true only when the failure is confidently a
    /// quota-related error from Apps Script (not a local transport/network failure).
    /// Does NOT mark the account exhausted — callers do that separately via
    /// `mark_exhausted` when they are confident the account is done.
    pub fn record_failure(&self, script_id: &str, is_quota_error: bool) {
        let mut st = self.state.lock().unwrap();
        if let Some(bucket) = st.buckets.get_mut(script_id) {
            bucket.failed_requests += 1;
            if is_quota_error {
                bucket.quota_error_count += 1;
            }
        }
        drop(st);
        self.dirty_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Hard-stop a specific account bucket with an explicit reason.
    /// Force-saves to disk immediately so the state survives a crash/restart.
    pub fn mark_exhausted(&self, script_id: &str, reason: &str) {
        let mut st = self.state.lock().unwrap();
        let bucket = st.buckets.entry(script_id.to_string()).or_insert_with(|| {
            AccountBucket {
                masked_id: mask_id(script_id),
                ..Default::default()
            }
        });
        bucket.exhausted = true;
        bucket.hard_stopped = true;
        bucket.exhaustion_reason = Some(reason.to_string());
        drop(st);
        self.save();
    }

    // ── Routing queries ──────────────────────────────────────────────────────

    /// Returns true if this account should be excluded from relay dispatch.
    pub fn is_hard_stopped(&self, script_id: &str) -> bool {
        let st = self.state.lock().unwrap();
        st.buckets
            .get(script_id)
            .map(|b| b.hard_stopped)
            .unwrap_or(false)
    }

    /// Returns true when all tracked account buckets are hard-stopped, OR when
    /// the aggregate remaining quota has crossed the collective safety threshold
    /// AND at least one confirmed quota error has been seen.
    ///
    /// Conservative by design: random transport failures or local disconnects do
    /// NOT trigger a global stop. Only exhaustion of every individual account
    /// bucket OR a confirmed aggregate-quota crossing with quota error evidence
    /// activates this.
    pub fn is_globally_hard_stopped(&self) -> bool {
        if self.script_ids.is_empty() {
            return false;
        }
        let st = self.state.lock().unwrap();
        let all_stopped = self.script_ids.iter().all(|sid| {
            st.buckets.get(sid).map(|b| b.hard_stopped).unwrap_or(false)
        });
        if all_stopped {
            return true;
        }
        // Secondary check: aggregate remaining < N × safety_buffer
        // AND at least one quota error signal has been seen (not just network
        // failures or local disconnects).
        // Only sum over currently configured script_ids so stale buckets from
        // removed accounts don't inflate the used count or error tally and
        // falsely trip this check.
        let total_quota_errors: u64 = self.script_ids.iter()
            .filter_map(|sid| st.buckets.get(sid))
            .map(|b| b.quota_error_count)
            .sum();
        if total_quota_errors == 0 {
            return false;
        }
        let total_used: u64 = self.script_ids.iter()
            .filter_map(|sid| st.buckets.get(sid))
            .map(|b| b.requests_used)
            .sum();
        let total_cap = self.daily_limit * self.script_ids.len() as u64;
        let total_remaining = total_cap.saturating_sub(total_used);
        let aggregate_reserve = self.safety_buffer * self.script_ids.len() as u64;
        total_remaining < aggregate_reserve
    }

    // ── Summary ──────────────────────────────────────────────────────────────

    /// Build a point-in-time aggregate summary across all tracked buckets.
    pub fn summary(&self) -> QuotaSummary {
        let n = self.script_ids.len();
        if n == 0 {
            return QuotaSummary::default();
        }
        let st = self.state.lock().unwrap();
        let mut used_total = 0u64;
        let mut failed_total = 0u64;
        let mut bytes_up = 0u64;
        let mut bytes_down = 0u64;
        let mut bytes_total = 0u64;
        let mut exhausted = 0usize;
        let mut hard_stopped = 0usize;
        let mut next_reset: Option<u64> = None;
        let mut next_reset_any: Option<u64> = None;
        let total_relay_calls = st.total_relay_calls;

        for sid in &self.script_ids {
            let Some(b) = st.buckets.get(sid) else { continue };
            used_total += b.requests_used;
            failed_total += b.failed_requests;
            bytes_up += b.bytes_up;
            bytes_down += b.bytes_down;
            bytes_total += b.bytes_total;
            if b.exhausted { exhausted += 1; }
            if b.hard_stopped { hard_stopped += 1; }
            if let Some(r) = b.next_reset_at {
                // next_reset_any covers all accounts including stopped ones.
                next_reset_any = Some(match next_reset_any {
                    None => r,
                    Some(prev) => prev.min(r),
                });
                if !b.hard_stopped {
                    next_reset = Some(match next_reset {
                        None => r,
                        Some(prev) => prev.min(r),
                    });
                }
            }
        }
        drop(st);

        let capacity = self.daily_limit * n as u64;
        // Remaining is capacity minus used, floored at zero.
        let remaining = capacity.saturating_sub(used_total);
        let global_stop = self.is_globally_hard_stopped();

        QuotaSummary {
            account_count: n,
            daily_capacity_total: capacity,
            requests_used_total: used_total,
            requests_remaining_total: remaining,
            failed_requests_total: failed_total,
            bytes_up_total: bytes_up,
            bytes_down_total: bytes_down,
            bytes_total,
            exhausted_count: exhausted,
            hard_stopped_count: hard_stopped,
            global_hard_stop: global_stop,
            next_reset_at: next_reset,
            next_reset_at_any: next_reset_any,
            total_relay_calls,
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// Write current state to `quota_state.json`. Non-fatal: logs on IO error.
    pub fn save(&self) {
        let st = self.state.lock().unwrap();
        match serde_json::to_string(&*st) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, json) {
                    tracing::warn!("[quota] failed to save state to {}: {}", self.state_path.display(), e);
                }
            }
            Err(e) => {
                tracing::warn!("[quota] failed to serialize quota state: {}", e);
            }
        }
    }

    /// Save if any mutations have occurred since the last flush.
    /// Called from the 1-second save task and periodic stats task.
    pub fn save_if_needed(&self) {
        if self.dirty_count.load(Ordering::Relaxed) > 0 {
            self.save();
            // Reset after save so next call knows it's clean.
            self.dirty_count.store(0, Ordering::Relaxed);
        }
    }

    /// Roll any expired 24-hour windows for all tracked buckets.
    /// Called from the periodic stats task so windows reset even when the
    /// proxy is idle and no new requests arrive to trigger record_attempt.
    pub fn roll_expired_windows(&self) {
        let now = now_unix();
        let mut st = self.state.lock().unwrap();
        let mut rolled = false;
        for bucket in st.buckets.values_mut() {
            if let Some(reset_at) = bucket.next_reset_at {
                if now >= reset_at {
                    bucket.requests_used = 0;
                    bucket.failed_requests = 0;
                    bucket.bytes_up = 0;
                    bucket.bytes_down = 0;
                    bucket.bytes_total = 0;
                    bucket.next_reset_at = Some(now + 86_400);
                    bucket.exhausted = false;
                    bucket.hard_stopped = false;
                    bucket.exhaustion_reason = None;
                    bucket.quota_error_count = 0;
                    rolled = true;
                    tracing::info!(
                        "[quota] account {} window rolled (idle expiry) — quota reset",
                        bucket.masked_id,
                    );
                }
            }
        }
        drop(st);
        if rolled {
            self.dirty_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record one call to relay() — all paths (exit node + Apps Script).
    /// Persisted so "fetches today" survives proxy restarts. Resets at UTC midnight.
    pub fn record_relay(&self) {
        let today = now_unix() / 86_400;
        let mut st = self.state.lock().unwrap();
        if st.relay_today_day != today {
            st.relay_today_day = today;
            st.total_relay_calls = 0;
        }
        st.total_relay_calls += 1;
        drop(st);
        self.dirty_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Log the masked ID and exhaustion reason for every hard-stopped bucket.
    /// Called once when global hard stop transitions from false to true.
    pub fn log_exhaustion_details(&self) {
        let st = self.state.lock().unwrap();
        for sid in &self.script_ids {
            let Some(b) = st.buckets.get(sid) else { continue };
            if b.hard_stopped {
                let reason = b.exhaustion_reason.as_deref().unwrap_or("no reason recorded");
                tracing::warn!("[quota]   {} exhausted: {}", b.masked_id, reason);
            }
        }
    }

    /// Build a human-readable startup summary line.
    pub fn startup_summary(&self) -> String {
        let s = self.summary();
        let now = now_unix();
        let reset_str = s.next_reset_at.map(|r| {
            let secs = r.saturating_sub(now);
            format!("  next_reset=in {}h {}m", secs / 3600, (secs / 60) % 60)
        }).unwrap_or_default();
        let stop_suffix = if s.global_hard_stop {
            format!("  exhausted={}/{} HARD-STOP", s.exhausted_count, s.account_count)
        } else if s.exhausted_count > 0 {
            format!("  exhausted={}/{}", s.exhausted_count, s.account_count)
        } else {
            String::new()
        };

        format!(
            "[quota] {} account(s)  capacity={}/day  used={}  remaining={}{}{}",
            s.account_count,
            s.daily_capacity_total,
            s.requests_used_total,
            s.requests_remaining_total,
            reset_str,
            stop_suffix,
        )
    }
}

impl Drop for QuotaTracker {
    fn drop(&mut self) {
        self.save();
    }
}

#[cfg(test)]
impl QuotaTracker {
    fn new_for_test(
        script_ids: Vec<String>,
        daily_limit: u64,
        safety_buffer: u64,
        state: QuotaState,
    ) -> Self {
        Self {
            state: Mutex::new(state),
            script_ids,
            daily_limit,
            safety_buffer,
            dirty_count: AtomicU64::new(0),
            state_path: std::path::PathBuf::from("/dev/null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stale exhausted bucket from a removed script ID must not cause a
    /// global hard stop when the currently configured ID is fresh and healthy.
    #[test]
    fn stale_exhausted_bucket_does_not_trigger_global_hard_stop() {
        let stale_id = "stale_removed_aaaa1111bbbb2222cccc".to_string();
        let active_id = "active_fresh_xxxx9999yyyy8888zzzz".to_string();

        let mut state = QuotaState::default();
        state.buckets.insert(stale_id.clone(), AccountBucket {
            masked_id: mask_id(&stale_id),
            requests_used: 19_500,
            quota_error_count: 5,
            exhausted: true,
            hard_stopped: true,
            exhaustion_reason: Some("quota exhausted".into()),
            ..Default::default()
        });
        state.buckets.insert(active_id.clone(), AccountBucket {
            masked_id: mask_id(&active_id),
            requests_used: 100,
            ..Default::default()
        });

        // Only active_id is in the live config — stale_id was removed.
        let tracker = QuotaTracker::new_for_test(
            vec![active_id],
            20_000,
            500,
            state,
        );

        assert!(
            !tracker.is_globally_hard_stopped(),
            "stale exhausted bucket from a removed script_id should not trigger global hard stop"
        );
    }
}
