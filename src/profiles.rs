//! Profile storage for the UI layer.
//!
//! A profile is a named, complete snapshot of `config.json`. The Rust core
//! (proxy server, tunnel client, MITM) keeps reading from a single
//! `config.json` — profiles are a UI-only convenience that lets the user
//! keep several configurations side by side (e.g. one Apps Script setup
//! and one Full tunnel setup) and switch between them without re-typing
//! deployment IDs, auth keys, and tuning knobs.
//!
//! Snapshots are stored as `serde_json::Value` rather than the parsed
//! `Config` struct. Forward-compat: a profile written by a newer build
//! that has more config fields still loads on an older build, and any
//! unknown fields round-trip through Save/Switch without being dropped.
//!
//! # Invariants (must match the Android side, see `ProfileStore.kt`)
//!
//!  1. **Raw snapshot preservation.** A profile's `config` is stored
//!     exactly as written. Applying a profile writes that raw JSON to
//!     `config.json` byte-for-byte (subject to pretty-print) — any
//!     config fields the desktop build doesn't model survive. The
//!     apply path must NOT round-trip through `Config` parse and
//!     re-serialize.
//!
//!  2. **`active` means "matches the live config".** Setting
//!     `active = "name"` is a promise that `profiles[name].config`
//!     equals the current `config.json`. Any operation that breaks
//!     that promise must clear `active` (set it to `""`). In
//!     particular: deleting the active profile sets `active = ""`
//!     — we do NOT auto-apply some other profile, because that would
//!     silently rewrite the user's live config.
//!
//!  3. **Persist before in-memory state changes.** Mutate a clone,
//!     `save()` the clone, then commit the clone to `self` only on
//!     success. A failed write must not leave the UI showing state
//!     that will disappear on restart.
//!
//!  4. **Load failure is loud.** A file that exists but won't parse is
//!     surfaced as a real error so the UI can refuse to clobber a
//!     corrupted-but-recoverable `profiles.json` with an empty one.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::data_dir;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("failed to read profiles file {0}: {1}")]
    Read(String, #[source] std::io::Error),
    #[error("failed to write profiles file {0}: {1}")]
    Write(String, #[source] std::io::Error),
    #[error("failed to parse profiles json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("profile '{0}' not found")]
    NotFound(String),
    #[error("profile '{0}' already exists")]
    Duplicate(String),
    #[error("profile name must not be empty")]
    EmptyName,
    /// The on-disk `profiles.json` exists but failed to parse. The UI
    /// must refuse to overwrite — clobbering a corrupted-but-recoverable
    /// file with an empty / partially-edited new one would destroy any
    /// chance of hand-recovering the user's data.
    #[error("profiles file on disk is corrupt: {0}")]
    CorruptOnDisk(String),
}

/// One named config snapshot. `config` is the raw config JSON object —
/// kept as a `Value` so adding fields to `Config` later doesn't require
/// touching this module, and so unknown fields round-trip cleanly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub config: serde_json::Value,
}

/// Top-level profiles file. `active` names the currently-selected profile
/// per invariant 2: `active = "name"` is a claim that `profiles[name]`
/// matches the live `config.json`. `active = ""` means no profile is
/// known to match (e.g. the user hand-edited `config.json` directly,
/// or the active profile was just deleted).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfilesFile {
    #[serde(default)]
    pub active: String,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

/// Path to `profiles.json` inside the platform data dir.
pub fn profiles_path() -> PathBuf {
    data_dir::data_dir().join("profiles.json")
}

/// Validate that a profile entry's shape is loadable / applyable.
///
/// Specifically: name must be non-empty after trim, and `config` must
/// be a JSON object (not `null`, not a scalar, not an array). The
/// runtime parses `config.json` with `serde(default)` so any object
/// is *acceptable* even if some fields are unknown, but `null` or a
/// non-object would write garbage that `Config::load` then rejects
/// — and worse, would clobber the user's previous live config in
/// the process. Reject loudly at load/upsert time so we never even
/// attempt the write.
/// Validate that a snapshot would load successfully as the runtime
/// [`Config`] — i.e. it parses, has a known mode, and (for
/// relay-bearing modes) has the credentials those modes need.
///
/// Mirrors [`crate::config::Config::load`] (which is
/// `from_str` + `validate()`) but operating on an already-parsed
/// `serde_json::Value`. We deliberately keep this check at the
/// apply boundary rather than at load time so that an older saved
/// profile doesn't get retroactively flagged corrupt the next time
/// the user opens the UI.
fn validate_snapshot_loadable(value: &serde_json::Value) -> Result<(), String> {
    let cfg: crate::config::Config = serde_json::from_value(value.clone())
        .map_err(|e| format!("snapshot is not a loadable Config: {}", e))?;
    cfg.validate()
        .map_err(|e| format!("snapshot would not pass runtime validation: {}", e))?;
    Ok(())
}

fn validate_profile(idx: usize, p: &Profile) -> Result<(), String> {
    let label = format!("profiles[{}]", idx);
    if p.name.trim().is_empty() {
        return Err(format!("{}: name is empty or whitespace", label));
    }
    if !p.config.is_object() {
        let kind = match &p.config {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object", // unreachable
        };
        return Err(format!(
            "{} ('{}'): config must be a JSON object, got {}",
            label, p.name, kind
        ));
    }
    Ok(())
}

impl ProfilesFile {
    /// Load the profiles file. Missing file = empty store (not an error
    /// — first run has no profiles yet). A file that exists but won't
    /// parse is returned as `Err(CorruptOnDisk)` so the UI can refuse
    /// to overwrite it (invariant 4).
    pub fn load() -> Result<Self, ProfileError> {
        Self::load_from(&profiles_path())
    }

    pub fn load_from(path: &Path) -> Result<Self, ProfileError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)
            .map_err(|e| ProfileError::Read(path.display().to_string(), e))?;
        if data.trim().is_empty() {
            return Ok(Self::default());
        }
        let pf: ProfilesFile = serde_json::from_str(&data)
            .map_err(|e| ProfileError::CorruptOnDisk(format!("{}", e)))?;
        // Strict schema check: matches Android's `parse` strictness so
        // a partially-malformed file surfaces loudly here too. Each
        // profile must have a non-empty name and a JSON object for
        // `config` — otherwise applying it would clobber config.json
        // with non-config bytes (e.g. `null`).
        for (i, p) in pf.profiles.iter().enumerate() {
            validate_profile(i, p)
                .map_err(|msg| ProfileError::CorruptOnDisk(msg))?;
        }
        // Names must be unique. With duplicates, `active` and every
        // by-name operation (apply / rename / delete) become
        // ambiguous: Rust's `delete` removes only the first match
        // while Android's `delete` removes all matches, so the two
        // implementations diverge on the same file. Reject loudly
        // so the user can hand-fix.
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(pf.profiles.len());
        for (i, p) in pf.profiles.iter().enumerate() {
            if !seen.insert(p.name.as_str()) {
                return Err(ProfileError::CorruptOnDisk(format!(
                    "profiles[{}] ('{}'): duplicate profile name",
                    i, p.name
                )));
            }
        }
        Ok(pf)
    }

    /// Save atomically: write to `profiles.json.tmp` then rename. Avoids
    /// a torn file if the UI crashes mid-write.
    pub fn save(&self) -> Result<(), ProfileError> {
        self.save_to(&profiles_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), ProfileError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ProfileError::Write(parent.display().to_string(), e))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)
            .map_err(|e| ProfileError::Write(tmp.display().to_string(), e))?;
        // `std::fs::rename` is an atomic replace on every platform we
        // support: POSIX rename(2) is atomic for same-filesystem
        // renames, and Windows since Rust 1.5 uses MoveFileExW with
        // MOVEFILE_REPLACE_EXISTING. We rely on that — we do NOT
        // remove the target first, which would create a window where
        // neither the old nor the new file exists if the subsequent
        // rename fails (data loss). If rename fails for some other
        // reason (locked file, antivirus), the original is preserved
        // and the tmp file is left behind for hand recovery.
        std::fs::rename(&tmp, path)
            .map_err(|e| ProfileError::Write(path.display().to_string(), e))?;
        Ok(())
    }

    pub fn names(&self) -> Vec<String> {
        self.profiles.iter().map(|p| p.name.clone()).collect()
    }

    pub fn find(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.name == name)
    }

    /// Upsert: replace the snapshot for an existing name, or append a
    /// new profile. The active pointer is moved to the upserted name
    /// — by invariant 2 this is correct ONLY if the caller also writes
    /// the snapshot to `config.json`. The high-level wrapper
    /// [`apply_saved_profile_to_live_config`] does both atomically;
    /// direct callers must do the same or accept the divergence.
    pub fn upsert(&mut self, name: &str, config: serde_json::Value) -> Result<(), ProfileError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if !config.is_object() {
            return Err(ProfileError::CorruptOnDisk(format!(
                "profile '{}': config must be a JSON object",
                name
            )));
        }
        if let Some(p) = self.find_mut(name) {
            p.config = config;
        } else {
            self.profiles.push(Profile {
                name: name.to_string(),
                config,
            });
        }
        self.active = name.to_string();
        Ok(())
    }

    /// Insert a new profile, refusing to overwrite an existing one of
    /// the same name. Same invariant-2 caveat as [`upsert`].
    pub fn insert_new(
        &mut self,
        name: &str,
        config: serde_json::Value,
    ) -> Result<(), ProfileError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if !config.is_object() {
            return Err(ProfileError::CorruptOnDisk(format!(
                "profile '{}': config must be a JSON object",
                name
            )));
        }
        if self.find(name).is_some() {
            return Err(ProfileError::Duplicate(name.to_string()));
        }
        self.profiles.push(Profile {
            name: name.to_string(),
            config,
        });
        self.active = name.to_string();
        Ok(())
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), ProfileError> {
        let to = to.trim();
        if to.is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if from != to && self.find(to).is_some() {
            return Err(ProfileError::Duplicate(to.to_string()));
        }
        let p = self
            .find_mut(from)
            .ok_or_else(|| ProfileError::NotFound(from.to_string()))?;
        p.name = to.to_string();
        if self.active == from {
            self.active = to.to_string();
        }
        Ok(())
    }

    /// Delete. If the deleted profile was active, `active` becomes `""`
    /// (invariant 2). We do NOT silently pick "first remaining" — that
    /// would claim some unrelated profile matches the live config when
    /// it doesn't. The user can explicitly switch to a different
    /// profile if they want.
    pub fn delete(&mut self, name: &str) -> Result<(), ProfileError> {
        let idx = self
            .profiles
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| ProfileError::NotFound(name.to_string()))?;
        self.profiles.remove(idx);
        if self.active == name {
            self.active = String::new();
        }
        Ok(())
    }

    /// Duplicate `from` under `to`. Non-destructive: does NOT change
    /// the active pointer or touch `config.json`.
    pub fn duplicate(&mut self, from: &str, to: &str) -> Result<(), ProfileError> {
        let to = to.trim();
        if to.is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if self.find(to).is_some() {
            return Err(ProfileError::Duplicate(to.to_string()));
        }
        let src = self
            .find(from)
            .ok_or_else(|| ProfileError::NotFound(from.to_string()))?;
        let copy = Profile {
            name: to.to_string(),
            config: src.config.clone(),
        };
        self.profiles.push(copy);
        Ok(())
    }
}

/// Outcome of [`apply_profile`]. Splits the two failure modes the UI
/// cares about: "nothing changed" (config write failed, we can show
/// a clean error) vs "config swapped but pointer didn't move"
/// (live runtime is on the new profile, just the bookkeeping is
/// stale — the UI should reflect the apply but warn the user).
#[derive(Debug)]
pub enum ApplyOutcome {
    /// Both `config.json` and `profiles.json` were written.
    Ok,
    /// `config.json` was written — live config IS the new profile —
    /// but the `profiles.json` write failed. The UI should reload the
    /// form (because config.json changed) and surface the carried
    /// error so the user knows the dropdown's active marker is stale.
    PartialConfigOnly(ProfileError),
}

/// Write a profile's snapshot to `config.json` and update the active
/// pointer. By invariant 1 we serialize the snapshot raw (not via a
/// `Config` round-trip) so any fields this build doesn't model still
/// survive in the live config — the Rust runtime parses with
/// `#[serde(default)]` on unknown fields, so they're harmlessly
/// preserved.
///
/// Outcome contract:
///   - `Err(ProfileError::NotFound)` — profile missing, no writes attempted.
///   - `Err(...)` for any error BEFORE `config.json` is written — nothing
///     changed on disk.
///   - `Ok(ApplyOutcome::Ok)` — both writes succeeded.
///   - `Ok(ApplyOutcome::PartialConfigOnly(e))` — `config.json` is the
///     new profile but `profiles.json` write failed. The caller should
///     still treat this as "switched" for UI purposes and surface the
///     carried error so the user sees the divergence honestly.
pub fn apply_profile(name: &str) -> Result<ApplyOutcome, ProfileError> {
    apply_profile_with_paths(&profiles_path(), &data_dir::config_path(), name)
}

/// Path-injecting variant of [`apply_profile`] for testability. Lets
/// unit tests redirect both files to a temp dir AND inject a write
/// failure on `config_path` (by making the path a directory before
/// the call, which makes the rename fail).
pub fn apply_profile_with_paths(
    profiles_path: &Path,
    config_path: &Path,
    name: &str,
) -> Result<ApplyOutcome, ProfileError> {
    let pf = ProfilesFile::load_from(profiles_path)?;
    let p = pf
        .find(name)
        .ok_or_else(|| ProfileError::NotFound(name.to_string()))?;

    // Belt-and-braces: even though load_from now schema-validates,
    // re-check at the apply boundary so a hand-modified in-memory
    // ProfilesFile can't smuggle a non-object snapshot through to
    // config.json. Without this, a `config: null` profile would
    // clobber the user's live config with the literal bytes `null`.
    validate_profile(0, p).map_err(ProfileError::CorruptOnDisk)?;

    // Runtime-shape validation: refuse to write a snapshot that
    // wouldn't load as a Config (e.g. {}, missing required mode,
    // missing script_id/auth_key for apps_script/full). Without
    // this, applying a malformed profile would clobber the user's
    // working config.json with bytes the runtime then rejects on
    // next start, leaving them with neither the old config nor a
    // usable one. We deliberately don't run this check at load
    // time — older saved profiles may pre-date a validation
    // tightening and we shouldn't mark them corrupt retroactively.
    validate_snapshot_loadable(&p.config).map_err(ProfileError::CorruptOnDisk)?;

    // Raw write — preserves unknown fields (invariant 1). If this
    // fails, nothing has changed on disk.
    write_config_json_to(config_path, &p.config)?;

    // Past this point, `config.json` IS the new profile. A failure
    // moving the pointer is real but not catastrophic — we surface it
    // as PartialConfigOnly.
    let mut updated = pf;
    updated.active = name.to_string();
    match updated.save_to(profiles_path) {
        Ok(()) => Ok(ApplyOutcome::Ok),
        Err(e) => Ok(ApplyOutcome::PartialConfigOnly(e)),
    }
}

/// Apply a snapshot value as the live config without involving the
/// profile store. Used by "Save as profile" — invariant 2 requires
/// that whenever we set `active = name`, the snapshot under that name
/// must equal `config.json`. The natural way to satisfy that on save
/// is to also write the snapshot to `config.json`.
pub fn write_config_json(snapshot: &serde_json::Value) -> Result<(), ProfileError> {
    write_config_json_to(&data_dir::config_path(), snapshot)
}

/// Path-injecting variant of [`write_config_json`] for testability.
/// Tests can make `cfg_path` a directory before calling so the
/// rename step fails and we can verify nothing-changed semantics.
pub fn write_config_json_to(
    cfg_path: &Path,
    snapshot: &serde_json::Value,
) -> Result<(), ProfileError> {
    let json = serde_json::to_string_pretty(snapshot)?;
    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ProfileError::Write(parent.display().to_string(), e))?;
    }
    let tmp = cfg_path.with_extension("json.tmp");
    std::fs::write(&tmp, json)
        .map_err(|e| ProfileError::Write(tmp.display().to_string(), e))?;
    // Atomic replace via rename — same rationale as ProfilesFile::save_to.
    // Do NOT pre-delete the target; rename(2) and MoveFileExW with
    // MOVEFILE_REPLACE_EXISTING are atomic on POSIX and Windows
    // respectively, and pre-deleting opens a window where neither file
    // exists if the rename then fails.
    let rename = std::fs::rename(&tmp, cfg_path)
        .map_err(|e| ProfileError::Write(cfg_path.display().to_string(), e));
    if rename.is_err() {
        // Best-effort cleanup of the tmp file so we don't litter the
        // data dir after a failed write.
        let _ = std::fs::remove_file(&tmp);
    }
    rename
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_profiles_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mhrv-profiles-{}-{}",
            label,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("profiles.json")
    }

    #[test]
    fn round_trip_via_tempfile() {
        let path = temp_profiles_path("rt");
        let _ = std::fs::remove_file(&path);

        let mut pf = ProfilesFile::default();
        pf.upsert("home", json!({"mode": "apps_script", "script_id": "A"}))
            .unwrap();
        pf.upsert(
            "work",
            json!({"mode": "full", "script_id": "B", "auth_key": "k"}),
        )
        .unwrap();
        pf.save_to(&path).unwrap();
        assert_eq!(pf.active, "work");

        let loaded = ProfilesFile::load_from(&path).unwrap();
        assert_eq!(loaded.profiles.len(), 2);
        assert_eq!(loaded.active, "work");
        assert_eq!(loaded.find("home").unwrap().config["script_id"], "A");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_replaces_existing() {
        let mut pf = ProfilesFile::default();
        pf.upsert("p", json!({"v": 1})).unwrap();
        pf.upsert("p", json!({"v": 2})).unwrap();
        assert_eq!(pf.profiles.len(), 1);
        assert_eq!(pf.find("p").unwrap().config["v"], 2);
    }

    #[test]
    fn insert_new_refuses_overwrite() {
        let mut pf = ProfilesFile::default();
        pf.insert_new("p", json!({})).unwrap();
        let err = pf.insert_new("p", json!({})).unwrap_err();
        assert!(matches!(err, ProfileError::Duplicate(_)));
    }

    #[test]
    fn rename_moves_active_pointer() {
        let mut pf = ProfilesFile::default();
        pf.upsert("a", json!({})).unwrap();
        assert_eq!(pf.active, "a");
        pf.rename("a", "b").unwrap();
        assert_eq!(pf.active, "b");
        assert!(pf.find("a").is_none());
        assert!(pf.find("b").is_some());
    }

    #[test]
    fn rename_to_existing_fails() {
        let mut pf = ProfilesFile::default();
        pf.upsert("a", json!({})).unwrap();
        pf.upsert("b", json!({})).unwrap();
        let err = pf.rename("a", "b").unwrap_err();
        assert!(matches!(err, ProfileError::Duplicate(_)));
    }

    /// Invariant 2: deleting the active profile clears `active`. We do
    /// NOT silently jump to "first remaining" because that would
    /// imply some unrelated profile matches the live config when it
    /// doesn't.
    #[test]
    fn delete_active_clears_pointer() {
        let mut pf = ProfilesFile::default();
        pf.upsert("a", json!({})).unwrap();
        pf.upsert("b", json!({})).unwrap();
        pf.upsert("c", json!({})).unwrap();
        // active is "c" after the last upsert.
        pf.delete("c").unwrap();
        assert_eq!(pf.active, "");
        // Other profiles remain accessible — they just don't auto-take
        // the active slot.
        assert!(pf.find("a").is_some());
        assert!(pf.find("b").is_some());
    }

    #[test]
    fn delete_non_active_keeps_pointer() {
        let mut pf = ProfilesFile::default();
        pf.upsert("a", json!({})).unwrap();
        pf.upsert("b", json!({})).unwrap();
        // active is "b".
        pf.delete("a").unwrap();
        assert_eq!(pf.active, "b");
    }

    #[test]
    fn delete_last_clears_pointer() {
        let mut pf = ProfilesFile::default();
        pf.upsert("only", json!({})).unwrap();
        pf.delete("only").unwrap();
        assert_eq!(pf.active, "");
        assert!(pf.profiles.is_empty());
    }

    #[test]
    fn duplicate_copies_snapshot() {
        let mut pf = ProfilesFile::default();
        pf.upsert("a", json!({"x": 1})).unwrap();
        pf.duplicate("a", "a-copy").unwrap();
        assert_eq!(pf.find("a-copy").unwrap().config["x"], 1);
        // Active pointer should NOT move on duplicate — it's a non-destructive
        // operation that doesn't change which profile matches the live config.
        assert_eq!(pf.active, "a");
    }

    #[test]
    fn empty_name_rejected() {
        let mut pf = ProfilesFile::default();
        assert!(matches!(
            pf.upsert("  ", json!({})).unwrap_err(),
            ProfileError::EmptyName
        ));
        assert!(matches!(
            pf.insert_new("", json!({})).unwrap_err(),
            ProfileError::EmptyName
        ));
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = std::env::temp_dir().join("mhrv-profiles-missing.json");
        let _ = std::fs::remove_file(&path);
        let pf = ProfilesFile::load_from(&path).unwrap();
        assert!(pf.profiles.is_empty());
        assert!(pf.active.is_empty());
    }

    /// Invariant 4: a present-but-unparseable file is loud, not silent.
    /// We must NOT flatten it to an empty State — the next save would
    /// then clobber the user's recoverable data.
    #[test]
    fn corrupt_file_surfaces_error() {
        let path = temp_profiles_path("corrupt");
        std::fs::write(&path, "{ not valid json").unwrap();
        let err = ProfilesFile::load_from(&path).unwrap_err();
        assert!(
            matches!(err, ProfileError::CorruptOnDisk(_)),
            "expected CorruptOnDisk, got {:?}",
            err
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Invariant 4 follow-up: empty file is treated as fresh / no
    /// profiles (not corrupt). Whitespace-only too.
    #[test]
    fn empty_file_loads_empty() {
        let path = temp_profiles_path("empty");
        std::fs::write(&path, "   \n  ").unwrap();
        let pf = ProfilesFile::load_from(&path).unwrap();
        assert!(pf.profiles.is_empty());
        assert!(pf.active.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    /// Invariant 1: unknown / future config fields round-trip through
    /// the snapshot store without loss. This is the property the
    /// Android side must also uphold (verified by raw-write on the
    /// apply path).
    #[test]
    fn forward_compat_unknown_config_fields_roundtrip() {
        let mut pf = ProfilesFile::default();
        pf.upsert(
            "future",
            json!({"mode": "apps_script", "future_field_xyz": [1, 2, 3]}),
        )
        .unwrap();
        let path = temp_profiles_path("fwd");
        let _ = std::fs::remove_file(&path);
        pf.save_to(&path).unwrap();
        let loaded = ProfilesFile::load_from(&path).unwrap();
        assert_eq!(
            loaded.find("future").unwrap().config["future_field_xyz"],
            json!([1, 2, 3])
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Regression guard for the data-loss-on-rename bug: `save_to`
    /// must NOT pre-delete the target. If rename fails (which we
    /// can't easily inject) the user still has the previous file.
    /// We can only verify the success path here, but we explicitly
    /// check that after a save the file contents match what we
    /// wrote and that NO `.tmp` is left behind on disk.
    #[test]
    fn save_to_leaves_no_tmp_behind_on_success() {
        let path = temp_profiles_path("notmp");
        let _ = std::fs::remove_file(&path);
        let mut pf = ProfilesFile::default();
        pf.upsert("p", json!({"v": 1})).unwrap();
        pf.save_to(&path).unwrap();
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp file should be cleaned up after rename");
        // And the target should have the new bytes.
        let loaded = ProfilesFile::load_from(&path).unwrap();
        assert_eq!(loaded.find("p").unwrap().config["v"], 1);
        let _ = std::fs::remove_file(&path);
    }

    /// Helper: temp dir holding a `profiles.json` + `config.json` pair
    /// for path-injecting tests of [`apply_profile_with_paths`].
    fn temp_pair(label: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "mhrv-apply-{}-{}-{}",
            label,
            std::process::id(),
            // monotonic nanos as a tie-breaker between concurrent test threads
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("profiles.json");
        let c = dir.join("config.json");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&c);
        (p, c)
    }

    fn cleanup_pair(p: &Path, c: &Path) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(c);
        let _ = std::fs::remove_file(p.with_extension("json.tmp"));
        let _ = std::fs::remove_file(c.with_extension("json.tmp"));
        // Tear down dir too if empty.
        if let Some(dir) = p.parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }

    /// A real-shaped snapshot that the runtime would accept. We pick
    /// `direct` mode so we don't need to invent a script_id / auth_key.
    fn loadable_snapshot(extra: serde_json::Value) -> serde_json::Value {
        let mut obj = serde_json::json!({"mode": "direct"});
        if let Some(map) = extra.as_object() {
            let target = obj.as_object_mut().unwrap();
            for (k, v) in map {
                target.insert(k.clone(), v.clone());
            }
        }
        obj
    }

    /// Happy path: both writes succeed → Ok and both files reflect
    /// the new profile.
    #[test]
    fn apply_profile_with_paths_ok() {
        let (pp, cp) = temp_pair("ok");
        let mut pf = ProfilesFile::default();
        pf.upsert("home", loadable_snapshot(json!({"k": 1}))).unwrap();
        // Reset active so the apply has work to do.
        pf.active = String::new();
        pf.save_to(&pp).unwrap();

        let outcome = apply_profile_with_paths(&pp, &cp, "home").unwrap();
        assert!(matches!(outcome, ApplyOutcome::Ok), "got {:?}", outcome);
        // Active moved.
        let after = ProfilesFile::load_from(&pp).unwrap();
        assert_eq!(after.active, "home");
        // config.json reflects the snapshot (including the unknown `k`
        // field — invariant 1, raw passthrough).
        let cfg_bytes = std::fs::read_to_string(&cp).unwrap();
        let cfg_val: serde_json::Value = serde_json::from_str(&cfg_bytes).unwrap();
        assert_eq!(cfg_val["k"], 1);

        cleanup_pair(&pp, &cp);
    }

    /// Inject a write failure on `config.json` by making the path
    /// a directory before the call. The rename step inside
    /// [`write_config_json_to`] then fails because we can't
    /// overwrite a directory with a file.
    ///
    /// Expected: Err(...) is returned, `profiles.json` is unchanged
    /// from its pre-call state, NO active pointer move was attempted
    /// (because we abort before that step), and the placeholder
    /// `config.json/` directory still exists.
    #[test]
    fn apply_profile_config_write_failure_changes_nothing() {
        let (pp, cp) = temp_pair("cfgfail");
        let mut pf = ProfilesFile::default();
        pf.upsert("home", json!({"v": "new"})).unwrap();
        pf.upsert("other", json!({"v": "other"})).unwrap();
        pf.active = "other".to_string();
        pf.save_to(&pp).unwrap();
        let profiles_before = std::fs::read_to_string(&pp).unwrap();

        // Force config write to fail: create a directory at cp.
        std::fs::create_dir_all(&cp).unwrap();
        // Drop a file inside so it can't be cleaned up as an empty
        // dir (a defensive measure in case rename had any sneaky
        // POSIX behaviour with empty dirs).
        std::fs::write(cp.join("sentinel"), "x").unwrap();

        let result = apply_profile_with_paths(&pp, &cp, "home");
        assert!(result.is_err(), "expected Err, got {:?}", result);

        // profiles.json must be byte-identical to its pre-call state
        // — the apply was supposed to abort before touching it.
        let profiles_after = std::fs::read_to_string(&pp).unwrap();
        assert_eq!(
            profiles_before, profiles_after,
            "profiles.json must not change when config.json write fails"
        );

        // Clean up the directory we made.
        let _ = std::fs::remove_file(cp.join("sentinel"));
        let _ = std::fs::remove_dir(&cp);
        cleanup_pair(&pp, &cp);
    }

    /// Inject a write failure on `profiles.json` AFTER `config.json`
    /// has been written. Expected outcome: `ApplyOutcome::PartialConfigOnly`
    /// — config IS the new bytes, but the active pointer didn't
    /// update on disk.
    ///
    /// Injected by making `profiles.json.tmp` a directory before
    /// `ProfilesFile::save_to` runs. The write step inside save_to
    /// then fails on the tmp file.
    #[test]
    fn apply_profile_profiles_write_failure_returns_partial() {
        let (pp, cp) = temp_pair("ppfail");
        let mut pf = ProfilesFile::default();
        pf.upsert("home", loadable_snapshot(json!({"v": "new"})))
            .unwrap();
        pf.upsert("other", loadable_snapshot(json!({"v": "other"})))
            .unwrap();
        pf.active = "other".to_string();
        pf.save_to(&pp).unwrap();

        // Block the tmp write by making profiles.json.tmp a directory.
        let tmp = pp.with_extension("json.tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("sentinel"), "x").unwrap();

        let outcome = apply_profile_with_paths(&pp, &cp, "home").unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::PartialConfigOnly(_)),
            "expected PartialConfigOnly, got {:?}",
            outcome
        );

        // config.json IS the new snapshot.
        let cfg_bytes = std::fs::read_to_string(&cp).unwrap();
        let cfg_val: serde_json::Value = serde_json::from_str(&cfg_bytes).unwrap();
        assert_eq!(cfg_val["v"], "new");

        // profiles.json is UNCHANGED — active is still "other", and
        // both profile snapshots are unmodified. The dropdown on disk
        // is stale (still claims "other" is active), but the partial
        // outcome surfaces that honestly to the caller.
        let pf_after = ProfilesFile::load_from(&pp).unwrap();
        assert_eq!(pf_after.active, "other");
        assert_eq!(pf_after.find("home").unwrap().config["v"], "new");
        assert_eq!(pf_after.find("other").unwrap().config["v"], "other");

        // Clean up.
        let _ = std::fs::remove_file(tmp.join("sentinel"));
        let _ = std::fs::remove_dir(&tmp);
        cleanup_pair(&pp, &cp);
    }

    /// Schema validation parity with Android: a profile whose
    /// `config` is `null` (or any non-object) must surface as
    /// CorruptOnDisk at load time. Without this, applying that
    /// profile would write the literal bytes `null` to
    /// `config.json`, clobbering the user's live config.
    #[test]
    fn null_config_surfaces_as_corrupt() {
        let path = temp_profiles_path("null-cfg");
        std::fs::write(
            &path,
            r#"{"active":"","profiles":[{"name":"bad","config":null}]}"#,
        )
        .unwrap();
        let err = ProfilesFile::load_from(&path).unwrap_err();
        assert!(
            matches!(err, ProfileError::CorruptOnDisk(_)),
            "expected CorruptOnDisk for null config, got {:?}",
            err
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn array_config_surfaces_as_corrupt() {
        let path = temp_profiles_path("arr-cfg");
        std::fs::write(
            &path,
            r#"{"active":"","profiles":[{"name":"bad","config":[1,2,3]}]}"#,
        )
        .unwrap();
        let err = ProfilesFile::load_from(&path).unwrap_err();
        assert!(matches!(err, ProfileError::CorruptOnDisk(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// Duplicate names are an invariant violation: every by-name
    /// operation (apply / rename / delete) becomes ambiguous, and
    /// Rust's "remove first" delete diverges from Android's "remove
    /// all" delete on the same file. Reject loudly on load.
    #[test]
    fn duplicate_names_surface_as_corrupt() {
        let path = temp_profiles_path("dup-names");
        std::fs::write(
            &path,
            r#"{
                "active": "p",
                "profiles": [
                    {"name": "p", "config": {"mode": "apps_script"}},
                    {"name": "p", "config": {"mode": "full"}}
                ]
            }"#,
        )
        .unwrap();
        let err = ProfilesFile::load_from(&path).unwrap_err();
        match err {
            ProfileError::CorruptOnDisk(msg) => {
                assert!(
                    msg.contains("duplicate"),
                    "error should call out the duplicate explicitly: {}",
                    msg
                );
            }
            other => panic!("expected CorruptOnDisk, got {:?}", other),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_name_surfaces_as_corrupt() {
        let path = temp_profiles_path("empty-name");
        std::fs::write(
            &path,
            r#"{"active":"","profiles":[{"name":"   ","config":{"mode":"apps_script"}}]}"#,
        )
        .unwrap();
        let err = ProfilesFile::load_from(&path).unwrap_err();
        assert!(matches!(err, ProfileError::CorruptOnDisk(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// In-memory `upsert` must also reject non-object configs so a
    /// caller can't smuggle a bad shape past the load-time check.
    #[test]
    fn upsert_rejects_non_object_config() {
        let mut pf = ProfilesFile::default();
        let err = pf.upsert("p", json!(null)).unwrap_err();
        assert!(matches!(err, ProfileError::CorruptOnDisk(_)));
        let err = pf.upsert("p", json!([1, 2, 3])).unwrap_err();
        assert!(matches!(err, ProfileError::CorruptOnDisk(_)));
        let err = pf.upsert("p", json!("just a string")).unwrap_err();
        assert!(matches!(err, ProfileError::CorruptOnDisk(_)));
        // And nothing should have been added to the store.
        assert!(pf.profiles.is_empty());
    }

    /// Belt-and-braces: even if a non-object snapshot somehow makes
    /// it past load (e.g. a hand-edited in-memory ProfilesFile),
    /// `apply_profile_with_paths` re-validates and refuses to write
    /// it to config.json.
    #[test]
    fn apply_profile_refuses_non_object_snapshot() {
        let (pp, cp) = temp_pair("bad-snapshot");
        // Bypass the public API to plant a bad snapshot directly.
        let bad = ProfilesFile {
            active: "bad".to_string(),
            profiles: vec![Profile {
                name: "bad".to_string(),
                config: serde_json::Value::Null,
            }],
        };
        // We have to write this with raw JSON because save_to → load
        // round-trip would reject it. Hand-craft instead.
        std::fs::write(
            &pp,
            serde_json::to_string(&serde_json::json!({
                "active": "bad",
                "profiles": [{"name": "bad", "config": serde_json::Value::Null}],
            }))
            .unwrap(),
        )
        .unwrap();
        let _ = bad; // suppress unused warning

        // Plant a known config.json so we can assert it's unchanged.
        std::fs::write(&cp, r#"{"mode":"apps_script","auth_key":"orig"}"#).unwrap();
        let before = std::fs::read_to_string(&cp).unwrap();

        let result = apply_profile_with_paths(&pp, &cp, "bad");
        assert!(
            matches!(result, Err(ProfileError::CorruptOnDisk(_))),
            "expected CorruptOnDisk, got {:?}",
            result
        );
        // config.json must be byte-identical — we refused before writing.
        assert_eq!(before, std::fs::read_to_string(&cp).unwrap());
        cleanup_pair(&pp, &cp);
    }

    /// A snapshot that's an empty JSON object passes the structural
    /// "is object" check but would fail `Config::validate` for
    /// apps_script/full mode (no script_id, no auth_key). Apply must
    /// refuse to clobber config.json with bytes the runtime would
    /// reject — otherwise the user ends up with neither their old
    /// working config nor a usable one.
    #[test]
    fn apply_profile_refuses_empty_object_snapshot() {
        let (pp, cp) = temp_pair("empty-obj");
        std::fs::write(
            &pp,
            r#"{"active":"empty","profiles":[{"name":"empty","config":{}}]}"#,
        )
        .unwrap();
        std::fs::write(&cp, r#"{"mode":"apps_script","auth_key":"orig","script_id":"X"}"#).unwrap();
        let before = std::fs::read_to_string(&cp).unwrap();

        let result = apply_profile_with_paths(&pp, &cp, "empty");
        assert!(
            matches!(result, Err(ProfileError::CorruptOnDisk(_))),
            "expected CorruptOnDisk, got {:?}",
            result
        );
        assert_eq!(
            before,
            std::fs::read_to_string(&cp).unwrap(),
            "live config must be unchanged when snapshot fails runtime validation"
        );
        cleanup_pair(&pp, &cp);
    }

    /// Snapshot with `auth_key` but no `script_id` / `script_ids` and
    /// mode = `apps_script` should also be rejected — the runtime
    /// Config validator demands at least one deployment ID for
    /// relay-bearing modes.
    #[test]
    fn apply_profile_refuses_missing_script_id_snapshot() {
        let (pp, cp) = temp_pair("no-script-id");
        let snapshot = serde_json::json!({
            "mode": "apps_script",
            "auth_key": "MY_REAL_SECRET",
            // Note: no script_id / script_ids — invalid for apps_script.
        });
        let pf = serde_json::json!({
            "active": "bad",
            "profiles": [{"name": "bad", "config": snapshot}],
        });
        std::fs::write(&pp, serde_json::to_string(&pf).unwrap()).unwrap();
        std::fs::write(&cp, r#"{"mode":"apps_script","auth_key":"orig","script_id":"X"}"#).unwrap();
        let before = std::fs::read_to_string(&cp).unwrap();

        let result = apply_profile_with_paths(&pp, &cp, "bad");
        assert!(
            matches!(result, Err(ProfileError::CorruptOnDisk(_))),
            "expected CorruptOnDisk, got {:?}",
            result
        );
        assert_eq!(before, std::fs::read_to_string(&cp).unwrap());
        cleanup_pair(&pp, &cp);
    }

    /// A `direct` mode snapshot doesn't need script_id or auth_key
    /// (the runtime tolerates both being absent there). It must pass.
    #[test]
    fn apply_profile_accepts_minimal_direct_snapshot() {
        let (pp, cp) = temp_pair("min-direct");
        let pf = serde_json::json!({
            "active": "",
            "profiles": [{"name": "direct", "config": {"mode": "direct"}}],
        });
        std::fs::write(&pp, serde_json::to_string(&pf).unwrap()).unwrap();
        let result = apply_profile_with_paths(&pp, &cp, "direct");
        assert!(
            matches!(result, Ok(ApplyOutcome::Ok)),
            "minimal direct snapshot must apply cleanly, got {:?}",
            result
        );
        cleanup_pair(&pp, &cp);
    }

    /// write_config_json_to's tmp file is cleaned up on rename
    /// failure — no leftover .tmp files after a failed apply.
    #[test]
    fn write_config_json_cleans_up_tmp_on_failure() {
        let (_pp, cp) = temp_pair("cleanup");
        std::fs::create_dir_all(&cp).unwrap();
        let _ = write_config_json_to(&cp, &json!({"v": 1}));
        let tmp = cp.with_extension("json.tmp");
        assert!(
            !tmp.exists(),
            "tmp file should be cleaned up after rename failure"
        );
        let _ = std::fs::remove_dir(&cp);
    }
}
