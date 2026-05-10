//! Curated fronting groups bundled with the binary.
//!
//! The JSON at `assets/fronting-groups/curated.json` ships a tested set
//! of (sni, edge IP, member-domain) tuples for Vercel, Fastly, AWS
//! CloudFront, and direct-to-GitHub paths — derived from
//! patterniha/MITM-DomainFronting. The UI exposes a button to install
//! these into the user's `fronting_groups` config in one click; CLI
//! users can copy `config.fronting-groups.example.json` (same data).
//!
//! Keep the asset in sync with the example file. `merge_into` is the
//! merge entry point: it appends groups whose `name` isn't already
//! present, leaving the user's hand-edited entries alone.
//!
//! Edge IPs rotate. The `sni` is the source of truth for re-resolution
//! (`nslookup <sni>`); see docs/fronting-groups.md.

use serde::Deserialize;

use crate::config::FrontingGroup;

/// Embedded JSON from `assets/fronting-groups/curated.json`. The path
/// is relative to the source file (`src/curated_groups.rs`), so the
/// `..` walks up to the crate root where `assets/` lives.
const CURATED_JSON: &str = include_str!("../assets/fronting-groups/curated.json");

#[derive(Debug, Deserialize)]
struct Bundle {
    fronting_groups: Vec<FrontingGroup>,
}

/// Parsed curated fronting groups. Returns the same list every call
/// — cheap enough that we don't bother caching across calls.
pub fn curated_fronting_groups() -> Result<Vec<FrontingGroup>, serde_json::Error> {
    let bundle: Bundle = serde_json::from_str(CURATED_JSON)?;
    Ok(bundle.fronting_groups)
}

/// Result of a `merge_into` call, surfaced to the UI for toast text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Groups newly appended to `existing`.
    pub added: usize,
    /// Groups skipped because a group with the same `name` was already
    /// present. The user's entry is left untouched (we never overwrite
    /// hand-edits).
    pub skipped: usize,
}

/// Append every curated group whose `name` isn't already in `existing`.
/// Skipped groups are counted in the report. Names compare
/// case-insensitively after trim, matching the way humans edit configs.
pub fn merge_into(existing: &mut Vec<FrontingGroup>) -> Result<MergeReport, serde_json::Error> {
    let curated = curated_fronting_groups()?;
    let mut report = MergeReport::default();
    for g in curated {
        let already = existing
            .iter()
            .any(|e| e.name.trim().eq_ignore_ascii_case(g.name.trim()));
        if already {
            report.skipped += 1;
        } else {
            existing.push(g);
            report.added += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_bundle_parses() {
        let groups = curated_fronting_groups().expect("curated.json must parse");
        assert!(
            !groups.is_empty(),
            "curated bundle should ship at least one group"
        );
        // github-direct must come before fastly, otherwise fastly's
        // `githubusercontent.com` suffix would eat
        // `objects-origin.githubusercontent.com` before
        // github-content-direct gets to claim it.
        let pos = |n: &str| groups.iter().position(|g| g.name == n);
        let github_content = pos("github-content-direct").expect("github-content-direct present");
        let fastly = pos("fastly").expect("fastly present");
        assert!(
            github_content < fastly,
            "github-content-direct must precede fastly for first-match-wins"
        );
    }

    #[test]
    fn merge_into_skips_existing_by_name() {
        let mut existing = vec![FrontingGroup {
            name: "vercel".into(),
            ip: "1.2.3.4".into(),
            sni: "user-edited.example".into(),
            domains: vec!["user.example".into()],
        }];
        let before_len = existing.len();
        let report = merge_into(&mut existing).expect("merge should succeed");
        // The user's vercel entry stays put.
        let user_vercel = existing
            .iter()
            .find(|g| g.name == "vercel")
            .expect("user vercel group preserved");
        assert_eq!(user_vercel.ip, "1.2.3.4");
        assert_eq!(user_vercel.sni, "user-edited.example");
        assert_eq!(report.skipped, 1, "vercel collision should be reported");
        assert_eq!(existing.len(), before_len + report.added);
    }

    #[test]
    fn merge_into_adds_all_when_empty() {
        let mut existing: Vec<FrontingGroup> = Vec::new();
        let report = merge_into(&mut existing).expect("merge should succeed");
        assert_eq!(report.skipped, 0);
        assert!(report.added > 0);
        assert_eq!(existing.len(), report.added);
    }

    /// The example config file at the repo root mirrors the curated
    /// asset bundle. Both files exist for different audiences (CLI
    /// users copy the example, UI users hit the button to load the
    /// asset) but their `fronting_groups` payloads must stay identical
    /// so the two paths can't drift. This test pins that property.
    /// Together with [example_file_loads_through_validate] it also
    /// confirms the asset is a valid input to the real load path.
    #[test]
    fn example_file_mirrors_curated_bundle() {
        use crate::config::Config;
        let curated = curated_fronting_groups().expect("curated.json parses");
        let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config.fronting-groups.example.json");
        let example_cfg = Config::load(&example_path)
            .expect("example file must load + validate");
        assert_eq!(
            curated.len(),
            example_cfg.fronting_groups.len(),
            "curated.json and the example file must declare the same group count"
        );
        for (c, e) in curated.iter().zip(example_cfg.fronting_groups.iter()) {
            assert_eq!(c.name, e.name, "group name");
            assert_eq!(c.ip, e.ip, "group ip ({})", c.name);
            assert_eq!(c.sni, e.sni, "group sni ({})", c.name);
            assert_eq!(c.domains, e.domains, "group domains ({})", c.name);
        }
    }

    /// Run the curated bundle through the same `Config::load` path the
    /// CLI and UI use at startup — this exercises the SNI parse, the
    /// per-group field validators, and the duplicate-name check inside
    /// `validate()`. Catches the failure mode where curated.json and
    /// the validator drift apart (e.g. a future validator tightens
    /// what counts as a valid SNI but a curated entry slips through
    /// because it was only tested against `serde_json::from_str`).
    #[test]
    fn example_file_loads_through_validate() {
        use crate::config::Config;
        let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config.fronting-groups.example.json");
        let cfg = Config::load(&example_path)
            .expect("example file with curated groups must pass Config::validate");
        assert!(
            !cfg.fronting_groups.is_empty(),
            "example file should declare fronting groups"
        );
    }
}
