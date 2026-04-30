# Maintainer knowledge base

Project-internal knowledge base for triaging issues, reviewing PRs, cutting releases, and writing user-facing replies in the project's voice. Treat this as canonical context for any maintenance work — local or automated.

## Read order

Start with `SKILL.md` for orientation, conventions, and pointers. Then read references lazily as relevant to the current task:

- `references/architecture.md` — apps_script vs Full mode, MITM CA, tunnel-node, AUTH_KEY/TUNNEL_AUTH_KEY/DIAGNOSTIC_MODE, SNI rewriting, Apps Script's hidden constraints
- `references/issue-patterns.md` — recurring user issue patterns with diagnostic procedures and canonical reply structures
- `references/diagnostic-taxonomy.md` — six candidate causes for the placeholder body, DIAGNOSTIC_MODE disambiguator
- `references/workflow-conventions.md` — reply marker, Persian/English match rule, changelog format, commit messages, close reasons
- `references/release-workflow.md` — Cargo.toml → tag → Telegram pipeline
- `references/update-signing.md` — one-time maintainer setup for minisign-signed auto-updates (CI gates on repo vars, defaults to off)
- `references/contributors.md` — core contributor roles + their substantive PRs
- `references/roadmap.md` — current and upcoming release batches
- `references/persian-templates.md` — adaptable Persian reply templates and standardized phrasings
- `assets/changelog-template.md` — starter template for a new `docs/changelog/vX.Y.Z.md`
- `assets/reply-marker.md` — the standard reply footer
