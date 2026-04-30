# Auto-updater signing — one-time setup

The desktop auto-updater (`src/update_apply.rs`) verifies a minisign
signature against an embedded public key before swapping the running
binary. The Android sideload updater uses the same embedded public key to
verify the downloaded APK's sibling `.minisig` before handing it to the
OS installer. Android's PackageInstaller still performs the normal APK
same-key check against the app's signing certificate; that prevents a
different package identity from replacing the app, but minisign is the
release-provenance check.

Until you complete the steps below the updater is in **rollout mode**:
it still applies updates, but it logs `MHRV_UPDATE_PUBKEY was not set
at build time — applying update without signature check (insecure)`. The
CI workflow's `sign` job is also skipped (it gates on
`vars.MINISIGN_SIGNING_ENABLED == 'true'`), and the build env var is left
empty. Both are fully backward-compatible — flipping the switch is what
turns verification on for new releases.

## What you're setting up

- **Public key** → committed to the repo as a GH Actions repo *variable*
  (it's public; doesn't need to be a secret), embedded into every release
  binary at compile time via `option_env!("MHRV_UPDATE_PUBKEY")`.
- **Secret key** → stored as a GH Actions *secret*, used by the `sign`
  job in `release.yml` to produce `<asset>.minisig` files for every
  release artifact.
- **Toggle** → repo variable that flips the `sign` job from skipped to
  active, so you can stage everything ahead of time and turn it on in a
  separate commit if you want.

## Step 1 — Generate the keypair (offline, one time)

Pick a machine that's not also a CI runner. Anywhere with `cargo` works:

```bash
cargo install --locked --version 0.6.5 rsign2
rsign generate -p mhrv-update.pub -s mhrv-update.key
# Choose a strong passphrase or hit enter for passwordless.
```

You now have:

- `mhrv-update.pub` — two lines: a comment, then the base64 public key
- `mhrv-update.key` — multi-line: comment, base64 secret key

Prefer a strong passphrase when you can. GitHub Actions secrets are
encrypted at rest, but a passwordless key is immediately usable if the
secret body ever leaks through a workflow-log mistake, compromised
runner, or maintainer-machine compromise. A passphrase adds
defense-in-depth; the CI workflow already reads it from the optional
`MINISIGN_KEY_PASSWORD` secret. Passwordless is still simpler and may be
acceptable for low-friction rollout, but treat that as a conscious
trade-off rather than extra security from Actions storage alone.

**Back up `mhrv-update.key` somewhere offline.** If you lose it, you
cannot sign future releases against the same public key, and existing
installs won't accept updates until you ship a new build with a new
embedded public key (which will then refuse to update from the old
build because *it* didn't have the new key embedded — you'd have to
break the update chain and ask users to manually reinstall). Don't lose
the key.

## Step 2 — Wire it into GitHub Actions

```bash
# Public key — bare base64 line (the one AFTER `untrusted comment:`).
gh variable set MINISIGN_PUBLIC_KEY --body "$(tail -1 mhrv-update.pub)"

# Secret key — full file content (multi-line). `gh secret set` reads
# stdin, which preserves newlines correctly.
gh secret set MINISIGN_SECRET_KEY < mhrv-update.key

# Passphrase, if you set one in step 1. Skip this command if the key is
# passwordless.
gh secret set MINISIGN_KEY_PASSWORD --body 'your-passphrase'

# Flip the switch — until this is `true`, the `sign` job is skipped and
# binaries embed no public key (rollout-mode behaviour).
gh variable set MINISIGN_SIGNING_ENABLED --body true
```

Sanity-check (run from the repo dir, or pass
`--repo therealaleph/MasterHttpRelayVPN-RUST` if you're elsewhere):

```bash
gh variable list   # MINISIGN_PUBLIC_KEY, MINISIGN_SIGNING_ENABLED
gh secret list     # MINISIGN_SECRET_KEY (+ MINISIGN_KEY_PASSWORD if set)
```

## Step 3 — Cut a release

Push a tag as you normally would. The `release` workflow now:

1. Builds binaries with `MHRV_UPDATE_PUBKEY` set, so the embedded key
   becomes the `option_env!` value at compile time.
2. Runs the `sign` job after build + android, which first fails fast if
   `MINISIGN_PUBLIC_KEY` or `MINISIGN_SECRET_KEY` is missing, then downloads every
   artifact, runs `rsign sign -W -s key -x out.minisig file` against
   each, and uploads the `.minisig` files as a workflow artifact.
3. The `release` job picks up everything (originals + `.minisig`s) and
   uploads them to the GitHub Release page.
4. The `commit-releases` job copies them all to the in-repo `releases/`
   folder so the GitHub-Releases-page-blocked fallback works for signed
   updates too.

## Step 4 — Verify a downloaded asset (manual sanity check)

```bash
rsign verify -P "$(tail -1 mhrv-update.pub)" \
  -x mhrv-rs-linux-amd64.tar.gz.minisig \
  mhrv-rs-linux-amd64.tar.gz
```

If you see `Signature and comment signature verified`, the chain works
end-to-end. Same check the `minisign-verify` crate runs at apply time.

## Rotating the keypair

Don't, unless the secret key is compromised. The cost is high: every
already-installed copy will refuse the update that ships the new public
key, because the *current* binary's embedded key won't match the new
signature. Recovery is "users manually reinstall from the GitHub Release
page" — the same UX as a Play-Store-less Android sideload.

If you must rotate:

1. Generate the new pair as in step 1.
2. **Sign the new binaries with BOTH the old key AND the new key.** Ship
   one `.minisig` per key (`<asset>.minisig` and `<asset>.minisig.new`,
   say) for at least one transitional release. The currently-deployed
   binary verifies against the old `.minisig` and applies cleanly; the
   newly-installed binary then has the new public key embedded and
   verifies against the new `.minisig` from then on.
3. After most users have advanced past the transitional release, drop
   the old signature.

This dual-sign step is not currently implemented in the workflow — it'd
need a small extension to the `sign` job. Add it then, not now.

## Threat model recap

What signing prevents:

- A compromised maintainer GitHub account or release pipeline pushing a
  malicious binary to the Releases page. Even though TLS proves "GitHub
  served this", without minisign the updater has no way to know whether
  the file came from a legitimate release process or a hijacked one.
  This applies to desktop archives and Android APK assets.

What signing does *not* prevent:

- A user downloading and running an unsigned binary manually from
  somewhere other than the auto-updater path (the launcher script, a
  fresh install). The signing scope is "updates to a running install",
  not "first-install verification". For first-install, users still rely
  on the GitHub repo identity and the HTTPS path.
- A compromise of *the offline machine where you keep the secret key*.
  Treat that key like an offline crypto wallet seed phrase.
