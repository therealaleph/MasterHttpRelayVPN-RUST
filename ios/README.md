# MhrvVPN — iOS

Full-tunnel VPN client. The Network Extension (`MhrvTunnel`) links the Rust core
(`libmhrv_rs.a`) and runs leaf (TUN/FakeIP) → SOCKS5 → mhrv-rs relay.

## Prerequisites

- Xcode (full install, not just Command Line Tools).
- Rust + iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`
- `xcodegen` (`brew install xcodegen`).
- An Apple Developer account in the team that owns the App ID / App Group.

## Signing setup (one-time)

The signing team lives in a local, gitignored `Local.xcconfig` so no team ID is
ever committed. Create it from the template and set your Apple Developer team:

```sh
cd ios
cp Local.xcconfig.example Local.xcconfig
# edit Local.xcconfig: DEVELOPMENT_TEAM = <your 10-char team ID>
```

`xcodegen generate` reads it. (The generated `MhrvVPN.xcodeproj` and `build/`
are also gitignored.)

## Build & run (device)

```sh
cd ios
xcodegen generate          # regenerate MhrvVPN.xcodeproj after editing project.yml
open MhrvVPN.xcodeproj
```

Then in Xcode: select the **MhrvVPN** scheme + your device, and **Product → Run** (⌘R).

The Rust static lib is built automatically by the **"Build Rust static lib"**
pre-build script. It uses:

```sh
cargo rustc --profile release-ios --target aarch64-apple-ios --lib --crate-type staticlib
```

> Important: do **not** switch this back to `cargo build --lib`. The crate is
> `crate-type = ["cdylib","rlib","staticlib"]`, and `cargo build` also links the
> cdylib, which fails on iOS (`Undefined symbols: ___chkstk_darwin`). That makes
> the whole build fail and silently leaves a stale `.a`, so device builds never
> pick up Rust changes. `cargo rustc --crate-type staticlib` builds only the
> `.a` (no link step) — the symbol resolves when Xcode links the extension.

To verify a freshly built lib contains your change:

```sh
strings target/aarch64-apple-ios/release-ios/libmhrv_rs.a | grep "<some string from your edit>"
```

## Versioning

The app version comes from `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in
`project.yml` (Info.plist references `$(MARKETING_VERSION)` / `$(CURRENT_PROJECT_VERSION)`).
Keep `MARKETING_VERSION` in sync with the crate version in `Cargo.toml`. After
changing it, run `xcodegen generate`.

## Building a separate copy (own bundle ID)

The committed bundle ID `com.therealaleph.mhrv` is reserved for the main release.
A bundle ID is globally unique across all of Apple, so if you want to ship your
own build (e.g. a personal TestFlight build that installs **alongside** the main
app without claiming its ID), append a unique suffix of your choice — shown below
as `<suffix>` (e.g. your initials) — to the IDs **locally**. Do **not** commit this.

1. `ios/project.yml` — app target:
   `PRODUCT_BUNDLE_IDENTIFIER: com.therealaleph.mhrv` → `com.therealaleph.mhrv.<suffix>`
2. `ios/project.yml` — `MhrvTunnel` target (the extension ID **must** stay a child
   of the app ID):
   `com.therealaleph.mhrv.tunnel` → `com.therealaleph.mhrv.<suffix>.tunnel`
3. `ios/App/ContentView.swift` — `VpnManager.tunnelId` must equal the extension ID:
   `"com.therealaleph.mhrv.tunnel"` → `"com.therealaleph.mhrv.<suffix>.tunnel"`
4. (Optional, for a fully independent data container) change the App Group in both
   `*.entitlements` and the `groupId` strings in `ContentView.swift` /
   `PacketTunnelProvider.swift` to `group.com.therealaleph.mhrv.<suffix>`.
5. `cd ios && xcodegen generate`, then create the App Store Connect record for the
   new bundle ID.

Keep these edits out of any PR to the main repo.

## Publishing to TestFlight

1. **Bump the version.** Edit `MARKETING_VERSION` (and bump `CURRENT_PROJECT_VERSION`,
   which must be unique per upload) in `project.yml`, then `xcodegen generate`.

2. **App Store Connect setup (one-time).**
   - Create the app record at https://appstoreconnect.apple.com with bundle id
     `com.therealaleph.mhrv`.
   - In the Apple Developer portal, ensure the App ID and the extension App ID
     (`com.therealaleph.mhrv.tunnel`) have the **Network Extensions** and
     **App Groups** (`group.com.therealaleph.mhrv`) capabilities, and that the
     App Group is enabled for both.
   - Network Extension on the App Store requires the **Packet Tunnel** capability;
     make sure the distribution provisioning profiles include it.

3. **Signing.** In Xcode → target → Signing & Capabilities, select your Apple
   Developer team for both **MhrvVPN** and **MhrvTunnel**. Automatic signing is
   fine; otherwise use App Store distribution profiles for both.

4. **Archive.** Select **Any iOS Device (arm64)** as the run destination
   (not a simulator), then **Product → Archive**. The pre-build script builds the
   device `aarch64-apple-ios` static lib.

5. **Upload.** In the Organizer window that opens: **Distribute App → App Store
   Connect → Upload**. (Alternatively export the `.ipa` and upload with
   Transporter.) Let Xcode manage signing or pick the distribution profiles.

6. **TestFlight.** After upload, the build appears in App Store Connect →
   TestFlight after processing (a few minutes). Complete the **export compliance**
   prompt (this app uses standard TLS/HTTPS encryption). Add internal testers
   (immediate) or external testers (requires a short Beta App Review).

### Troubleshooting

- **Archive missing the Rust lib / link errors:** confirm the pre-build script ran
  and produced `ios/build/<Config>/libmhrv_rs.a`. Re-run `xcodegen generate` if the
  script is missing from the target.
- **"stale" behaviour (code changes not taking effect):** you're likely linking an
  old `.a` because `cargo build` failed. Use the `cargo rustc --crate-type staticlib`
  command above and check the pre-build log for errors.
