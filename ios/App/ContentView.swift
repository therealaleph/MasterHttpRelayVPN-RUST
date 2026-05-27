import SwiftUI
import NetworkExtension
import UniformTypeIdentifiers
import Compression
import Network

/// Per-SNI probe result for the SNI pool tester.
enum SniProbeState: Equatable {
    case idle
    case inFlight
    case ok(Int)   // handshake latency in ms
    case err
}

/// Default SNI rotation pool — mirrors Android's DEFAULT_SNI_POOL and the Rust
/// DEFAULT_GOOGLE_SNI_POOL. Empty sniHosts in config = let Rust auto-expand these.
let DEFAULT_SNI_POOL: [String] = [
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    "accounts.google.com",
    "scholar.google.com",
    "maps.google.com",
    "chat.google.com",
    "translate.google.com",
    "play.google.com",
    "lens.google.com",
    "chromewebstore.google.com",
]

// MARK: — Config model

/// Structured VPN config — mirrors Android's MhrvConfig / ConfigStore JSON format.
/// The extension accepts both JSON (Android) and TOML; iOS generates JSON for export.
struct VpnConfig {
    var mode: String = "full"             // full only in UI for now (apps_script | direct | full)
    var scriptIds: [String] = []          // bare deployment IDs
    var authKey: String = ""
    var listenHost: String = "127.0.0.1"
    var listenPort: Int = 8085
    var socks5Port: Int = 8086
    var googleIp: String = "216.239.38.120"
    var frontDomain: String = "www.google.com"
    var sniHosts: [String] = []           // SNI rotation pool; empty = Rust auto-expands defaults
    var logLevel: String = "warn"
    var verifySsl: Bool = true
    var blockQuic: Bool = true
    var blockStun: Bool = true
    var blockDoh: Bool = true
    var tunnelDoh: Bool = true
    var coalesceStepMs: Int = 10          // full-mode batch coalescing
    var coalesceMaxMs: Int = 1000

    // MARK: serialise

    /// Android-compatible JSON for sharing and for the extension.
    func toJson(pretty: Bool = true) -> String {
        var obj: [String: Any] = [
            "mode": mode,
            "listen_host": listenHost,
            "listen_port": listenPort,
            "socks5_port": socks5Port,
            "auth_key": authKey,
            "google_ip": googleIp,
            "front_domain": frontDomain,
            "log_level": logLevel,
            "verify_ssl": verifySsl,
            "block_quic": blockQuic,
            "block_stun": blockStun,
            "block_doh": blockDoh,
            "tunnel_doh": tunnelDoh,
            "coalesce_step_ms": coalesceStepMs,
            "coalesce_max_ms": coalesceMaxMs,
            "fetch_ips_from_api": false,
            "max_ips_to_scan": 20,
            "scan_batch_size": 100,
        ]
        let ids = scriptIds.map { Self.extractId($0) }.filter { !$0.isEmpty }
        obj["script_ids"] = ids
        // Only emit sni_hosts when non-empty (matches Android; empty lets Rust auto-expand).
        let sni = sniHosts.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        if !sni.isEmpty { obj["sni_hosts"] = sni }
        let opts: JSONSerialization.WritingOptions = pretty ? .prettyPrinted : []
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: opts),
              let str = String(data: data, encoding: .utf8) else { return "{}" }
        return str
    }

    /// Android-compatible share string: `mhrv-rs://` + URL-safe base64 of the
    /// zlib-compressed (RFC 1950) JSON — byte-for-byte decodable by Android's
    /// ConfigStore.decode (InflaterInputStream). Falls back to uncompressed
    /// base64 if compression fails (still decodable by both sides).
    func encode() -> String {
        let json = toJson(pretty: false)
        let bytes = Data(json.utf8)
        let payload = Self.zlibDeflate(bytes) ?? bytes
        return "mhrv-rs://" + Self.urlSafeBase64(payload)
    }

    private static func urlSafeBase64(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    // MARK: parse

    /// Try to parse raw text — mhrv-rs:// (Android share), JSON, or TOML.
    static func from(configText: String) -> VpnConfig? {
        let t = configText.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("mhrv-rs://") { return fromMhrvEncoded(t) }
        if t.hasPrefix("{") { return fromJson(t) }
        return fromToml(t)
    }

    /// Decode Android's share format: mhrv-rs:// + URL-safe base64 + zlib-compressed JSON.
    private static func fromMhrvEncoded(_ text: String) -> VpnConfig? {
        let payload = String(text.dropFirst("mhrv-rs://".count))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        // URL-safe base64 → standard base64 with padding.
        var b64 = payload.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem != 0 { b64 += String(repeating: "=", count: 4 - rem) }
        // ignoreUnknownCharacters handles any stray whitespace/newlines in the clipboard.
        guard let raw = Data(base64Encoded: b64, options: .ignoreUnknownCharacters) else { return nil }
        // Prefer zlib-inflated JSON; fall back to raw UTF-8 (mirrors Android's
        // inflateOrRaw — handles uncompressed mhrv-rs:// payloads too).
        if let inflated = zlibInflate(raw),
           let json = String(data: inflated, encoding: .utf8),
           let cfg = fromJson(json) {
            return cfg
        }
        if let json = String(data: raw, encoding: .utf8) {
            return fromJson(json)
        }
        return nil
    }

    /// Decompress Java DeflaterOutputStream output (zlib / RFC 1950).
    /// Apple's COMPRESSION_ZLIB is actually raw DEFLATE (RFC 1951), so strip the
    /// 2-byte zlib header first; the raw decoder ignores the trailing Adler-32.
    private static func zlibInflate(_ data: Data) -> Data? {
        guard data.count > 6 else { return decompressOnce(data, COMPRESSION_ZLIB) }
        if let r = decompressOnce(data.dropFirst(2), COMPRESSION_ZLIB), !r.isEmpty { return r }
        // Fallback: maybe it was already raw DEFLATE with no zlib header.
        return decompressOnce(data, COMPRESSION_ZLIB)
    }

    private static func decompressOnce(_ data: Data, _ algo: compression_algorithm) -> Data? {
        guard !data.isEmpty else { return nil }
        let bufSize = 256 * 1024
        var outBuf = [UInt8](repeating: 0, count: bufSize)
        var written = 0
        data.withUnsafeBytes { (srcPtr: UnsafeRawBufferPointer) in
            guard let src = srcPtr.bindMemory(to: UInt8.self).baseAddress else { return }
            outBuf.withUnsafeMutableBufferPointer { dstPtr in
                written = compression_decode_buffer(
                    dstPtr.baseAddress!, bufSize,
                    src, srcPtr.count,
                    nil, algo
                )
            }
        }
        guard written > 0 else { return nil }
        return Data(outBuf.prefix(written))
    }

    /// Compress to zlib format (RFC 1950) so Android's InflaterInputStream reads
    /// it: 2-byte header + raw DEFLATE (Apple COMPRESSION_ZLIB) + 4-byte Adler-32.
    private static func zlibDeflate(_ data: Data) -> Data? {
        guard !data.isEmpty else { return nil }
        let cap = data.count + 4096
        var outBuf = [UInt8](repeating: 0, count: cap)
        var written = 0
        data.withUnsafeBytes { (srcPtr: UnsafeRawBufferPointer) in
            guard let src = srcPtr.bindMemory(to: UInt8.self).baseAddress else { return }
            outBuf.withUnsafeMutableBufferPointer { dstPtr in
                written = compression_encode_buffer(
                    dstPtr.baseAddress!, cap,
                    src, srcPtr.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard written > 0 else { return nil }
        var out = Data([0x78, 0x9C])                 // zlib header: deflate, default level
        out.append(contentsOf: outBuf[0..<written])  // raw DEFLATE body
        var adler = adler32(data).bigEndian          // Adler-32 over uncompressed bytes, MSB first
        withUnsafeBytes(of: &adler) { out.append(contentsOf: $0) }
        return out
    }

    private static func adler32(_ data: Data) -> UInt32 {
        var a: UInt32 = 1, b: UInt32 = 0
        let mod: UInt32 = 65521
        for byte in data {
            a = (a + UInt32(byte)) % mod
            b = (b + a) % mod
        }
        return (b << 16) | a
    }

    static func fromJson(_ json: String) -> VpnConfig? {
        guard let data = json.data(using: .utf8),
              let obj  = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        var cfg = VpnConfig()
        if let v = obj["mode"]         as? String  { cfg.mode        = v }
        if let v = obj["listen_host"]  as? String  { cfg.listenHost  = v }
        if let v = obj["listen_port"]  as? Int     { cfg.listenPort  = v }
        if let v = obj["socks5_port"]  as? Int     { cfg.socks5Port  = v }
        if let v = obj["auth_key"]     as? String  { cfg.authKey     = v }
        if let v = obj["google_ip"]    as? String  { cfg.googleIp    = v }
        if let v = obj["front_domain"] as? String  { cfg.frontDomain = v }
        if let v = obj["log_level"]    as? String  { cfg.logLevel    = v }
        if let v = obj["verify_ssl"]   as? Bool    { cfg.verifySsl   = v }
        if let v = obj["block_quic"]   as? Bool    { cfg.blockQuic   = v }
        if let v = obj["block_stun"]   as? Bool    { cfg.blockStun   = v }
        if let v = obj["block_doh"]    as? Bool    { cfg.blockDoh    = v }
        if let v = obj["tunnel_doh"]   as? Bool    { cfg.tunnelDoh   = v }
        if let v = obj["coalesce_step_ms"] as? Int { cfg.coalesceStepMs = v }
        if let v = obj["coalesce_max_ms"]  as? Int { cfg.coalesceMaxMs  = v }
        // script_ids: array or single string (both Android formats)
        if let arr = obj["script_ids"] as? [String] {
            cfg.scriptIds = arr.map { extractId($0) }.filter { !$0.isEmpty }
        } else if let arr = obj["script_ids"] as? [Any] {
            cfg.scriptIds = arr.compactMap { $0 as? String }.map { extractId($0) }.filter { !$0.isEmpty }
        } else if let s = obj["script_id"] as? String {
            let id = extractId(s); if !id.isEmpty { cfg.scriptIds = [id] }
        }
        if let arr = obj["sni_hosts"] as? [Any] {
            cfg.sniHosts = arr.compactMap { $0 as? String }
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return cfg
    }

    /// Minimal TOML parser for the fields we care about (no full parser needed).
    static func fromToml(_ toml: String) -> VpnConfig? {
        var cfg = VpnConfig()
        var section = ""
        var found = false
        for raw in toml.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") {
                section = line
                continue
            }
            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let raw = parts[1].trimmingCharacters(in: .whitespaces)
            let val = raw.hasPrefix("\"") && raw.hasSuffix("\"")
                ? String(raw.dropFirst().dropLast()) : raw

            let inRelay   = section.contains("relay")
            let inNetwork = section.contains("network")
            let inLog     = section.contains("logging")
            let flat      = section.isEmpty

            if inRelay || flat {
                switch key {
                case "mode":      cfg.mode    = val; found = true
                case "auth_key":  cfg.authKey = val; found = true
                case "script_id":
                    // single value or inline array ["A","B"]
                    if val.hasPrefix("[") {
                        let ids = val.dropFirst().dropLast()
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .init(charactersIn: " \"")) }
                            .filter { !$0.isEmpty }
                        cfg.scriptIds = ids.map { extractId($0) }.filter { !$0.isEmpty }
                    } else {
                        let id = extractId(val); if !id.isEmpty { cfg.scriptIds = [id] }
                    }
                    found = true
                default: break
                }
            }
            if inNetwork || flat {
                switch key {
                case "google_ip":    cfg.googleIp    = val
                case "front_domain": cfg.frontDomain = val
                case "listen_host":  cfg.listenHost  = val
                case "listen_port":  cfg.listenPort  = Int(val) ?? cfg.listenPort
                case "socks5_port":  cfg.socks5Port  = Int(val) ?? cfg.socks5Port
                case "block_quic":   cfg.blockQuic   = val == "true"
                case "block_stun":   cfg.blockStun   = val == "true"
                case "block_doh":    cfg.blockDoh    = val == "true"
                case "tunnel_doh":   cfg.tunnelDoh   = val == "true"
                case "verify_ssl":   cfg.verifySsl   = val == "true"
                default: break
                }
            }
            if inLog || flat {
                if key == "log_level" { cfg.logLevel = val }
            }
        }
        return found ? cfg : nil
    }

    /// Extract bare deployment ID from either a full URL or bare ID.
    static func extractId(_ input: String) -> String {
        var s = input.trimmingCharacters(in: .whitespaces)
        if s.isEmpty { return s }
        let marker = "/macros/s/"
        if let r = s.range(of: marker) { s = String(s[r.upperBound...]) }
        if let i = s.firstIndex(of: "/") { s = String(s[..<i]) }
        if let i = s.firstIndex(of: "?") { s = String(s[..<i]) }
        return s.trimmingCharacters(in: .whitespaces)
    }

    var hasConfig: Bool {
        mode == "direct" || (!scriptIds.isEmpty && !authKey.isEmpty)
    }
}

// MARK: — Root view

struct ContentView: View {
    @StateObject private var vpn = VpnManager()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    ConfigSharingBar(vpn: vpn)

                    ConnectButton(vpn: vpn)

                    RelaySection(vpn: vpn)

                    NetworkSection(vpn: vpn)

                    SniPoolSection(vpn: vpn)

                    AdvancedSection(vpn: vpn)

                    LogsSection(vpn: vpn)

                    Spacer(minLength: 16)
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }
            // Dismiss the keyboard on a tap in empty space or on scroll.
            // Interactive controls consume their own taps, so fields/buttons
            // still work — only non-control taps fall through to here.
            .scrollDismissesKeyboard(.interactively)
            .onTapGesture { UIApplication.shared.endEditing() }
            .navigationTitle("mhrv-rs")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Text("v\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .onAppear { vpn.load() }
            .onOpenURL { vpn.handleImport(url: $0) }
            .alert("Config Imported", isPresented: $vpn.importedAlert) {
                Button("OK") {}
            } message: {
                Text("Config loaded. Reconnect to apply.")
            }
            .alert("Import Failed", isPresented: $vpn.importErrorAlert) {
                Button("OK") {}
            } message: {
                Text(vpn.importError)
            }
        }
    }
}

// MARK: — Config sharing bar

private struct ConfigSharingBar: View {
    @ObservedObject var vpn: VpnManager
    @State private var showShareSheet = false

    var body: some View {
        HStack(spacing: 10) {
            Button {
                if let s = UIPasteboard.general.string, !s.isEmpty {
                    vpn.applyConfigText(s)
                }
            } label: {
                Label("Paste Config", systemImage: "doc.on.clipboard")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)

            Button {
                showShareSheet = true
            } label: {
                Label("Share", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.bordered)
            .sheet(isPresented: $showShareSheet) {
                ShareSheet(items: [vpn.config.encode()])
            }
        }
    }
}

// MARK: — Connect / Disconnect button

private struct ConnectButton: View {
    @ObservedObject var vpn: VpnManager

    var body: some View {
        VStack(spacing: 6) {
            // Status row
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                Text(vpn.statusLabel)
                    .font(.subheadline)
                Spacer()
                if let cp = vpn.lastCheckpoint, !cp.isEmpty {
                    Text(cp)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Button {
                vpn.toggle()
            } label: {
                Text(vpn.isConnected ? "Disconnect" : "Connect")
                    .frame(maxWidth: .infinity)
                    .font(.headline)
            }
            .buttonStyle(.borderedProminent)
            .tint(vpn.isConnected ? .red : .green)
            .disabled(!vpn.config.hasConfig && !vpn.isConnected)
            .controlSize(.large)
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var statusColor: Color {
        switch vpn.statusLabel {
        case "Connected": return .green
        case "Connecting…", "Reconnecting…": return .orange
        default: return .red
        }
    }
}

// MARK: — Apps Script Relay section

private struct RelaySection: View {
    @ObservedObject var vpn: VpnManager
    @State private var newId = ""
    @State private var showAuthKey = false

    var body: some View {
        CollapsibleCard(title: "Apps Script Relay", expanded: true) {
            VStack(alignment: .leading, spacing: 14) {
                // Deployment IDs list
                VStack(alignment: .leading, spacing: 8) {
                    Text("Deployment IDs")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    ForEach(Array(vpn.config.scriptIds.enumerated()), id: \.offset) { idx, _ in
                        HStack {
                            TextField("#\(idx + 1)", text: Binding(
                                // Guard the index: after a delete, SwiftUI may
                                // re-evaluate a removed row's binding before the
                                // list updates — a stale index would crash.
                                get: { idx < vpn.config.scriptIds.count ? vpn.config.scriptIds[idx] : "" },
                                // Normalize on edit so a pasted full URL collapses
                                // to the bare deployment ID (no prefix sticks).
                                set: {
                                    guard idx < vpn.config.scriptIds.count else { return }
                                    vpn.config.scriptIds[idx] = VpnConfig.extractId($0); vpn.save()
                                }
                            ))
                            .font(.system(.caption, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            Button {
                                guard idx < vpn.config.scriptIds.count else { return }
                                vpn.config.scriptIds.remove(at: idx); vpn.save()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.red)
                            }
                        }
                    }

                    // Add row — give it breathing room from the list above.
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Paste deployment ID or URL", text: $newId, axis: .vertical)
                            .font(.caption)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(1...4)
                            .padding(8)
                            .background(Color(.systemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        Button {
                            addIds()
                        } label: {
                            Label("Add ID", systemImage: "plus.circle.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(newId.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                    .padding(.top, 4)
                }

                Divider()

                // Auth key — eye toggle to reveal/verify the value.
                LabeledField(label: "Auth Key") {
                    HStack {
                        let binding = Binding(
                            get: { vpn.config.authKey },
                            set: { vpn.config.authKey = $0; vpn.save() }
                        )
                        Group {
                            if showAuthKey {
                                TextField("Required", text: binding)
                            } else {
                                SecureField("Required", text: binding)
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        Button { showAuthKey.toggle() } label: {
                            Image(systemName: showAuthKey ? "eye.slash" : "eye")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func addIds() {
        // Accept multiple IDs separated by whitespace, newlines, or commas.
        let ids = newId
            .components(separatedBy: CharacterSet(charactersIn: " \n\t,"))
            .map { VpnConfig.extractId($0) }
            .filter { !$0.isEmpty }
        guard !ids.isEmpty else { return }
        for id in ids where !vpn.config.scriptIds.contains(id) {
            vpn.config.scriptIds.append(id)
        }
        vpn.save()
        newId = ""
    }
}

// MARK: — Network section

private struct NetworkSection: View {
    @ObservedObject var vpn: VpnManager

    var body: some View {
        CollapsibleCard(title: "Network", expanded: false) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    LabeledField(label: "Google IP") {
                        TextField("216.239.38.120", text: Binding(
                            get: { vpn.config.googleIp },
                            set: { vpn.config.googleIp = $0; vpn.save() }
                        ))
                        .keyboardType(.asciiCapable)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                    LabeledField(label: "Front Domain") {
                        TextField("www.google.com", text: Binding(
                            get: { vpn.config.frontDomain },
                            set: { vpn.config.frontDomain = $0; vpn.save() }
                        ))
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                }

                // Auto-detect the current Google edge IP by resolving the front
                // domain (mirrors Android's NetworkDetect.resolveGoogleIp).
                Button {
                    vpn.autoDetectGoogleIp()
                } label: {
                    HStack(spacing: 6) {
                        if vpn.detectingIp {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "antenna.radiowaves.left.and.right")
                        }
                        Text(vpn.detectingIp ? "Detecting…" : "Auto-detect Google IP")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(vpn.detectingIp)

                if let msg = vpn.detectIpMessage {
                    Text(msg).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: — SNI pool section

private struct SniPoolSection: View {
    @ObservedObject var vpn: VpnManager
    @State private var custom = ""

    // Displayed = front domain + defaults + custom hosts, deduped, in order.
    private var displayed: [String] {
        var seen: [String] = []
        let fd = vpn.config.frontDomain.trimmingCharacters(in: .whitespaces)
        if !fd.isEmpty { seen.append(fd) }
        for h in DEFAULT_SNI_POOL where !seen.contains(h) { seen.append(h) }
        for h in vpn.config.sniHosts where !h.isEmpty && !seen.contains(h) { seen.append(h) }
        return seen
    }

    // A host is enabled if it's in sniHosts; empty sniHosts = all defaults + front domain.
    private var enabledSet: Set<String> {
        if !vpn.config.sniHosts.isEmpty { return Set(vpn.config.sniHosts) }
        var s = Set(DEFAULT_SNI_POOL)
        let fd = vpn.config.frontDomain.trimmingCharacters(in: .whitespaces)
        if !fd.isEmpty { s.insert(fd) }
        return s
    }

    var body: some View {
        CollapsibleCard(title: "SNI Pool", expanded: false) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Hostnames rotated as TLS SNI for domain fronting. Leave all enabled to let the engine pick; disable any that your network blocks.")
                    .font(.caption).foregroundStyle(.secondary)

                ForEach(displayed, id: \.self) { sni in
                    HStack(spacing: 8) {
                        Text(sni).font(.system(.caption, design: .monospaced))
                        Spacer()
                        probeView(sni)
                        Toggle("", isOn: Binding(
                            get: { enabledSet.contains(sni) },
                            set: { on in toggle(sni, on: on) }
                        ))
                        .labelsHidden()
                    }
                }

                Button {
                    for sni in displayed { vpn.testSni(sni) }
                } label: {
                    Label("Test all", systemImage: "bolt.horizontal")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .font(.caption)

                Divider()

                VStack(alignment: .leading, spacing: 8) {
                    TextField("Add custom SNI host(s)", text: $custom, axis: .vertical)
                        .font(.caption)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .lineLimit(1...4)
                        .padding(8)
                        .background(Color(.systemGroupedBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    Button {
                        addCustom()
                    } label: {
                        Label("Add SNI", systemImage: "plus.circle.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(custom.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }

    @ViewBuilder
    private func probeView(_ sni: String) -> some View {
        switch vpn.sniProbe[sni] ?? .idle {
        case .idle:
            Button { vpn.testSni(sni) } label: {
                Image(systemName: "bolt.horizontal").foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        case .inFlight:
            ProgressView().controlSize(.small)
        case .ok(let ms):
            Button { vpn.testSni(sni) } label: {
                HStack(spacing: 3) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text("\(ms)ms").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)
        case .err:
            Button { vpn.testSni(sni) } label: {
                Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            }
            .buttonStyle(.plain)
        }
    }

    private func toggle(_ sni: String, on: Bool) {
        // Materialize the full enabled set first (empty sniHosts means "all defaults").
        var current = vpn.config.sniHosts.isEmpty ? Array(enabledSet) : vpn.config.sniHosts
        if on {
            if !current.contains(sni) { current.append(sni) }
        } else {
            current.removeAll { $0 == sni }
        }
        vpn.config.sniHosts = current
        vpn.save()
    }

    private func addCustom() {
        let tokens = custom
            .components(separatedBy: CharacterSet(charactersIn: " \n\t,;"))
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !tokens.isEmpty else { return }
        var base = vpn.config.sniHosts.isEmpty ? Array(enabledSet) : vpn.config.sniHosts
        for t in tokens where !base.contains(t) { base.append(t) }
        vpn.config.sniHosts = base
        vpn.save()
        custom = ""
    }
}

// MARK: — Advanced section

private struct AdvancedSection: View {
    @ObservedObject var vpn: VpnManager

    private let logLevels = ["trace", "debug", "info", "warn", "error", "off"]

    var body: some View {
        CollapsibleCard(title: "Advanced", expanded: false) {
            VStack(alignment: .leading, spacing: 12) {
                // Mode — locked to Full tunnel for now (other modes land in a later PR).
                VStack(alignment: .leading, spacing: 4) {
                    Text("Mode").font(.subheadline).foregroundStyle(.secondary)
                    HStack {
                        Text("Full tunnel").font(.body)
                        Spacer()
                        Text("locked").font(.caption2).foregroundStyle(.secondary)
                    }
                    Text("All traffic tunneled through Apps Script + remote node. No cert needed. Other modes coming soon.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Divider()

                // Log level
                VStack(alignment: .leading, spacing: 4) {
                    Text("Log Level").font(.subheadline).foregroundStyle(.secondary)
                    Picker("Log Level", selection: Binding(
                        get: { vpn.config.logLevel },
                        set: { vpn.config.logLevel = $0; vpn.save() }
                    )) {
                        ForEach(logLevels, id: \.self) { Text($0) }
                    }
                    .pickerStyle(.segmented)
                }

                Divider()

                // Toggles
                Toggle("Block QUIC (UDP/443)", isOn: Binding(
                    get: { vpn.config.blockQuic },
                    set: { vpn.config.blockQuic = $0; vpn.save() }
                ))
                Text("Drops QUIC so browsers fall back to HTTPS/TCP — prevents TCP-over-UDP meltdown.")
                    .font(.caption).foregroundStyle(.secondary)

                Divider()
                Toggle("Block STUN/TURN", isOn: Binding(
                    get: { vpn.config.blockStun },
                    set: { vpn.config.blockStun = $0; vpn.save() }
                ))
                Text("Drops STUN/TURN (3478/5349/19302) so WebRTC falls back to TCP.")
                    .font(.caption).foregroundStyle(.secondary)

                Divider()
                Toggle("Block DoH", isOn: Binding(
                    get: { vpn.config.blockDoh },
                    set: { vpn.config.blockDoh = $0; vpn.save() }
                ))
                Text("Reject browser DoH — forces system DNS via leaf FakeIP (instant, no relay round-trip).")
                    .font(.caption).foregroundStyle(.secondary)

                Divider()
                Toggle("Verify TLS", isOn: Binding(
                    get: { vpn.config.verifySsl },
                    set: { vpn.config.verifySsl = $0; vpn.save() }
                ))

                Divider()

                // Full-mode batch coalescing.
                VStack(alignment: .leading, spacing: 4) {
                    Text("Batch Coalescing").font(.subheadline).foregroundStyle(.secondary)
                    HStack(spacing: 10) {
                        LabeledField(label: "Window (ms)") {
                            TextField("10", value: Binding(
                                get: { vpn.config.coalesceStepMs },
                                set: { vpn.config.coalesceStepMs = max(0, $0); vpn.save() }
                            ), format: .number)
                            .keyboardType(.numberPad)
                        }
                        LabeledField(label: "Max (ms)") {
                            TextField("1000", value: Binding(
                                get: { vpn.config.coalesceMaxMs },
                                set: { vpn.config.coalesceMaxMs = max(0, $0); vpn.save() }
                            ), format: .number)
                            .keyboardType(.numberPad)
                        }
                    }
                    Text("How long the tunnel waits to batch outbound requests to Apps Script. Lower = snappier; higher = fewer round-trips (better throughput). 0 = compiled default.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: — Live logs section

private struct LogsSection: View {
    @ObservedObject var vpn: VpnManager
    @State private var expanded = false

    var body: some View {
        CollapsibleCard(title: "Logs", expanded: false) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("\(vpn.logs.isEmpty ? 0 : vpn.logs.components(separatedBy: "\n").count) lines")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Copy") {
                        UIPasteboard.general.string = vpn.logs
                    }
                    .font(.caption)
                    .disabled(vpn.logs.isEmpty)
                    Button("Clear") { vpn.logs = "" }
                        .font(.caption)
                }
                if let cp = vpn.lastCheckpoint {
                    Text("Checkpoint: \(cp)").font(.caption2).foregroundStyle(.secondary)
                }
                ScrollView {
                    Text(vpn.logs.isEmpty ? "(no logs yet)" : vpn.logs)
                        .font(.system(.caption2, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 240)
                .background(Color(.systemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
    }
}

// MARK: — Shared UI helpers

private struct CollapsibleCard<Content: View>: View {
    let title: String
    let expanded: Bool
    @ViewBuilder let content: () -> Content
    @State private var open: Bool

    init(title: String, expanded: Bool, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.expanded = expanded
        self.content = content
        self._open = State(initialValue: expanded)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { open.toggle() }
            } label: {
                HStack {
                    Text(title).font(.headline)
                    Spacer()
                    Image(systemName: open ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding()

            if open {
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    content()
                }
                .padding()
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

private struct LabeledField<Content: View>: View {
    let label: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content()
                .padding(8)
                .background(Color(.systemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// UIActivityViewController wrapper for the share sheet.
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

// MARK: — VPN Manager

@MainActor
class VpnManager: ObservableObject {
    @Published var isConnected = false
    @Published var statusLabel = "Not connected"
    @Published var logs = ""
    @Published var importedAlert = false
    @Published var importErrorAlert = false
    @Published var importError = ""
    @Published var lastCheckpoint: String?
    @Published var detectingIp = false
    @Published var detectIpMessage: String?
    @Published var sniProbe: [String: SniProbeState] = [:]

    /// Structured config — source of truth for the UI.
    @Published var config = VpnConfig()

    private let groupId  = "group.com.therealaleph.mhrv"
    private let tunnelId = "com.therealaleph.mhrv.tunnel"
    private var manager: NETunnelProviderManager?
    private var statusObserver: Any?
    private var logTimer: Timer?
    private var checkpointTimer: Timer?

    // MARK: lifecycle

    func load() {
        let ud = UserDefaults(suiteName: groupId)
        // Try loading structured JSON first; fall back to raw text.
        if let raw = ud?.string(forKey: "mhrv_config"), !raw.isEmpty {
            config = VpnConfig.from(configText: raw) ?? defaultConfig()
        } else {
            config = defaultConfig()
        }
        // The UI only supports full-tunnel mode right now; other modes ship later.
        config.mode = "full"
        save()
        startLogPolling()
        startCheckpointPolling()
        loadManager()
    }

    func save() {
        let json = config.toJson()
        UserDefaults(suiteName: groupId)?.set(json, forKey: "mhrv_config")
    }

    func toggle() {
        isConnected ? disconnect() : connect()
    }

    // MARK: Google IP auto-detect

    /// Resolve the front domain to its current IPv4 edge and store it as
    /// google_ip — mirrors Android's NetworkDetect.resolveGoogleIp. Runs before
    /// the tunnel is up so the system resolver is used.
    func autoDetectGoogleIp() {
        let host = config.frontDomain.isEmpty ? "www.google.com" : config.frontDomain
        detectingIp = true
        detectIpMessage = nil
        Task.detached {
            let ip = Self.resolveIPv4(host)
            await MainActor.run {
                self.detectingIp = false
                if let ip {
                    self.config.googleIp = ip
                    self.save()
                    self.detectIpMessage = "Set Google IP to \(ip) (from \(host))."
                } else {
                    self.detectIpMessage = "Couldn't resolve \(host). Check connectivity and try again."
                }
            }
        }
    }

    // MARK: SNI probe

    /// Probe one SNI host by completing a TLS handshake to the configured Google
    /// edge IP with that SNI, measuring latency. Cert trust is bypassed — this
    /// measures DPI passability + reachability, not certificate validity.
    func testSni(_ host: String) {
        let ip = config.googleIp.trimmingCharacters(in: .whitespaces)
        guard !ip.isEmpty else { sniProbe[host] = .err; return }
        sniProbe[host] = .inFlight

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in
            complete(true)  // accept any cert — we only care that the handshake completes
        }, DispatchQueue.global())

        let params = NWParameters(tls: tls)
        let conn = NWConnection(host: NWEndpoint.Host(ip), port: 443, using: params)
        let start = Date()
        var finished = false
        let finish: (SniProbeState) -> Void = { [weak self] state in
            if finished { return }
            finished = true
            conn.cancel()
            Task { @MainActor in self?.sniProbe[host] = state }
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready: finish(.ok(Int(Date().timeIntervalSince(start) * 1000)))
            case .failed, .cancelled: finish(.err)
            default: break
            }
        }
        conn.start(queue: .global())
        DispatchQueue.global().asyncAfter(deadline: .now() + 6) { finish(.err) }
    }

    /// Blocking DNS resolution to the first IPv4 address. Call off the main actor.
    nonisolated private static func resolveIPv4(_ host: String) -> String? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(result) }
        var node = Optional(first)
        while let n = node {
            if let sa = n.pointee.ai_addr {
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var addr = sin.sin_addr
                if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buf)
                }
            }
            node = n.pointee.ai_next
        }
        return nil
    }

    // MARK: import

    /// Accept raw text from clipboard or deep link — mhrv-rs://, JSON, or TOML.
    func applyConfigText(_ text: String) {
        let cleaned = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else {
            showImportError("Clipboard is empty.")
            return
        }
        guard let parsed = VpnConfig.from(configText: cleaned) else {
            showImportError("Unrecognised config format.\nExpected JSON, TOML, or a mhrv-rs:// share link.")
            return
        }
        config = parsed
        save()
        importedAlert = true
    }

    /// Handle deep links:
    ///   mhrvvpn://import?config=<base64>
    ///   mhrvvpn://import?url=<remote-url>
    func handleImport(url: URL) {
        guard url.scheme?.lowercased() == "mhrvvpn",
              url.host?.lowercased()   == "import" else { return }

        let params = Dictionary(
            uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems ?? []).compactMap { item in
                item.value.map { (item.name, $0) }
            }
        )

        if let b64 = params["config"] {
            guard let data = Data(base64Encoded: b64, options: .ignoreUnknownCharacters),
                  let text = String(data: data, encoding: .utf8) else {
                showImportError("Invalid base64 payload.")
                return
            }
            applyConfigText(text)
        } else if let rawUrl = params["url"], let fetchUrl = URL(string: rawUrl) {
            Task {
                do {
                    let (data, _) = try await URLSession.shared.data(from: fetchUrl)
                    guard let text = String(data: data, encoding: .utf8) else {
                        await MainActor.run { self.showImportError("Config is not valid UTF-8.") }
                        return
                    }
                    await MainActor.run { self.applyConfigText(text) }
                } catch {
                    await MainActor.run { self.showImportError(error.localizedDescription) }
                }
            }
        } else {
            showImportError("Missing 'config' or 'url' parameter.")
        }
    }

    private func showImportError(_ msg: String) {
        importError = msg
        importErrorAlert = true
    }

    // MARK: private — tunnel management

    private func loadManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            guard let self else { return }
            if let existing = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == self.tunnelId
            }) {
                self.manager = existing
            } else {
                self.manager = self.buildManager()
            }
            self.observeStatus()
            self.updateStatus()
        }
    }

    private func buildManager() -> NETunnelProviderManager {
        let m = NETunnelProviderManager()
        m.localizedDescription = "MhrvVPN"
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelId
        proto.serverAddress = "mhrv-relay"
        m.protocolConfiguration = proto
        m.isEnabled = true
        return m
    }

    private func connect() {
        guard let m = manager else { return }
        save()  // flush latest config to shared UserDefaults before starting
        let ud = UserDefaults(suiteName: groupId)
        ud?.synchronize()
        m.isEnabled = true
        m.saveToPreferences { [weak self] error in
            if let error {
                self?.statusLabel = "Save failed: \(error.localizedDescription)"
                return
            }
            do {
                try m.connection.startVPNTunnel()
            } catch {
                self?.statusLabel = "Start failed: \(error.localizedDescription)"
            }
        }
    }

    private func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager?.connection,
            queue: .main
        ) { [weak self] _ in self?.updateStatus() }
    }

    private func updateStatus() {
        let s = manager?.connection.status ?? .invalid
        isConnected = (s == .connected)
        statusLabel = s.displayName
    }

    // MARK: log polling

    private func startLogPolling() {
        let nc = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(nc, Unmanaged.passRetained(self).toOpaque(),
            { _, observer, _, _, _ in
                let mgr = Unmanaged<VpnManager>.fromOpaque(observer!).takeUnretainedValue()
                Task { @MainActor in mgr.pollLogs() }
            },
            "com.therealaleph.mhrv.newLogs" as CFString,
            nil, .deliverImmediately
        )
        pollLogs()
        // Fallback polling every 2 s in case Darwin notification is missed.
        logTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollLogs() }
        }
    }

    private func pollLogs() {
        let ud = UserDefaults(suiteName: groupId)
        if let fresh = ud?.string(forKey: "mhrv_logs"), !fresh.isEmpty {
            logs = fresh
        }
    }

    // Poll the tunnel_checkpoint key so the UI shows progress even before logs flush.
    private func startCheckpointPolling() {
        checkpointTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                let ud = UserDefaults(suiteName: self?.groupId ?? "")
                self?.lastCheckpoint = ud?.string(forKey: "tunnel_checkpoint")
            }
        }
    }

    // MARK: defaults

    private func defaultConfig() -> VpnConfig {
        VpnConfig()
    }
}

// MARK: — Helpers

extension UIApplication {
    /// Resign first responder on whatever is focused — hides the keyboard.
    func endEditing() {
        sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }
}

extension NEVPNStatus {
    var displayName: String {
        switch self {
        case .invalid:       return "Not configured"
        case .disconnected:  return "Disconnected"
        case .connecting:    return "Connecting…"
        case .connected:     return "Connected"
        case .reasserting:   return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        @unknown default:    return "Unknown"
        }
    }
}
