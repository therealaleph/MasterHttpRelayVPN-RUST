import NetworkExtension
import os.log

// PacketTunnelProvider — full-tunnel VPN using mhrv-rs + leaf/FakeIP.
//
// Traffic flow (full tunnel, all traffic):
//   App → NEPacketTunnelProvider (this class)
//     → leaf TUN inbound (FakeIP DNS: intercepts DNS, maps domains→198.18.x.x)
//     → leaf SOCKS5 outbound → mhrv-rs ProxyServer (loopback)
//     → mhrv-rs tunnel client (DPI bypass via domain fronting)
//     → Internet
//
// Build: cargo build --target aarch64-apple-ios --release
// Link:  libmhrv_rs.a in the NetworkExtension target's "Link Binary With Libraries"
// Bridge: add mhrv_rs.h to the bridging header (or module map)

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.therealaleph.mhrv", category: "tunnel")
    private var sessionId: UInt64 = 0
    private var logDrainTimer: Timer?

    // MARK: — Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("startTunnel called", log: log, type: .info)

        let groupId  = "group.com.therealaleph.mhrv"
        let defaults = UserDefaults(suiteName: groupId)

        // Checkpoint helper — survives an extension crash (written to
        // UserDefaults before each step so the host app can show "last step").
        func checkpoint(_ msg: String) {
            os_log("%{public}@", log: self.log, type: .info, msg)
            defaults?.set(msg, forKey: "tunnel_checkpoint")
            defaults?.synchronize()
        }

        // 1. Data dir — App Group container shared with the host app.
        checkpoint("step1: setting data dir")
        let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId)
        let dataDir  = groupURL?.path ?? NSTemporaryDirectory()
        mhrv_set_data_dir(dataDir)

        // 2. Config.
        checkpoint("step2: loading config")
        guard let configStr = defaults?.string(forKey: "mhrv_config"), !configStr.isEmpty else {
            checkpoint("ERROR: no mhrv_config in UserDefaults")
            completionHandler(TunnelError.missingConfig)
            return
        }
        checkpoint("step3: config loaded (\(configStr.count) bytes)")

        // 3. Network settings (full tunnel).
        let settings = buildNetworkSettings()
        checkpoint("step4: calling setTunnelNetworkSettings")

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.checkpoint("ERROR: setTunnelNetworkSettings: \(error.localizedDescription)", defaults: defaults)
                completionHandler(error)
                return
            }
            self.checkpoint("step5: network settings applied", defaults: defaults)

            // 4. Obtain the utun fd. KVC works on most iOS versions, but the
            //    keypath has broken on newer ones (returns nil), so fall back to
            //    scanning for the utun control socket — the WireGuard approach.
            guard let tunFd = self.resolveTunFd(defaults: defaults), tunFd >= 0 else {
                self.checkpoint("ERROR: could not resolve utun fd (KVC + scan failed)", defaults: defaults)
                completionHandler(TunnelError.noTunFd)
                return
            }
            os_log("utun fd = %d", log: self.log, type: .info, tunFd)

            // 5. Start mhrv-rs + leaf.
            self.checkpoint("step7: calling mhrv_start tunFd=\(tunFd)", defaults: defaults)
            let sid = mhrv_start(configStr, tunFd)
            self.checkpoint("step8: mhrv_start returned sid=\(sid)", defaults: defaults)
            guard sid != 0 else {
                // Drain logs immediately so the failure reason is visible.
                self.drainLogs()
                self.checkpoint("ERROR: mhrv_start returned 0", defaults: defaults)
                completionHandler(TunnelError.startFailed)
                return
            }
            self.sessionId = sid
            os_log("mhrv_start ok, session=%llu", log: self.log, type: .info, sid)

            // Drain any startup logs produced by Rust before the timer fires.
            self.drainLogs()

            // 6. Periodic log drain.
            self.startLogDrain()
            self.checkpoint("step9: tunnel running sid=\(sid)", defaults: defaults)
            completionHandler(nil)
        }
    }

    private func checkpoint(_ msg: String, defaults: UserDefaults?) {
        os_log("%{public}@", log: log, type: .info, msg)
        defaults?.set(msg, forKey: "tunnel_checkpoint")
        defaults?.synchronize()
    }

    // MARK: — utun fd resolution

    /// Resolve the utun file descriptor. Tries the KVC keypath first (works on
    /// most iOS versions); if that returns nil/garbage — as seen on newer iOS —
    /// falls back to scanning open fds for the utun control socket.
    private func resolveTunFd(defaults: UserDefaults?) -> Int32? {
        let rawFd = packetFlow.value(forKeyPath: "socket.fileDescriptor")
        checkpoint("step6: KVC rawFd=\(String(describing: rawFd))", defaults: defaults)
        if let n = rawFd as? NSNumber, n.int32Value >= 0 { return n.int32Value }
        if let i = rawFd as? Int32, i >= 0 { return i }
        let scanned = Self.findUtunFd()
        checkpoint("step6b: fd scan=\(String(describing: scanned))", defaults: defaults)
        return scanned
    }

    /// Scan open fds for the one backing a "utun*" interface and return it.
    /// Asks each fd for its utun interface name via getsockopt; non-utun and
    /// non-socket fds simply fail the call and are skipped. This is the approach
    /// WireGuard uses on iOS — it relies only on public symbols (the kernel
    /// control structs `sockaddr_ctl`/`ctl_info` are not exposed in the iOS SDK).
    private static func findUtunFd() -> Int32? {
        let sysprotoControl: Int32 = 2   // SYSPROTO_CONTROL (not public on iOS)
        let utunOptIfname: Int32 = 2     // UTUN_OPT_IFNAME (not public on iOS)
        var nameBuf = [CChar](repeating: 0, count: 256)
        for fd: Int32 in 0...1024 {
            var len = socklen_t(nameBuf.count)
            let ret = getsockopt(fd, sysprotoControl, utunOptIfname, &nameBuf, &len)
            if ret == 0, String(cString: nameBuf).hasPrefix("utun") {
                return fd
            }
        }
        return nil
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("stopTunnel reason=%d", log: log, type: .info, reason.rawValue)
        let ud = UserDefaults(suiteName: "group.com.therealaleph.mhrv")
        ud?.set("stopTunnel reason=\(reason.rawValue)", forKey: "tunnel_checkpoint")
        ud?.synchronize()
        logDrainTimer?.invalidate()
        logDrainTimer = nil
        // Final log drain so the host app can see what caused the stop.
        drainLogs()

        if sessionId != 0 {
            mhrv_stop(sessionId)
            sessionId = 0
        }
        completionHandler()
    }

    // MARK: — Network settings (full tunnel)

    private func buildNetworkSettings() -> NEPacketTunnelNetworkSettings {
        // Remote address is a dummy — actual traffic goes through loopback SOCKS5.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "240.0.0.1")

        // IPv4: TUN address in the FakeIP range leaf uses (198.18.0.1/15).
        // The /15 covers 198.18.0.0–198.19.255.255 — leaf's entire FakeIP pool.
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.254.0.0"])
        // Full tunnel: default route through the TUN interface.
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Exclude RFC-1918 ranges so local LAN traffic bypasses the tunnel.
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0",    subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0",  subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
        ]
        settings.ipv4Settings = ipv4

        // IPv6: minimal — exclude everything except loopback so IPv6 falls back
        // to IPv4 (the FakeIP pool is IPv4-only in leaf's current implementation).
        let ipv6 = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        ipv6.excludedRoutes = [
            NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
            NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),
            NEIPv6Route(destinationAddress: "::1",    networkPrefixLength: 128),
        ]
        settings.ipv6Settings = ipv6

        // DNS: point all queries at leaf's FakeIP DNS listener on the TUN address.
        // leaf intercepts these, returns fake 198.18.x.x IPs, and maps them back
        // to real hostnames when the TCP connection arrives — giving mhrv-rs the
        // domain name it needs for domain-fronting decisions.
        settings.dnsSettings = NEDNSSettings(servers: ["198.18.0.1"])

        settings.mtu = 1500
        return settings
    }

    // MARK: — Log drain

    private func startLogDrain() {
        logDrainTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.drainLogs()
        }
        RunLoop.main.add(logDrainTimer!, forMode: .common)
    }

    private func drainLogs() {
        guard let ptr = mhrv_drain_logs() else { return }
        defer { mhrv_free_string(ptr) }
        let s = String(cString: ptr)
        guard !s.isEmpty else { return }
        // Post to the host app via Darwin notifications so it can display them
        // in a live log panel without any IPC round-trip.
        let defaults = UserDefaults(suiteName: "group.com.therealaleph.mhrv")
        let existing = defaults?.string(forKey: "mhrv_logs") ?? ""
        let combined = existing.isEmpty ? s : existing + "\n" + s
        // Keep the stored log bounded to ~50 KB.
        let capped = combined.count > 50_000
            ? String(combined.suffix(50_000))
            : combined
        defaults?.set(capped, forKey: "mhrv_logs")
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.therealaleph.mhrv.newLogs" as CFString),
            nil, nil, true
        )
    }

    // MARK: — App messages (host app → extension)

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let msg = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = msg["action"] as? String else {
            completionHandler?(nil)
            return
        }
        switch action {
        case "exportCa":
            handleExportCa(completionHandler: completionHandler)
        case "version":
            let v = String(cString: mhrv_version())
            let data = try? JSONSerialization.data(withJSONObject: ["version": v])
            completionHandler?(data)
        default:
            completionHandler?(nil)
        }
    }

    private func handleExportCa(completionHandler: ((Data?) -> Void)?) {
        let tmp = NSTemporaryDirectory() + "mhrv_ca.pem"
        let ok  = mhrv_export_ca(tmp)
        var resp: [String: Any] = ["ok": ok]
        if ok { resp["path"] = tmp }
        let data = try? JSONSerialization.data(withJSONObject: resp)
        completionHandler?(data)
    }
}

// MARK: — Errors

enum TunnelError: LocalizedError {
    case missingConfig
    case noTunFd
    case startFailed

    var errorDescription: String? {
        switch self {
        case .missingConfig: return "No VPN config found. Open the app and configure it first."
        case .noTunFd:       return "Could not obtain tunnel file descriptor."
        case .startFailed:   return "VPN engine failed to start. Check the app logs."
        }
    }
}
