#pragma once
#include <stdint.h>
#include <stdbool.h>

/// Set the data directory for certificate storage.
/// Call once before mhrv_start, with the App Group container path.
void mhrv_set_data_dir(const char *path);

/// Start the VPN: mhrv-rs SOCKS5 proxy + leaf TUN/FakeIP bridge.
///
/// config_json  mhrv-rs config as JSON or TOML string.
///              listen_host should be "127.0.0.1" (loopback only).
/// tun_fd       File descriptor for the utun device, obtained via:
///              packetFlow.value(forKeyPath: "socket.fileDescriptor")
///
/// Returns a nonzero session handle on success, 0 on failure.
uint64_t mhrv_start(const char *config_json, int32_t tun_fd);

/// Stop the session returned by mhrv_start.
/// Returns true if the session was found and stopped.
bool mhrv_stop(uint64_t session_id);

/// Drain the in-memory log ring as a '\n'-joined C string.
/// The caller MUST free the returned pointer with mhrv_free_string.
char *mhrv_drain_logs(void);

/// Free a string returned by mhrv_drain_logs.
void mhrv_free_string(char *s);

/// Return the crate version string. The pointer is static — do NOT free.
const char *mhrv_version(void);

/// Copy the MITM CA certificate to dest_path.
/// Returns true on success.
bool mhrv_export_ca(const char *dest_path);
