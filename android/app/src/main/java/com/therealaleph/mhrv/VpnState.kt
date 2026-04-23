package com.therealaleph.mhrv

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide observable for "is mhrv-rs's VPN/proxy currently up?"
 *
 * The activity and the service live in the same process (same UID, same
 * ClassLoader), so a plain singleton with a `MutableStateFlow` is the
 * shortest path from "service just finished starting" to "button swaps
 * to Disconnect". No IPC, no broadcasts, no lifecycle dance.
 *
 * The service toggles this from its startEverything() / teardown() paths;
 * the Compose UI collects it and swaps the Connect/Disconnect button
 * label + color accordingly. We intentionally do NOT try to reconstruct
 * the flag by querying Android's ConnectivityManager or a service-binding
 * check: those race with the service's own teardown and would show
 * "Connected" for a half-second after the user tapped Disconnect.
 * Trusting the service's own self-report is both simpler and correct.
 *
 * Process death resets the flag to false, which is also correct — VPN is
 * torn down by Android when our process dies, so "not running" is the
 * accurate state on the next launch.
 */
object VpnState {
    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    fun setRunning(running: Boolean) {
        _isRunning.value = running
    }
}
