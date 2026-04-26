package com.therealaleph.mhrv.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.HourglassBottom
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.therealaleph.mhrv.CaInstall
import com.therealaleph.mhrv.ConfigStore
import com.therealaleph.mhrv.DEFAULT_SNI_POOL
import com.therealaleph.mhrv.MhrvConfig
import com.therealaleph.mhrv.Mode
import com.therealaleph.mhrv.Native
import com.therealaleph.mhrv.ConnectionMode
import com.therealaleph.mhrv.NetworkDetect
import com.therealaleph.mhrv.R
import com.therealaleph.mhrv.SplitMode
import com.therealaleph.mhrv.UiLang
import com.therealaleph.mhrv.VpnState
import androidx.compose.ui.res.stringResource
import com.therealaleph.mhrv.ui.theme.ErrRed
import com.therealaleph.mhrv.ui.theme.OkGreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * UI state returned by the Activity after the CA install flow finishes,
 * so the screen can show a matching snackbar. Kept as a sum type — a raw
 * string message would conflate "installed" vs. "failed to export".
 */
sealed class CaInstallOutcome {
    object Installed : CaInstallOutcome()
    /**
     * Cert not found in the AndroidCAStore after the Settings activity
     * returned. Carries an optional downloadPath so the snackbar can tell
     * the user where the file landed (Downloads or app-private external).
     */
    data class NotInstalled(val downloadPath: String?) : CaInstallOutcome()
    data class Failed(val message: String) : CaInstallOutcome()
}

/**
 * Top-level screen. Intentionally one scrollable page rather than tabs —
 * first-run users need to see everything (deployment IDs, cert button,
 * Start) on one surface. Anything that isn't first-run critical lives in
 * collapsible sections (SNI pool, Advanced, Logs) so the default view
 * stays short.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onInstallCaConfirmed: () -> Unit,
    caOutcome: CaInstallOutcome?,
    onCaOutcomeConsumed: () -> Unit,
    onLangChange: (UiLang) -> Unit = {},
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    // Persisted form state. Any edit writes back to disk immediately —
    // cheap at this write rate, avoids "I tapped Start before saving" bugs.
    var cfg by remember { mutableStateOf(ConfigStore.load(ctx)) }
    fun persist(new: MhrvConfig) {
        cfg = new
        ConfigStore.save(ctx, new)
    }

    // CA install dialog visibility.
    var showInstallDialog by rememberSaveable { mutableStateOf(false) }

    // One-shot auto update check on first composition. Silent if we're
    // already on the latest (no point nagging about a network miss or an
    // up-to-date install); surfaces a snackbar only when a newer tag is
    // available. rememberSaveable so it doesn't re-fire on every config
    // change / rotation.
    var autoUpdateChecked by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(autoUpdateChecked) {
        if (autoUpdateChecked) return@LaunchedEffect
        autoUpdateChecked = true
        val json = withContext(Dispatchers.IO) {
            runCatching { Native.checkUpdate() }.getOrNull()
        }
        if (json != null) {
            val obj = runCatching { JSONObject(json) }.getOrNull()
            if (obj?.optString("kind") == "updateAvailable") {
                snackbar.showSnackbar(
                    "Update available: v${obj.optString("current")} → " +
                    "v${obj.optString("latest")}  ${obj.optString("url")}",
                    withDismissAction = true,
                )
            }
        }
    }

    // Gate Start/Stop on the service's actual state transition rather
    // than a fixed timer. The previous 2s cooldown was shorter than the
    // worst-case teardown (Tun2proxy.stop + 4s join + 5s rt.shutdown_timeout
    // ≈ 9s on the slowest path), which let the user fire a fresh Connect
    // while the previous Stop's native cleanup was still releasing the
    // listener port — the new startProxy then failed with "Address already
    // in use".
    //
    // `awaitingRunning` holds the value we expect VpnState.isRunning to
    // settle on after the user's action; null means "no transition in
    // flight". The LaunchedEffect below suspends on the StateFlow until
    // the predicate matches, with a 12s backstop in case the service
    // failed before flipping the flag (e.g., establish() returned null).
    // Side benefit: this also debounces the rapid-tap EGL renderer crash
    // the old timer was guarding against.
    var awaitingRunning by remember { mutableStateOf<Boolean?>(null) }
    val transitioning = awaitingRunning != null
    LaunchedEffect(awaitingRunning) {
        val target = awaitingRunning ?: return@LaunchedEffect
        try {
            withTimeoutOrNull(12_000) {
                VpnState.isRunning.first { it == target }
            }
        } finally {
            awaitingRunning = null
        }
    }

    // Surface CA install result as a snackbar. We consume the outcome
    // after showing so a recomposition doesn't re-trigger it.
    LaunchedEffect(caOutcome) {
        val o = caOutcome ?: return@LaunchedEffect
        val msg = when (o) {
            is CaInstallOutcome.Installed ->
                "Certificate installed ✓"
            is CaInstallOutcome.NotInstalled -> buildString {
                append("Certificate not yet installed.")
                if (!o.downloadPath.isNullOrBlank()) {
                    append(" Saved to ${o.downloadPath}. ")
                    append("In Settings, search for \"CA certificate\" and install from there — NOT \"VPN & app user certificate\" or \"Wi-Fi\".")
                } else {
                    append(" Tap Install again to retry.")
                }
            }
            is CaInstallOutcome.Failed -> o.message
        }
        snackbar.showSnackbar(msg, withDismissAction = true)
        onCaOutcomeConsumed()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("mhrv-rs") },
                actions = {
                    // Language toggle — cycles AUTO → FA → EN → AUTO.
                    // Saving writes to config.json and triggers activity
                    // recreate, which re-applies the AppCompatDelegate
                    // locale (and flips LTR ↔ RTL accordingly). Kept as
                    // a small label button instead of an icon because
                    // "AUTO/FA/EN" communicates the current state at a
                    // glance; a flag icon alone would be ambiguous.
                    TextButton(
                        onClick = {
                            val next = when (cfg.uiLang) {
                                UiLang.AUTO -> UiLang.FA
                                UiLang.FA -> UiLang.EN
                                UiLang.EN -> UiLang.AUTO
                            }
                            persist(cfg.copy(uiLang = next))
                            onLangChange(next)
                        },
                    ) {
                        Text(
                            text = when (cfg.uiLang) {
                                UiLang.AUTO -> "AUTO"
                                UiLang.FA -> "FA"
                                UiLang.EN -> "EN"
                            },
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }

                    // Tap the version label to check for updates.
                    var checking by remember { mutableStateOf(false) }
                    TextButton(
                        onClick = {
                            if (checking) return@TextButton
                            checking = true
                            scope.launch {
                                val json = withContext(Dispatchers.IO) {
                                    runCatching { Native.checkUpdate() }.getOrNull()
                                }
                                val msg = summarizeUpdateCheck(json)
                                snackbar.showSnackbar(msg, withDismissAction = true)
                                checking = false
                            }
                        },
                        modifier = Modifier.padding(end = 4.dp),
                    ) {
                        Text(
                            text = if (checking) stringResource(R.string.tb_check_update_checking)
                                   else stringResource(R.string.tb_version_prefix) +
                                        runCatching { Native.version() }.getOrDefault("?"),
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { inner ->
        Column(
            modifier = Modifier
                .padding(inner)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SectionHeader("Mode")
            ModeDropdown(
                mode = cfg.mode,
                onChange = { persist(cfg.copy(mode = it)) },
            )

            Spacer(Modifier.height(4.dp))
            SectionHeader(stringResource(R.string.sec_apps_script_relay))

            val appsScriptEnabled = cfg.mode == Mode.APPS_SCRIPT || cfg.mode == Mode.FULL
            DeploymentIdsField(
                urls = cfg.appsScriptUrls,
                onChange = { persist(cfg.copy(appsScriptUrls = it)) },
                enabled = appsScriptEnabled,
            )

            OutlinedTextField(
                value = cfg.authKey,
                onValueChange = { persist(cfg.copy(authKey = it)) },
                label = { Text(stringResource(R.string.field_auth_key)) },
                singleLine = true,
                enabled = appsScriptEnabled,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth(),
                supportingText = {
                    Text(stringResource(R.string.help_auth_key))
                },
            )

            Spacer(Modifier.height(4.dp))
            SectionHeader(stringResource(R.string.sec_network))

            ConnectionModeDropdown(
                mode = cfg.connectionMode,
                onChange = { persist(cfg.copy(connectionMode = it)) },
                httpPort = cfg.listenPort,
                socks5Port = cfg.socks5Port ?: (cfg.listenPort + 1),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = cfg.googleIp,
                    onValueChange = { persist(cfg.copy(googleIp = it)) },
                    label = { Text(stringResource(R.string.field_google_ip)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = cfg.frontDomain,
                    onValueChange = { persist(cfg.copy(frontDomain = it)) },
                    label = { Text(stringResource(R.string.field_front_domain)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
            }
            // "Auto-detect" forces a fresh DNS resolution now. Start also
            // auto-resolves transparently, but exposing a button makes the
            // "I'm getting connect timeouts, is my google_ip stale?" case
            // a one-tap fix without needing to look up nslookup output.
            TextButton(
                onClick = {
                    scope.launch {
                        val fresh = withContext(Dispatchers.IO) {
                            NetworkDetect.resolveGoogleIp()
                        }
                        if (!fresh.isNullOrBlank()) {
                            var updated = cfg
                            if (fresh != updated.googleIp) {
                                updated = updated.copy(googleIp = fresh)
                            }
                            // Same repair logic as the Start button —
                            // if front_domain has been corrupted into an
                            // IP we can't use it for SNI, so put the
                            // default hostname back.
                            if (updated.frontDomain.isBlank() ||
                                updated.frontDomain.parseAsIpOrNull() != null
                            ) {
                                updated = updated.copy(frontDomain = "www.google.com")
                            }
                            // Captured up-front so the lambda has access
                            // to the format-string resources via context
                            // before running on the IO dispatcher.
                            if (updated !== cfg) {
                                persist(updated)
                                snackbar.showSnackbar(
                                    ctx.getString(R.string.snack_google_ip_updated, fresh),
                                )
                            } else {
                                snackbar.showSnackbar(
                                    ctx.getString(R.string.snack_google_ip_current, fresh),
                                )
                            }
                        } else {
                            snackbar.showSnackbar(ctx.getString(R.string.snack_dns_lookup_failed))
                        }
                    }
                },
                modifier = Modifier.align(Alignment.End),
            ) { Text(stringResource(R.string.btn_auto_detect_google_ip)) }

            // App splitting — only makes sense in VPN_TUN mode.
            // PROXY_ONLY has no system-level routing to partition.
            if (cfg.connectionMode == ConnectionMode.VPN_TUN) {
                CollapsibleSection(title = stringResource(R.string.sec_app_splitting)) {
                    AppSplittingEditor(cfg = cfg, onChange = ::persist)
                }
            }

            // SNI pool: collapsed by default. Users without a reason to
            // touch it should leave Rust's auto-expansion to handle it.
            CollapsibleSection(title = stringResource(R.string.sec_sni_pool_tester)) {
                SniPoolEditor(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            // Advanced settings: collapsed by default.
            CollapsibleSection(title = stringResource(R.string.sec_advanced)) {
                AdvancedSettings(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            Spacer(Modifier.height(8.dp))

            // Unified Connect/Disconnect button. Color + label track the
            // service's real "is it running right now" state (via
            // `VpnState.isRunning`), so the UI never shows "Connect" while
            // the tunnel is still up or "Disconnect" after the service
            // finished tearing down. Two tap paths, one button:
            //   - running=false → green "Connect" → runs the auto-resolve
            //     + persist + onStart() sequence we used to hang off the
            //     old Start button.
            //   - running=true  → red "Disconnect" → fires onStop().
            val isVpnRunning by VpnState.isRunning.collectAsState()
            Button(
                onClick = {
                    if (isVpnRunning) {
                        awaitingRunning = false
                        onStop()
                    } else {
                        awaitingRunning = true
                        // Connect flow: auto-resolve google_ip so we don't
                        // hand the proxy a stale anycast target; repair
                        // front_domain if it got corrupted into an IP
                        // (SNI has to be a hostname); then fire onStart.
                        // All three steps go through the Compose persist()
                        // so a subsequent field edit can't overwrite the
                        // fresh values with pre-resolve ones.
                        scope.launch {
                            // Only auto-fill google_ip if it's empty.
                            // Issue #71: some Iranian ISPs return
                            // poisoned A records for www.google.com that
                            // resolve but then refuse TLS (or route to a
                            // Google IP that's not on the GFE and can't
                            // handle our SNI-rewrite). If the user has
                            // manually set a working IP
                            // (e.g. 216.239.38.120), we must NOT
                            // overwrite it with a poisoned fresh lookup
                            // just because the two values differ. They
                            // can still force a re-resolve via the
                            // explicit "Auto-detect" button above.
                            var updated = cfg
                            if (updated.googleIp.isBlank()) {
                                val fresh = withContext(Dispatchers.IO) {
                                    NetworkDetect.resolveGoogleIp()
                                }
                                if (!fresh.isNullOrBlank()) {
                                    updated = updated.copy(googleIp = fresh)
                                }
                            }
                            if (updated.frontDomain.isBlank() ||
                                updated.frontDomain.parseAsIpOrNull() != null
                            ) {
                                updated = updated.copy(frontDomain = "www.google.com")
                            }
                            if (updated !== cfg) persist(updated)
                            onStart()
                        }
                    }
                },
                enabled = (isVpnRunning ||
                    cfg.mode == Mode.GOOGLE_ONLY ||
                    (cfg.hasDeploymentId && cfg.authKey.isNotBlank())) && !transitioning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isVpnRunning) ErrRed else OkGreen,
                    contentColor = androidx.compose.ui.graphics.Color.White,
                    disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp),
            ) {
                Text(
                    when {
                        transitioning -> "…"
                        isVpnRunning -> stringResource(R.string.btn_disconnect)
                        else -> stringResource(R.string.btn_connect)
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }

            Spacer(Modifier.height(4.dp))
            // Secondary accent button — FilledTonalButton reads as a lower-
            // priority action next to Start/Stop, matching the desktop UI's
            // visual hierarchy where Install CA is offered as a helper
            // button rather than the headline action.
            FilledTonalButton(
                onClick = { showInstallDialog = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.btn_install_mitm))
            }

            // "Usage today (estimated)" — visible only while a proxy is
            // actually running (the handle is non-zero). Polls the native
            // stats counter once a second; cheap (just reads atomics on
            // the Rust side) and gives users a live feel for how close
            // they are to the Apps Script daily quota. Also links out to
            // Google's dashboard for the authoritative number — the
            // client-side estimate only sees what this device relayed,
            // not what other devices on the same deployment consumed.
            UsageTodayCard()

            CollapsibleSection(title = stringResource(R.string.sec_live_logs), initiallyExpanded = false) {
                LiveLogPane()
            }

            Spacer(Modifier.height(16.dp))
            // Wrapped in a collapsible so the big prose block doesn't
            // dominate the form after the user has learned the flow.
            // Starts expanded once for a fresh install so the first-run
            // instructions are immediately visible.
            CollapsibleSection(
                title = stringResource(R.string.sec_how_to_use),
                initiallyExpanded = cfg.appsScriptUrls.isEmpty() || cfg.authKey.isBlank(),
            ) {
                HowToUseBody(cfg.listenPort)
            }
        }
    }

    // ---- CA install confirmation dialog ---------------------------------
    if (showInstallDialog) {
        // Export eagerly so we can show the fingerprint in the dialog body
        // — builds user confidence ("yes, that's the cert I'm trusting")
        // and gives us a usable failure path if the CA doesn't exist yet.
        val exported = remember { CaInstall.export(ctx) }
        val fp = remember(exported) { if (exported) CaInstall.fingerprint(ctx) else null }
        val cn = remember(exported) { if (exported) CaInstall.subjectCn(ctx) else null }

        AlertDialog(
            onDismissRequest = { showInstallDialog = false },
            title = { Text(stringResource(R.string.dialog_install_mitm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "mhrv-rs creates a local certificate authority so it can decrypt " +
                        "and re-encrypt HTTPS traffic before tunnelling it through the Apps " +
                        "Script relay. Without this CA installed as trusted, apps will show " +
                        "certificate errors."
                    )
                    Text(
                        "On Android 11+ the system removed the inline install path, so " +
                        "tapping Install will: (1) save a PEM copy to Downloads/mhrv-ca.crt, " +
                        "(2) open the Settings app.\n\n" +
                        "Inside Settings, tap the search bar and type \"CA certificate\". " +
                        "Open the result labelled \"CA certificate\" (NOT \"VPN & app user " +
                        "certificate\" or \"Wi-Fi certificate\"). Pick mhrv-ca.crt from " +
                        "Downloads when prompted. If you don't have a screen lock, Android " +
                        "will ask you to add one first — that's an OS requirement for " +
                        "installing any user CA."
                    )
                    if (fp != null) {
                        Text("Subject: ${cn ?: "(unknown)"}", style = MaterialTheme.typography.labelMedium)
                        Text(
                            text = "SHA-256: ${CaInstall.fingerprintHex(fp)}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    } else {
                        Text(
                            "Could not read the CA cert yet. Tap Start once so the " +
                            "proxy generates it, then come back.",
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showInstallDialog = false
                        if (fp != null) onInstallCaConfirmed()
                    },
                    enabled = fp != null,
                ) { Text("Install") }
            },
            dismissButton = {
                TextButton(onClick = { showInstallDialog = false }) { Text("Cancel") }
            },
        )
    }
}

// =========================================================================
// App splitting — ALL / ONLY / EXCEPT, plus a picker for the package list.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppSplittingEditor(
    cfg: MhrvConfig,
    onChange: (MhrvConfig) -> Unit,
) {
    val ctx = LocalContext.current
    var pickerOpen by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            stringResource(R.string.help_app_splitting),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Radio-style mode selector. Using Column-of-Row-with-RadioButton
        // instead of a dropdown because all three options deserve to be
        // visible simultaneously — the labels explain the contract.
        SplitModeRow(
            label = stringResource(R.string.split_all),
            selected = cfg.splitMode == SplitMode.ALL,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.ALL)) },
        )
        SplitModeRow(
            label = stringResource(R.string.split_only),
            selected = cfg.splitMode == SplitMode.ONLY,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.ONLY)) },
        )
        SplitModeRow(
            label = stringResource(R.string.split_except),
            selected = cfg.splitMode == SplitMode.EXCEPT,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.EXCEPT)) },
        )

        if (cfg.splitMode != SplitMode.ALL) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    stringResource(R.string.sni_selected_count, cfg.splitApps.size),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { pickerOpen = true }) {
                    Text(stringResource(R.string.split_pick_apps))
                }
            }
        }
    }

    if (pickerOpen) {
        AppPickerDialog(
            initial = cfg.splitApps.toSet(),
            ownPackage = ctx.packageName,
            onSave = { picked ->
                onChange(cfg.copy(splitApps = picked))
                pickerOpen = false
            },
            onDismiss = { pickerOpen = false },
        )
    }
}

@Composable
private fun SplitModeRow(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
    }
}

// =========================================================================
// Connection mode — VPN (TUN) vs Proxy-only.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectionModeDropdown(
    mode: ConnectionMode,
    onChange: (ConnectionMode) -> Unit,
    httpPort: Int,
    socks5Port: Int,
) {
    val labelVpn = stringResource(R.string.mode_vpn_tun)
    val labelProxy = stringResource(R.string.mode_proxy_only)
    val currentLabel = when (mode) {
        ConnectionMode.VPN_TUN -> labelVpn
        ConnectionMode.PROXY_ONLY -> labelProxy
    }
    var expanded by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = currentLabel,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.field_connection_mode)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                DropdownMenuItem(
                    text = { Text(labelVpn) },
                    onClick = {
                        onChange(ConnectionMode.VPN_TUN)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelProxy) },
                    onClick = {
                        onChange(ConnectionMode.PROXY_ONLY)
                        expanded = false
                    },
                )
            }
        }

        // Helper text under the dropdown explains what the user is
        // signing up for in each mode — especially important for
        // PROXY_ONLY, where "tap Connect" alone doesn't route anything
        // until they set the Wi-Fi proxy themselves.
        val help = when (mode) {
            ConnectionMode.VPN_TUN ->
                stringResource(R.string.help_mode_vpn_tun)
            ConnectionMode.PROXY_ONLY ->
                stringResource(R.string.help_mode_proxy_only, httpPort, socks5Port)
        }
        Text(
            help,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// =========================================================================
// Deployment IDs editor — one row per ID, with add/remove buttons. The
// "+ Add" field accepts a single ID OR a bulk paste of many separated by
// whitespace / newline / comma / semicolon — useful when migrating from
// the desktop config or pasting a freshly-deployed batch (issue: bulk add).
// =========================================================================

/** Split a bulk-pasted blob into individual entries. */
private val ID_SEPARATORS = Regex("[\\s,;]+")

@Composable
private fun DeploymentIdsField(
    urls: List<String>,
    onChange: (List<String>) -> Unit,
    enabled: Boolean = true,
) {
    var newEntry by remember { mutableStateOf("") }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            stringResource(R.string.field_deployment_urls),
            style = MaterialTheme.typography.labelLarge,
        )

        // Existing entries — each with its own row and a remove button.
        // A bulk paste into an existing row also expands into multiple
        // entries, so users don't have to find the "+ Add" field to do it.
        urls.forEachIndexed { index, url ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                OutlinedTextField(
                    value = url,
                    onValueChange = { edited ->
                        val parts = edited.split(ID_SEPARATORS).filter { it.isNotBlank() }
                        val updated = urls.toMutableList()
                        if (parts.size > 1) {
                            // Bulk paste into this row: expand in place.
                            updated.removeAt(index)
                            updated.addAll(index, parts)
                        } else {
                            // Normal typing — preserve raw input so the
                            // caret/whitespace doesn't get reformatted on
                            // every keystroke.
                            updated[index] = edited
                        }
                        onChange(updated)
                    },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall,
                    label = { Text("#${index + 1}") },
                )
                IconButton(
                    onClick = {
                        onChange(urls.filterIndexed { i, _ -> i != index })
                    },
                    enabled = enabled,
                ) {
                    Text("✕", color = MaterialTheme.colorScheme.error)
                }
            }
        }

        // "Add" row: multi-line text field + button. Multi-line so a user
        // can paste a long list at once (newline-separated is the natural
        // form when copying out of the desktop UI's textarea).
        Row(
            verticalAlignment = Alignment.Top,
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = newEntry,
                onValueChange = { newEntry = it },
                enabled = enabled,
                modifier = Modifier.weight(1f),
                singleLine = false,
                minLines = 1,
                maxLines = 6,
                placeholder = { Text(stringResource(R.string.placeholder_paste_ids)) },
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = {
                    val parts = newEntry.split(ID_SEPARATORS).filter { it.isNotBlank() }
                    if (parts.isNotEmpty()) {
                        onChange(urls + parts)
                        newEntry = ""
                    }
                },
                enabled = enabled && newEntry.isNotBlank(),
                contentPadding = PaddingValues(horizontal = 12.dp),
            ) {
                Text("+ Add")
            }
        }

        Text(
            stringResource(R.string.help_deployment_urls),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// =========================================================================
// Mode dropdown: apps_script (default) vs google_only (bootstrap).
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModeDropdown(
    mode: Mode,
    onChange: (Mode) -> Unit,
) {
    val labelApps = "Apps Script (MITM)"
    val labelGoogle = "Google-only (bootstrap)"
    val labelFull = "Full tunnel (no cert)"
    val currentLabel = when (mode) {
        Mode.APPS_SCRIPT -> labelApps
        Mode.GOOGLE_ONLY -> labelGoogle
        Mode.FULL -> labelFull
    }
    var expanded by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = currentLabel,
                onValueChange = {},
                readOnly = true,
                label = { Text("Mode") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                DropdownMenuItem(
                    text = { Text(labelApps) },
                    onClick = { onChange(Mode.APPS_SCRIPT); expanded = false },
                )
                DropdownMenuItem(
                    text = { Text(labelGoogle) },
                    onClick = { onChange(Mode.GOOGLE_ONLY); expanded = false },
                )
                DropdownMenuItem(
                    text = { Text(labelFull) },
                    onClick = { onChange(Mode.FULL); expanded = false },
                )
            }
        }

        val help = when (mode) {
            Mode.APPS_SCRIPT ->
                "Full DPI bypass through your deployed Apps Script relay."
            Mode.GOOGLE_ONLY ->
                "Bootstrap: reach *.google.com directly so you can open script.google.com and deploy Code.gs. Non-Google traffic goes direct."
            Mode.FULL ->
                "All traffic tunneled end-to-end through Apps Script + remote tunnel node. No certificate needed."
        }
        Text(
            help,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// =========================================================================
// SNI pool editor + per-SNI probe.
// =========================================================================

private sealed class ProbeState {
    object Idle : ProbeState()
    object InFlight : ProbeState()
    data class Ok(val latencyMs: Int) : ProbeState()
    data class Err(val message: String) : ProbeState()
}

@Composable
private fun SniPoolEditor(
    cfg: MhrvConfig,
    onChange: (MhrvConfig) -> Unit,
) {
    val scope = rememberCoroutineScope()

    // Build the displayed list: union of the default pool + the config's
    // sniHosts + the current front_domain. Order: front_domain first,
    // defaults, then user customs. Deduped.
    val displayed: List<String> = remember(cfg) {
        val seen = linkedSetOf<String>()
        if (cfg.frontDomain.isNotBlank()) seen.add(cfg.frontDomain.trim())
        DEFAULT_SNI_POOL.forEach { seen.add(it) }
        cfg.sniHosts.forEach { if (it.isNotBlank()) seen.add(it.trim()) }
        seen.toList()
    }

    // A host is enabled if it appears in cfg.sniHosts. Empty sniHosts
    // means "let Rust auto-expand" — we reflect that as "default pool
    // enabled, customs not".
    val enabledSet: Set<String> = remember(cfg.sniHosts) {
        if (cfg.sniHosts.isNotEmpty()) cfg.sniHosts.toSet()
        else DEFAULT_SNI_POOL.toSet() + setOfNotNull(cfg.frontDomain.takeIf { it.isNotBlank() })
    }

    val probeState = remember { mutableStateMapOf<String, ProbeState>() }

    fun probe(sni: String) {
        probeState[sni] = ProbeState.InFlight
        scope.launch {
            val json = withContext(Dispatchers.IO) {
                runCatching { Native.testSni(cfg.googleIp, sni) }.getOrNull()
            }
            probeState[sni] = parseProbeResult(json)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            stringResource(R.string.help_sni_pool),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        displayed.forEach { sni ->
            val enabled = sni in enabledSet
            SniRow(
                sni = sni,
                enabled = enabled,
                state = probeState[sni] ?: ProbeState.Idle,
                onToggle = { nowEnabled ->
                    val next = if (nowEnabled) {
                        (cfg.sniHosts.takeIf { it.isNotEmpty() } ?: emptyList()) + sni
                    } else {
                        val current = if (cfg.sniHosts.isNotEmpty()) cfg.sniHosts else enabledSet.toList()
                        current.filter { it != sni }
                    }
                    onChange(cfg.copy(sniHosts = next.distinct()))
                },
                onTest = { probe(sni) },
            )
        }

        // Custom-add row.
        var custom by remember { mutableStateOf("") }
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = custom,
                onValueChange = { custom = it },
                label = { Text(stringResource(R.string.field_add_custom_sni)) },
                // Accept a pasted list — users (issue #47) want to dump a
                // whole list of subdomains in one go. We split on newlines,
                // commas, semicolons, and whitespace so formats like
                //   www.google.com\nmail.google.com\ndrive.google.com
                //   www.google.com, mail.google.com
                //   www.google.com mail.google.com
                // all do the right thing on Add.
                singleLine = false,
                maxLines = 6,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = {
                    // Tokenise on any whitespace, comma, or semicolon so one
                    // Add click absorbs a pasted list. Deduplicate within
                    // the paste before merging into the existing list.
                    val tokens = custom.split(Regex("[\\s,;]+"))
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                    if (tokens.isNotEmpty()) {
                        val base = cfg.sniHosts.takeIf { it.isNotEmpty() } ?: enabledSet.toList()
                        val next = (base + tokens).distinct()
                        onChange(cfg.copy(sniHosts = next))
                        custom = ""
                    }
                },
                enabled = custom.isNotBlank(),
            ) { Text(stringResource(R.string.btn_add)) }
        }

        TextButton(
            onClick = { displayed.forEach { probe(it) } },
            modifier = Modifier.align(Alignment.End),
        ) { Text(stringResource(R.string.btn_test_all)) }
    }
}

@Composable
private fun SniRow(
    sni: String,
    enabled: Boolean,
    state: ProbeState,
    onToggle: (Boolean) -> Unit,
    onTest: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Checkbox(checked = enabled, onCheckedChange = onToggle)
            Text(
                sni,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            ProbeBadge(state)
            Spacer(Modifier.width(4.dp))
            TextButton(onClick = onTest, enabled = state !is ProbeState.InFlight) {
                Text(stringResource(R.string.btn_test))
            }
        }
        // Show the error reason on its own line when the probe failed —
        // a red dot with no explanation was confusing ("SNI test also
        // fails despite having internet"). Common reasons: "dns: ..." or
        // "connect: ...".
        if (state is ProbeState.Err) {
            Text(
                text = state.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(start = 48.dp, bottom = 4.dp),
            )
        }
    }
}

@Composable
private fun ProbeBadge(state: ProbeState) {
    when (state) {
        is ProbeState.Idle -> {}
        is ProbeState.InFlight -> {
            CircularProgressIndicator(
                modifier = Modifier.size(14.dp),
                strokeWidth = 2.dp,
            )
        }
        is ProbeState.Ok -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Same green the desktop UI uses for OK status (OK_GREEN
                // in src/bin/ui.rs line 510) — kept in sync via Theme.kt.
                Icon(
                    Icons.Default.CheckCircle, null,
                    tint = OkGreen,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(Modifier.width(2.dp))
                Text("${state.latencyMs} ms", style = MaterialTheme.typography.labelSmall)
            }
        }
        is ProbeState.Err -> {
            Icon(
                Icons.Default.ErrorOutline, state.message,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

/**
 * Turn the JSON blob from `Native.checkUpdate()` into a one-line
 * snackbar message. Parsing is lenient — if the shape is anything other
 * than what we expect we fall back to "check failed" rather than
 * spewing the raw JSON at the user.
 */
private fun summarizeUpdateCheck(json: String?): String {
    if (json.isNullOrBlank()) return "Update check failed (no response)"
    return try {
        val obj = JSONObject(json)
        when (obj.optString("kind")) {
            "upToDate" -> "Up to date (running v${obj.optString("current")})"
            "updateAvailable" -> {
                val cur = obj.optString("current")
                val latest = obj.optString("latest")
                val url = obj.optString("url")
                "Update available: v$cur → v$latest   $url"
            }
            "offline" -> "Offline: ${obj.optString("reason", "no details")}"
            "error" -> "Check failed: ${obj.optString("reason", "no details")}"
            else -> "Check failed (unknown response)"
        }
    } catch (_: Throwable) {
        "Check failed (bad json)"
    }
}

/**
 * Try to parse a string as an IPv4 or IPv6 literal. Returns null if it
 * looks like a hostname (or bogus) — which is what we want for
 * front_domain, where a hostname is required (goes into the TLS SNI on
 * the outbound leg).
 *
 * Intentionally strict: must be a valid literal AND must not contain a
 * letter anywhere. Plain `InetAddress.getByName(...)` would succeed for
 * hostnames too (it'd do a DNS lookup and return an IP), which would
 * false-positive every normal value like "www.google.com".
 */
private fun String.parseAsIpOrNull(): java.net.InetAddress? {
    val s = trim()
    if (s.isEmpty() || s.any { it.isLetter() }) return null
    return try {
        // Literal-only parse: rejects anything that would need DNS.
        java.net.InetAddress.getByName(s).takeIf {
            it.hostAddress?.let { addr -> addr == s || addr.contains(s) } == true
        }
    } catch (_: Throwable) {
        null
    }
}

private fun parseProbeResult(json: String?): ProbeState {
    if (json.isNullOrBlank()) return ProbeState.Err("no response")
    return try {
        val obj = JSONObject(json)
        if (obj.optBoolean("ok", false)) {
            ProbeState.Ok(obj.optInt("latencyMs", -1))
        } else {
            ProbeState.Err(obj.optString("error", "failed"))
        }
    } catch (_: Throwable) {
        ProbeState.Err("bad json")
    }
}

// =========================================================================
// Advanced settings.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdvancedSettings(
    cfg: MhrvConfig,
    onChange: (MhrvConfig) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // verify_ssl
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.adv_verify_tls), style = MaterialTheme.typography.bodyMedium)
                Text(
                    stringResource(R.string.adv_verify_tls_help),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.verifySsl,
                onCheckedChange = { onChange(cfg.copy(verifySsl = it)) },
            )
        }

        // log_level dropdown
        var expanded by remember { mutableStateOf(false) }
        val levels = listOf("trace", "debug", "info", "warn", "error", "off")
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = cfg.logLevel,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.adv_log_level)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                levels.forEach { lvl ->
                    DropdownMenuItem(
                        text = { Text(lvl) },
                        onClick = {
                            onChange(cfg.copy(logLevel = lvl))
                            expanded = false
                        },
                    )
                }
            }
        }

        // parallel_relay slider
        Column {
            Text(
                stringResource(R.string.adv_parallel_relay, cfg.parallelRelay),
                style = MaterialTheme.typography.bodyMedium,
            )
            Slider(
                value = cfg.parallelRelay.toFloat(),
                onValueChange = { onChange(cfg.copy(parallelRelay = it.toInt().coerceIn(1, 5))) },
                valueRange = 1f..5f,
                steps = 3,  // yields 1,2,3,4,5 positions
            )
            Text(
                stringResource(R.string.adv_parallel_relay_help),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        OutlinedTextField(
            value = cfg.upstreamSocks5,
            onValueChange = { onChange(cfg.copy(upstreamSocks5 = it)) },
            label = { Text(stringResource(R.string.adv_upstream_socks5)) },
            placeholder = { Text("host:port") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            supportingText = {
                Text(stringResource(R.string.adv_upstream_socks5_help))
            },
        )
    }
}

// =========================================================================
// Live log pane — polls Native.drainLogs() on a 500ms tick.
// =========================================================================

@Composable
private fun LiveLogPane() {
    val lines = remember { mutableStateListOf<String>() }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()

    // Pull from the ring buffer periodically. We pull even while the
    // section is collapsed (cheap), so re-expanding shows fresh tail.
    LaunchedEffect(Unit) {
        while (true) {
            val blob = withContext(Dispatchers.IO) {
                runCatching { Native.drainLogs() }.getOrNull()
            }
            if (!blob.isNullOrEmpty()) {
                blob.split("\n").forEach { if (it.isNotBlank()) lines.add(it) }
                // Cap the visible list so we don't grow unboundedly.
                while (lines.size > 500) lines.removeAt(0)
                // Follow tail.
                if (lines.isNotEmpty()) {
                    listState.scrollToItem(lines.size - 1)
                }
            }
            delay(500)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${lines.size} lines",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { lines.clear() }) { Text("Clear") }
        }
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp, max = 320.dp),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.padding(8.dp),
            ) {
                items(lines) { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}

// =========================================================================
// Small shared pieces.
// =========================================================================

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
    )
}

/**
 * Minimal disclosure widget. Compose has no stock "expandable card" in
 * Material3 yet, so we build it from a clickable header + AnimatedVisibility
 * wrapping the content.
 */
@Composable
private fun CollapsibleSection(
    title: String,
    initiallyExpanded: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { expanded = !expanded }) {
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (expanded) "Collapse" else "Expand",
                    )
                }
            }
            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    content = content,
                )
            }
        }
    }
}

/**
 * "Usage today (estimated)" card. Polls `Native.statsJson(handle)` every
 * second while the proxy is up and renders today's relay calls vs. the
 * Apps Script free-tier quota (20,000/day), today's bytes, UTC day key,
 * and a countdown to the 00:00 UTC reset. Also shows a "View quota on
 * Google" button that opens Google's Apps Script dashboard — the
 * authoritative number, since the client-side estimate only sees what
 * this device relayed.
 *
 * Hidden when the handle is 0 (proxy not running) or the JSON comes back
 * empty (google_only / full-only configs don't run a DomainFronter and so
 * have nothing to report).
 */
@Composable
private fun UsageTodayCard() {
    // Free-tier Apps Script UrlFetchApp daily quota. Workspace / paid
    // tiers get 100k but most users are on free.
    val freeQuotaPerDay = 20_000

    val handle by VpnState.proxyHandle.collectAsState()
    val isRunning by VpnState.isRunning.collectAsState()

    // Nothing to poll until the proxy is up.
    if (!isRunning || handle == 0L) return

    var statsJson by remember { mutableStateOf("") }
    LaunchedEffect(handle) {
        // Drop any stale snapshot from a previous run.
        statsJson = ""
        while (true) {
            statsJson = withContext(Dispatchers.IO) {
                runCatching { Native.statsJson(handle) }.getOrDefault("")
            }
            delay(1000)
        }
    }

    val obj = remember(statsJson) {
        if (statsJson.isBlank()) null
        else runCatching { JSONObject(statsJson) }.getOrNull()
    }
    // Still booting / not an apps-script config — stay silent.
    if (obj == null) return

    val todayCalls = obj.optLong("today_calls", 0L)
    val todayBytes = obj.optLong("today_bytes", 0L)
    val todayKey = obj.optString("today_key", "")
    val resetSecs = obj.optLong("today_reset_secs", 0L)
    val pct = if (freeQuotaPerDay > 0) {
        (todayCalls.toDouble() / freeQuotaPerDay) * 100.0
    } else 0.0

    val ctx = LocalContext.current

    Spacer(Modifier.height(8.dp))
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                stringResource(R.string.sec_usage_today),
                style = MaterialTheme.typography.titleSmall,
            )

            UsageRow(
                label = stringResource(R.string.label_calls_today),
                value = stringResource(
                    R.string.usage_calls_of_quota,
                    todayCalls.toInt(),
                    freeQuotaPerDay,
                    pct,
                ),
            )
            UsageRow(
                label = stringResource(R.string.label_bytes_today),
                value = fmtBytes(todayBytes),
            )
            UsageRow(
                label = stringResource(R.string.label_utc_day),
                value = todayKey,
            )
            UsageRow(
                label = stringResource(R.string.label_resets_in),
                value = stringResource(
                    R.string.usage_resets_hm,
                    (resetSecs / 3600).toInt(),
                    ((resetSecs / 60) % 60).toInt(),
                ),
            )

            Spacer(Modifier.height(4.dp))
            TextButton(
                onClick = {
                    // Open the Google-side Apps Script quota dashboard in
                    // the user's browser. Uses ACTION_VIEW with a https://
                    // URI — the OS picks whatever default browser is set.
                    val intent = android.content.Intent(
                        android.content.Intent.ACTION_VIEW,
                        android.net.Uri.parse("https://script.google.com/home/usage"),
                    )
                    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { ctx.startActivity(intent) }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.btn_view_quota_on_google))
            }
            Text(
                stringResource(R.string.usage_today_note),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun UsageRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
    }
}

private fun fmtBytes(b: Long): String {
    val k = 1024L
    val m = k * k
    val g = m * k
    return when {
        b >= g -> String.format("%.2f GB", b.toDouble() / g)
        b >= m -> String.format("%.2f MB", b.toDouble() / m)
        b >= k -> String.format("%.1f KB", b.toDouble() / k)
        else -> "$b B"
    }
}

@Composable
private fun HowToUseBody(listenPort: Int) {
    // Used inside the collapsible "How to use" CollapsibleSection. The
    // card + title are provided by the section wrapper, so this body
    // just renders the body text.
    //
    // Text is sourced from string resources (values/strings.xml +
    // values-fa/strings.xml) so the Persian locale gets a translated
    // guide instead of falling back to English.
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.help_how_to_use),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
