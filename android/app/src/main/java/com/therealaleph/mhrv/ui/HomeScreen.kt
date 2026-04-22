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
import com.therealaleph.mhrv.Native
import com.therealaleph.mhrv.ui.theme.OkGreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

    // Cooldown on Start/Stop. Rapid taps during a VPN transition trigger
    // an emulator-specific EGL renderer crash
    // (F OpenGLRenderer: EGL_NOT_INITIALIZED during rendering) — the
    // service survives, but the Compose UI process dies and the app
    // appears to close. On real hardware this is rare, but debouncing
    // is useful UX anyway: neither start nor stop is truly instant,
    // and the user gets no feedback if they tap while one is in flight.
    var transitionCooldown by remember { mutableStateOf(false) }
    LaunchedEffect(transitionCooldown) {
        if (transitionCooldown) {
            delay(2000)
            transitionCooldown = false
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
                    append("In Settings: Encryption & credentials → Install a certificate → \"CA certificate\" (not VPN, not Wi-Fi) → pick that file.")
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
                    Text(
                        text = "v" + runCatching { Native.version() }.getOrDefault("?"),
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(end = 12.dp),
                    )
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
            SectionHeader("Apps Script relay")

            DeploymentIdsField(
                urls = cfg.appsScriptUrls,
                onChange = { persist(cfg.copy(appsScriptUrls = it)) },
            )

            OutlinedTextField(
                value = cfg.authKey,
                onValueChange = { persist(cfg.copy(authKey = it)) },
                label = { Text("auth_key") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth(),
                supportingText = {
                    Text("The shared secret you set in the Apps Script.")
                },
            )

            Spacer(Modifier.height(4.dp))
            SectionHeader("Network")

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = cfg.googleIp,
                    onValueChange = { persist(cfg.copy(googleIp = it)) },
                    label = { Text("google_ip") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = cfg.frontDomain,
                    onValueChange = { persist(cfg.copy(frontDomain = it)) },
                    label = { Text("front_domain") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.weight(1f),
                )
            }

            // SNI pool: collapsed by default. Users without a reason to
            // touch it should leave Rust's auto-expansion to handle it.
            CollapsibleSection(title = "SNI pool + tester") {
                SniPoolEditor(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            // Advanced settings: collapsed by default.
            CollapsibleSection(title = "Advanced") {
                AdvancedSettings(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            Spacer(Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = {
                        transitionCooldown = true
                        onStart()
                    },
                    enabled = cfg.hasDeploymentId && cfg.authKey.isNotBlank() && !transitionCooldown,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (transitionCooldown) "…" else "Start")
                }
                OutlinedButton(
                    onClick = {
                        transitionCooldown = true
                        onStop()
                    },
                    enabled = !transitionCooldown,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (transitionCooldown) "…" else "Stop")
                }
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
                Text("Install MITM certificate")
            }

            CollapsibleSection(title = "Live logs", initiallyExpanded = false) {
                LiveLogPane()
            }

            Spacer(Modifier.height(16.dp))
            HowToUseCard(cfg.listenPort)
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
            title = { Text("Install MITM certificate?") },
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
                        "(2) open Security settings. From there navigate to Encryption & " +
                        "credentials → Install a certificate → pick \"CA certificate\" (NOT " +
                        "\"VPN & app user certificate\" or \"Wi-Fi certificate\") → select " +
                        "mhrv-ca.crt from Downloads. If you don't have a screen lock, Android " +
                        "will ask you to add one first."
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
// Deployment IDs editor (multi-line, one URL/ID per line).
// =========================================================================

@Composable
private fun DeploymentIdsField(
    urls: List<String>,
    onChange: (List<String>) -> Unit,
) {
    // Treat the list as newline-joined text. Keep trailing newlines so the
    // cursor behaves naturally while the user is adding a new entry.
    var raw by remember(urls) { mutableStateOf(urls.joinToString("\n")) }

    OutlinedTextField(
        value = raw,
        onValueChange = {
            raw = it
            val parsed = it.split("\n").map(String::trim).filter(String::isNotBlank)
            onChange(parsed)
        },
        label = { Text("Deployment URL(s) or script ID(s)") },
        modifier = Modifier.fillMaxWidth(),
        minLines = 2,
        maxLines = 6,
        supportingText = {
            Text(
                "One per line. Full URLs (https://script.google.com/macros/s/.../exec) " +
                "or bare IDs — mix as you like. Multiple IDs are rotated round-robin.",
            )
        },
    )
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
            "Enabled SNIs are rotated when connecting to google_ip. Leaving all unchecked " +
            "lets Rust auto-expand the default Google pool.",
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
                label = { Text("Add custom SNI") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = {
                    val s = custom.trim()
                    if (s.isNotEmpty()) {
                        val next = (cfg.sniHosts.takeIf { it.isNotEmpty() } ?: enabledSet.toList()) + s
                        onChange(cfg.copy(sniHosts = next.distinct()))
                        custom = ""
                    }
                },
                enabled = custom.isNotBlank(),
            ) { Text("Add") }
        }

        TextButton(
            onClick = { displayed.forEach { probe(it) } },
            modifier = Modifier.align(Alignment.End),
        ) { Text("Test all") }
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
                Text("Test")
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
                Text("Verify upstream TLS", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Off disables cert checks for the Google edge. Only useful for debugging.",
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
                label = { Text("log_level") },
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
                "parallel_relay: ${cfg.parallelRelay}",
                style = MaterialTheme.typography.bodyMedium,
            )
            Slider(
                value = cfg.parallelRelay.toFloat(),
                onValueChange = { onChange(cfg.copy(parallelRelay = it.toInt().coerceIn(1, 5))) },
                valueRange = 1f..5f,
                steps = 3,  // yields 1,2,3,4,5 positions
            )
            Text(
                "Fan-out per request. 1 is normal; bump to 2-3 on lossy links.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        OutlinedTextField(
            value = cfg.upstreamSocks5,
            onValueChange = { onChange(cfg.copy(upstreamSocks5 = it)) },
            label = { Text("upstream_socks5 (optional)") },
            placeholder = { Text("host:port") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            supportingText = {
                Text("If set, route upstream via this SOCKS5. Leave blank for direct.")
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

@Composable
private fun HowToUseCard(listenPort: Int) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("How to use", style = MaterialTheme.typography.titleMedium)
            Text(
                "1. Paste one or more Apps Script deployment URLs (or bare IDs) and your auth_key.\n" +
                "2. Tap Install MITM certificate. Confirm the dialog — the cert is saved to " +
                "Downloads/mhrv-ca.crt and Security settings opens. Navigate: Encryption & " +
                "credentials → Install a certificate → \"CA certificate\" (NOT \"VPN & app user " +
                "certificate\" or \"Wi-Fi\"). Pick mhrv-ca.crt from Downloads. You'll be asked to " +
                "set a screen lock if you don't have one (Android requirement).\n" +
                "3. Before tapping Start, expand \"SNI pool + tester\" and hit \"Test all\". If " +
                "every entry times out, your google_ip is unreachable — replace it with one that " +
                "resolves locally (e.g. `nslookup www.google.com` on any working device).\n" +
                "4. Tap Start. Accept the VPN prompt. The full TUN bridge routes every app on the " +
                "device through the proxy — no per-app setup needed.\n" +
                "5. If Chrome shows \"504 Relay timeout\": your Apps Script deployment isn't " +
                "responding. Redeploy the script, grab the new /exec URL, and paste it above. " +
                "Watch Live logs for \"Relay timeout\" vs \"connect:\" errors to tell which layer " +
                "is failing.\n" +
                "\n" +
                "Known limitation — Cloudflare Turnstile (\"Verify you are human\") will loop " +
                "endlessly on most CF-protected sites. Every Apps Script request uses a rotating " +
                "Google-datacenter egress IP + a fixed \"Google-Apps-Script\" User-Agent + a " +
                "Google TLS fingerprint. The cf_clearance cookie is bound to the (IP, UA, JA3) " +
                "tuple the challenge was solved against, so the NEXT request — from a different " +
                "egress IP — gets re-challenged. Nothing in this app can fix that; it's inherent " +
                "to Apps Script as a relay. Sites that only gate the initial page load (not every " +
                "request) will work after one solve.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
