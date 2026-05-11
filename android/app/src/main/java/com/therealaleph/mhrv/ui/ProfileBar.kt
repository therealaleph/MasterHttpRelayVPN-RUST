package com.therealaleph.mhrv.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.therealaleph.mhrv.MhrvConfig
import com.therealaleph.mhrv.ProfileStore
import com.therealaleph.mhrv.R
import com.therealaleph.mhrv.UiLang
import com.therealaleph.mhrv.VpnState
import kotlinx.coroutines.launch

/**
 * Profile bar shown at the top of the config screen, between the
 * import/export bar and the mode selector.
 *
 * Three actions:
 *   - **Selector**: dropdown listing every saved profile; tap one to
 *     switch the live config to it.
 *   - **Save as profile**: capture the current form under a name.
 *   - **Manage**: rename / duplicate / delete saved profiles.
 *
 * Switching a profile rewrites `config.json` to the snapshot (raw — no
 * round-trip through MhrvConfig, so unknown fields survive) and
 * triggers [onConfigChange] so the parent screen reloads its `cfg`
 * state from disk. If the new profile has a different `ui_lang`,
 * [onLangChange] is fired so the activity recreates with the right
 * locale, matching the top-bar language toggle.
 *
 * Profile switching is disabled while the VPN is running — the running
 * service still holds the old config until Disconnect/Connect, so
 * swapping the live `config.json` underneath would be a footgun.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileBar(
    cfg: MhrvConfig,
    onConfigChange: (MhrvConfig) -> Unit,
    onLangChange: (UiLang) -> Unit,
    onSnackbar: suspend (String) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val isVpnRunning by VpnState.isRunning.collectAsState()

    // Bump this counter to force a re-read of the profiles file when
    // a profile action mutates it. We ALSO re-key the state read on
    // `cfg` so that field edits flowing through HomeScreen.persist()
    // (which calls ProfileStore.clearActiveIfAny) cause the bar to
    // pick up the cleared `active` immediately — otherwise the UI
    // keeps claiming the old profile is active even though the live
    // config no longer matches.
    //
    // We use loadStrict() (not load()) so a corrupt profiles.json
    // surfaces loudly via a banner instead of being flattened into
    // an empty state — the "load failure is loud" invariant.
    var refresh by remember { mutableIntStateOf(0) }
    val loadResult = remember(refresh, cfg) { ProfileStore.loadStrict(ctx) }
    val state = when (loadResult) {
        is ProfileStore.LoadResult.Ok -> loadResult.state
        is ProfileStore.LoadResult.Missing -> loadResult.state
        is ProfileStore.LoadResult.Corrupt ->
            // Fall through to empty for the selector — we'll show a
            // corruption banner below so the user knows what's going
            // on. We still gate writes via the existing CorruptOnDisk
            // MutationResult so we never clobber the bad file.
            ProfileStore.State(active = "", profiles = emptyList())
    }
    val corrupt = loadResult is ProfileStore.LoadResult.Corrupt

    var menuOpen by remember { mutableStateOf(false) }
    var showSaveDialog by remember { mutableStateOf(false) }
    var showManageDialog by remember { mutableStateOf(false) }

    val activePrefix = stringResource(R.string.profile_active_prefix)
    val none = stringResource(R.string.profile_none)
    val noSavedLabel = stringResource(R.string.profile_no_saved)
    val switchBlockedMsg = stringResource(R.string.snack_profile_switch_blocked_running)

    if (corrupt) {
        // Loud corruption banner. Sits above the selector so the
        // user sees it before tapping anything, and the existing
        // CorruptOnDisk mutation gate prevents accidental overwrite.
        Text(
            text = stringResource(R.string.profile_err_corrupt_on_disk),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Selector — wrap so the dropdown anchors under the button.
        // Stays enabled while the VPN is running: the click handler
        // shows a snackbar explaining why switching takes effect on
        // the next Connect rather than going dark and silent.
        Box(modifier = Modifier.weight(1f)) {
            OutlinedButton(
                onClick = {
                    if (isVpnRunning) {
                        scope.launch { onSnackbar(switchBlockedMsg) }
                    } else {
                        menuOpen = true
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Folder, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    text = "$activePrefix ${if (state.active.isBlank()) none else state.active}",
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Spacer(Modifier.width(4.dp))
                Icon(Icons.Default.ArrowDropDown, null, modifier = Modifier.size(18.dp))
            }
            DropdownMenu(
                expanded = menuOpen,
                onDismissRequest = { menuOpen = false },
            ) {
                if (state.profiles.isEmpty()) {
                    DropdownMenuItem(
                        text = { Text(noSavedLabel, style = MaterialTheme.typography.bodySmall) },
                        onClick = { menuOpen = false },
                        enabled = false,
                    )
                } else {
                    for (p in state.profiles) {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = if (p.name == state.active) "● ${p.name}" else "  ${p.name}",
                                )
                            },
                            onClick = {
                                menuOpen = false
                                scope.launch {
                                    when (val r = ProfileStore.applyProfile(ctx, p.name)) {
                                        is ProfileStore.ApplyResult.Ok -> {
                                            // Locale change path mirrors the
                                            // top-bar toggle so RTL/LTR flips
                                            // and the activity recreates.
                                            if (r.cfg.uiLang != cfg.uiLang) {
                                                onLangChange(r.cfg.uiLang)
                                            }
                                            onConfigChange(r.cfg)
                                            refresh++
                                            onSnackbar(ctx.getString(
                                                R.string.snack_profile_switched, p.name))
                                        }
                                        is ProfileStore.ApplyResult.PartialConfigOnly -> {
                                            // Live config IS the new profile —
                                            // reload the form — but tell the
                                            // user the dropdown's active
                                            // marker on disk is stale.
                                            if (r.cfg.uiLang != cfg.uiLang) {
                                                onLangChange(r.cfg.uiLang)
                                            }
                                            onConfigChange(r.cfg)
                                            refresh++
                                            onSnackbar(ctx.getString(
                                                R.string.snack_profile_switched_partial, p.name))
                                        }
                                        is ProfileStore.ApplyResult.NotFound,
                                        is ProfileStore.ApplyResult.Failed -> {
                                            onSnackbar(ctx.getString(
                                                R.string.snack_profile_switch_failed, p.name))
                                        }
                                    }
                                }
                            },
                        )
                    }
                }
            }
        }

        IconButton(
            onClick = { showSaveDialog = true },
        ) {
            Icon(
                Icons.Default.BookmarkAdd,
                contentDescription = stringResource(R.string.btn_save_as_profile),
            )
        }
    }

    if (showSaveDialog) {
        SaveAsProfileDialog(
            cfg = cfg,
            existingNames = state.names(),
            onDismiss = { showSaveDialog = false },
            onSaved = { name ->
                scope.launch {
                    refresh++
                    onSnackbar(ctx.getString(R.string.snack_profile_saved, name))
                }
                showSaveDialog = false
            },
        )
    }

    // "Manage" sits under the selector — surfacing it as a row below so
    // it's discoverable without long-press on the dropdown.
    if (state.profiles.isNotEmpty()) {
        TextButton(onClick = { showManageDialog = true }) {
            Text(
                stringResource(R.string.btn_manage_profiles),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }

    if (showManageDialog) {
        ManageProfilesDialog(
            state = state,
            onMutated = { refresh++ },
            onDismiss = { showManageDialog = false },
        )
    }
}

@Composable
private fun SaveAsProfileDialog(
    cfg: MhrvConfig,
    existingNames: List<String>,
    onDismiss: () -> Unit,
    onSaved: (String) -> Unit,
) {
    val ctx = LocalContext.current
    var name by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val trimmed = name.trim()
    val exists = trimmed.isNotEmpty() && existingNames.contains(trimmed)

    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.padding(16.dp)) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(R.string.dialog_save_profile_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                OutlinedTextField(
                    value = name,
                    onValueChange = {
                        name = it
                        error = null
                    },
                    label = { Text(stringResource(R.string.field_profile_name)) },
                    placeholder = { Text(stringResource(R.string.placeholder_profile_name)) },
                    singleLine = true,
                    isError = error != null,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) {
                    Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (exists) {
                    Text(
                        stringResource(R.string.profile_overwrite_warning, trimmed),
                        color = MaterialTheme.colorScheme.tertiary,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onDismiss) {
                        Text(stringResource(R.string.btn_cancel))
                    }
                    Button(
                        enabled = trimmed.isNotEmpty(),
                        onClick = {
                            val result = if (exists) {
                                ProfileStore.upsert(ctx, trimmed, cfg)
                            } else {
                                ProfileStore.insertNew(ctx, trimmed, cfg)
                            }
                            when (result) {
                                ProfileStore.MutationResult.Ok -> onSaved(trimmed)
                                ProfileStore.MutationResult.PartialConfigOnly -> {
                                    // config.json was written (live
                                    // config IS the new form bytes,
                                    // equivalent to a regular Save)
                                    // but the profiles.json write
                                    // failed, so no profile entry
                                    // was created/updated. User can
                                    // retry to capture the profile.
                                    error = ctx.getString(R.string.profile_err_partial_config_only)
                                }
                                ProfileStore.MutationResult.Duplicate,
                                ProfileStore.MutationResult.EmptyName,
                                ProfileStore.MutationResult.NotFound,
                                ProfileStore.MutationResult.SaveFailed ->
                                    error = ctx.getString(R.string.profile_err_save_failed)
                                is ProfileStore.MutationResult.CorruptOnDisk ->
                                    error = ctx.getString(R.string.profile_err_corrupt_on_disk)
                            }
                        },
                    ) {
                        Text(
                            stringResource(
                                if (exists) R.string.btn_overwrite else R.string.btn_save
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ManageProfilesDialog(
    state: ProfileStore.State,
    onMutated: () -> Unit,
    onDismiss: () -> Unit,
) {
    val ctx = LocalContext.current
    var renamingName by remember { mutableStateOf<String?>(null) }
    var renameBuf by remember { mutableStateOf("") }
    var pendingDeleteName by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun applyResult(
        result: ProfileStore.MutationResult,
        fallbackErrKey: Int,
        onOk: () -> Unit = {},
    ) {
        when (result) {
            ProfileStore.MutationResult.Ok -> {
                error = null
                onOk()
                onMutated()
            }
            is ProfileStore.MutationResult.CorruptOnDisk ->
                error = ctx.getString(R.string.profile_err_corrupt_on_disk)
            else -> error = ctx.getString(fallbackErrKey)
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.padding(16.dp)) {
            Column(
                // Cap the dialog height so 20+ profiles don't push the
                // Close button off-screen; the inner list scrolls.
                modifier = Modifier
                    .padding(20.dp)
                    .heightIn(max = 480.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    stringResource(R.string.dialog_manage_profiles_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                if (error != null) {
                    Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (state.profiles.isEmpty()) {
                    Text(
                        stringResource(R.string.profile_no_saved),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                // Scroll the profile list, not the whole dialog —
                // keeps the Close row pinned to the bottom.
                val scroll = rememberScrollState()
                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(scroll),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                for (p in state.profiles) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        val isActive = p.name == state.active
                        Text(
                            if (isActive) "●" else "  ",
                            color = if (isActive) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.width(16.dp),
                        )
                        if (renamingName == p.name) {
                            OutlinedTextField(
                                value = renameBuf,
                                onValueChange = { renameBuf = it },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = {
                                applyResult(
                                    ProfileStore.rename(ctx, p.name, renameBuf),
                                    R.string.profile_err_rename_failed,
                                    onOk = {
                                        renamingName = null
                                        renameBuf = ""
                                    },
                                )
                            }) { Text(stringResource(R.string.btn_ok)) }
                            TextButton(onClick = {
                                renamingName = null
                                renameBuf = ""
                                error = null
                            }) { Text(stringResource(R.string.btn_cancel)) }
                        } else if (pendingDeleteName == p.name) {
                            // Two-step delete: profile data may be the
                            // user's only saved copy, so we don't take
                            // it out on a single accidental tap.
                            Text(
                                text = stringResource(R.string.confirm_delete_profile, p.name),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f),
                            )
                            Button(
                                onClick = {
                                    applyResult(
                                        ProfileStore.delete(ctx, p.name),
                                        R.string.profile_err_delete_failed,
                                        onOk = { pendingDeleteName = null },
                                    )
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.error,
                                    contentColor = MaterialTheme.colorScheme.onError,
                                ),
                            ) { Text(stringResource(R.string.btn_confirm_delete)) }
                            TextButton(onClick = {
                                pendingDeleteName = null
                                error = null
                            }) { Text(stringResource(R.string.btn_cancel)) }
                        } else {
                            Text(
                                p.name,
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = {
                                renamingName = p.name
                                renameBuf = p.name
                                error = null
                            }) { Text(stringResource(R.string.btn_rename)) }
                            TextButton(onClick = {
                                val target = ProfileStore.uniqueCopyName(state, p.name)
                                applyResult(
                                    ProfileStore.duplicate(ctx, p.name, target),
                                    R.string.profile_err_duplicate_failed,
                                )
                            }) { Text(stringResource(R.string.btn_duplicate)) }
                            TextButton(onClick = {
                                // Arm the confirm row instead of deleting.
                                pendingDeleteName = p.name
                                error = null
                            }) { Text(stringResource(R.string.btn_delete)) }
                        }
                    }
                }
                } // end scrolling Column
                Row {
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onDismiss) {
                        Text(stringResource(R.string.btn_close))
                    }
                }
            }
        }
    }
}
