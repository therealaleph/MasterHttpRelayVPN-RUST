package com.therealaleph.mhrv.ui

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * A bottom-sheet-style dialog for picking apps by package name. Used by
 * the App-splitting section to seed the allow-list or the deny-list.
 *
 * Design:
 *   - Lists every user-installed app (system apps filtered by default —
 *     they're rarely what you want to single out, and the list would be
 *     overwhelming without filtering). A "Show system apps" toggle at
 *     the top brings them back.
 *   - Search bar filters by label + package name substring.
 *   - Multi-select via Checkbox per row; a running counter at the top
 *     reminds the user how many packages are currently selected.
 *   - Save returns the chosen package-name list; Cancel is a no-op.
 *
 * Dismissing the dialog (back-press / scrim tap) is treated as Cancel —
 * we never silently overwrite the caller's selection with a partial
 * in-flight edit.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun AppPickerDialog(
    initial: Set<String>,
    ownPackage: String,
    onSave: (List<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val ctx = LocalContext.current

    // Load installed-app metadata off the main thread — PackageManager
    // queries can be slow on devices with 400+ apps.
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var showSystem by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    val selected = remember { mutableStateListOf<String>().apply { addAll(initial) } }

    LaunchedEffect(showSystem) {
        loading = true
        apps = withContext(Dispatchers.IO) {
            loadInstalledApps(ctx.packageManager, includeSystem = showSystem, ownPackage = ownPackage)
        }
        loading = false
    }

    val filtered: List<AppEntry> = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter {
            it.label.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Pick apps (${selected.size} selected)") },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Search") },
                    singleLine = true,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        imeAction = ImeAction.Search,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                ) {
                    Checkbox(
                        checked = showSystem,
                        onCheckedChange = { showSystem = it },
                    )
                    Text("Show system apps", style = MaterialTheme.typography.bodySmall)
                }
                if (loading) {
                    Box(
                        modifier = Modifier.fillMaxWidth().height(160.dp),
                        contentAlignment = Alignment.Center,
                    ) { CircularProgressIndicator() }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxWidth().heightIn(min = 240.dp, max = 420.dp),
                    ) {
                        items(filtered, key = { it.packageName }) { entry ->
                            AppRow(
                                entry = entry,
                                checked = entry.packageName in selected,
                                onCheck = { now ->
                                    if (now) {
                                        if (entry.packageName !in selected) {
                                            selected.add(entry.packageName)
                                        }
                                    } else {
                                        selected.remove(entry.packageName)
                                    }
                                },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(selected.toList()) }) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun AppRow(entry: AppEntry, checked: Boolean, onCheck: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheck)
        Spacer(Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(entry.label, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            Text(
                entry.packageName,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
    }
}

private data class AppEntry(val packageName: String, val label: String)

private fun loadInstalledApps(
    pm: PackageManager,
    includeSystem: Boolean,
    ownPackage: String,
): List<AppEntry> {
    // Only apps that have a launcher entry are user-visible — the rest
    // are content providers, platform helpers, etc. that the user would
    // never want to manually include/exclude.
    val mainIntent = android.content.Intent(android.content.Intent.ACTION_MAIN)
        .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
    val resolved = pm.queryIntentActivities(mainIntent, 0)
    return resolved
        .asSequence()
        .mapNotNull { it.activityInfo?.applicationInfo }
        .filter { info ->
            // Our own package is handled by the mandatory self-exclude
            // at service-start time; surfacing it in the picker would be
            // confusing and a selection would be silently overridden.
            if (info.packageName == ownPackage) return@filter false
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            includeSystem || !isSystem
        }
        .distinctBy { it.packageName }
        .map { info ->
            AppEntry(
                packageName = info.packageName,
                label = pm.getApplicationLabel(info).toString(),
            )
        }
        .sortedBy { it.label.lowercase() }
        .toList()
}
