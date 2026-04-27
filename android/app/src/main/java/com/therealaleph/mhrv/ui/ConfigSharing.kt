package com.therealaleph.mhrv.ui

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.therealaleph.mhrv.ConfigStore
import com.therealaleph.mhrv.MhrvConfig
import androidx.compose.foundation.text.selection.SelectionContainer
import com.therealaleph.mhrv.R
import kotlinx.coroutines.launch

// =========================================================================
// Import/Export bar — shown at the top of the config screen.
// =========================================================================

@Composable
fun ConfigSharingBar(
    cfg: MhrvConfig,
    onImport: (MhrvConfig) -> Unit,
    onSnackbar: suspend (String) -> Unit,
) {
    // Deep link import — requires confirmation before applying.
    val deepLinkCfg by com.therealaleph.mhrv.MainActivity.pendingDeepLinkConfig
    if (deepLinkCfg != null) {
        ImportConfirmDialog(
            cfg = deepLinkCfg!!,
            onConfirm = {
                onImport(deepLinkCfg!!)
                com.therealaleph.mhrv.MainActivity.pendingDeepLinkConfig.value = null
            },
            onDismiss = {
                com.therealaleph.mhrv.MainActivity.pendingDeepLinkConfig.value = null
            },
        )
    }
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    val clipText = clipboard.getText()?.text.orEmpty()
    val hasConfigInClipboard = clipText.isNotEmpty() && ConfigStore.looksLikeConfig(clipText)

    var showExportDialog by remember { mutableStateOf(false) }
    var showImportConfirm by remember { mutableStateOf(false) }
    var pendingImport by remember { mutableStateOf<MhrvConfig?>(null) }
    var showQrDialog by remember { mutableStateOf(false) }

    // QR scanner launcher — fires the ZXing embedded scanner activity.
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scanned = result.contents ?: return@rememberLauncherForActivityResult
        val decoded = ConfigStore.decode(scanned)
        if (decoded != null) {
            pendingImport = decoded
            showImportConfirm = true
        } else {
            scope.launch { onSnackbar(ctx.getString(R.string.snack_invalid_config)) }
        }
    }

    // --- Paste from clipboard banner ---
    if (hasConfigInClipboard) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
            ),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "Config detected in clipboard",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.weight(1f),
                )
                FilledTonalButton(
                    onClick = {
                        val decoded = ConfigStore.decode(clipText)
                        if (decoded != null) {
                            pendingImport = decoded
                            showImportConfirm = true
                        } else {
                            scope.launch { onSnackbar(ctx.getString(R.string.snack_invalid_config)) }
                        }
                    },
                ) {
                    Icon(Icons.Default.ContentPaste, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.btn_import_clipboard))
                }
            }
        }
    }

    // --- Export + Scan row ---
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = { showExportDialog = true },
            modifier = Modifier.weight(1f),
        ) {
            Icon(Icons.Default.Share, null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text(stringResource(R.string.btn_export_config))
        }
        OutlinedButton(
            onClick = {
                val opts = ScanOptions().apply {
                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    setPrompt("Scan mhrv config QR code")
                    setBeepEnabled(false)
                    setOrientationLocked(true)
                }
                scanLauncher.launch(opts)
            },
        ) {
            Icon(Icons.Default.QrCodeScanner, null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text(stringResource(R.string.btn_scan_qr))
        }
    }

    // --- Export dialog (QR + hash + copy in one) ---
    if (showExportDialog) {
        val encoded = remember(cfg) { ConfigStore.encode(cfg) }
        val qrBitmap = remember(encoded) { generateQr(encoded, 512) }
        Dialog(onDismissRequest = { showExportDialog = false }) {
            Card(modifier = Modifier.padding(16.dp)) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        stringResource(R.string.dialog_export_title),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        stringResource(R.string.dialog_export_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )

                    // QR code
                    if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR code",
                            modifier = Modifier.size(260.dp),
                        )
                    } else {
                        Text(
                            "Config too large for QR code",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    // Hash with copy button
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        SelectionContainer(modifier = Modifier.weight(1f)) {
                            Text(
                                encoded,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            )
                        }
                        IconButton(onClick = {
                            clipboard.setText(AnnotatedString(encoded))
                            scope.launch { onSnackbar(ctx.getString(R.string.snack_config_copied)) }
                        }) {
                            Icon(
                                Icons.Default.ContentPaste,
                                contentDescription = stringResource(R.string.btn_copy),
                                modifier = Modifier.size(20.dp),
                            )
                        }
                    }

                    // Action buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                    ) {
                        OutlinedButton(onClick = {
                            // Save QR bitmap to cache dir and share both image + text.
                            val intent = if (qrBitmap != null) {
                                val file = java.io.File(ctx.cacheDir, "mhrv-config-qr.png")
                                file.outputStream().use { qrBitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
                                val uri = androidx.core.content.FileProvider.getUriForFile(
                                    ctx, "${ctx.packageName}.fileprovider", file
                                )
                                android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "image/png"
                                    putExtra(android.content.Intent.EXTRA_STREAM, uri)
                                    putExtra(android.content.Intent.EXTRA_TEXT, encoded)
                                    addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                            } else {
                                android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(android.content.Intent.EXTRA_TEXT, encoded)
                                }
                            }
                            ctx.startActivity(android.content.Intent.createChooser(intent, "Share config"))
                        }) {
                            Icon(Icons.Default.Share, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Share")
                        }
                        TextButton(onClick = { showExportDialog = false }) {
                            Text("Close")
                        }
                    }
                }
            }
        }
    }

    // --- Import confirmation dialog (clipboard + QR scan) ---
    if (showImportConfirm && pendingImport != null) {
        ImportConfirmDialog(
            cfg = pendingImport!!,
            onConfirm = {
                onImport(pendingImport!!)
                clipboard.setText(AnnotatedString(""))
                showImportConfirm = false
                pendingImport = null
                scope.launch { onSnackbar(ctx.getString(R.string.snack_config_imported)) }
            },
            onDismiss = {
                showImportConfirm = false
                pendingImport = null
            },
        )
    }
}

// =========================================================================
// Import confirmation dialog — shared by clipboard, QR scan, and deep link.
// Shows deployment IDs, mode, and a trust warning before overwriting config.
// =========================================================================

@Composable
private fun ImportConfirmDialog(
    cfg: MhrvConfig,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val ids = cfg.appsScriptUrls.mapNotNull { url ->
        val marker = "/macros/s/"
        val i = url.indexOf(marker)
        val raw = if (i >= 0) url.substring(i + marker.length).substringBefore("/") else url
        raw.trim().takeIf { it.isNotEmpty() }
    }
    val preview = ids.take(3).joinToString("\n") { "  ${it.take(20)}…" }
    val modeLabel = when (cfg.mode) {
        com.therealaleph.mhrv.Mode.APPS_SCRIPT -> "apps_script"
        com.therealaleph.mhrv.Mode.GOOGLE_ONLY -> "google_only"
        com.therealaleph.mhrv.Mode.FULL -> "full"
        com.therealaleph.mhrv.Mode.GOOGLE_DRIVE -> "google_drive"
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.dialog_import_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Importing routes your traffic through the deployment IDs in this config. Only import from trusted sources.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Text(
                    "Mode: $modeLabel\nDeployments: ${ids.size}\n$preview",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    stringResource(R.string.dialog_import_body),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text("Import") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) }
        },
    )
}

// =========================================================================
// QR code generation
// =========================================================================

private fun generateQr(content: String, size: Int): Bitmap? {
    return try {
        val writer = QRCodeWriter()
        val matrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bitmap.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        bitmap
    } catch (_: Throwable) {
        null // Config too large for QR
    }
}

