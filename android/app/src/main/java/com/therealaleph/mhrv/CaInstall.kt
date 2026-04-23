package com.therealaleph.mhrv

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.Settings
import android.security.KeyChain
import android.util.Base64
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory

/**
 * Helpers for the MITM-CA install UX.
 *
 * The flow has three steps:
 *   1. `export()` — copy the CA cert from the Rust-managed dir
 *      (`<filesDir>/ca/ca.crt`) to a stable location (`<filesDir>/ca.crt`)
 *      the UI can hand to Android's system picker.
 *   2. `buildInstallIntent()` — build a `KeyChain.createInstallIntent` loaded
 *      with the cert's DER bytes. Passing the bytes via `EXTRA_CERTIFICATE`
 *      is cleaner than handing Android a file Uri: no content-provider
 *      plumbing, no external-storage permission, and Android resolves the
 *      "VPN and apps" / "Wi-Fi" category on its own.
 *   3. `isInstalled()` — after the system dialog returns we can't rely on
 *      the `resultCode` (Android 11+ opens a Settings activity that always
 *      returns `RESULT_CANCELED`), so we walk `AndroidCAStore` looking for
 *      a cert whose SHA-256 fingerprint matches ours. That keystore spans
 *      both system and user-installed CAs, so it's the ground truth.
 */
object CaInstall {
    private const val CA_FILENAME = "ca.crt"
    private const val CA_FRIENDLY_NAME = "mhrv-rs MITM CA"

    /** Stable path where the UI stages the exported CA. */
    fun caFile(ctx: Context): File = File(ctx.filesDir, CA_FILENAME)

    /**
     * Copy the current Rust-side CA cert to a UI-accessible path.
     * Returns true only if the file exists and is non-empty on return —
     * Native.exportCa is supposed to do that, but we re-check because a
     * truncated write would make the install dialog look empty and the
     * user would have no idea why.
     */
    fun export(ctx: Context): Boolean {
        val dest = caFile(ctx)
        if (!Native.exportCa(dest.absolutePath)) return false
        return dest.exists() && dest.length() > 0
    }

    /** DER-encoded bytes of the exported CA, or null if export hasn't run. */
    fun readDer(ctx: Context): ByteArray? {
        val f = caFile(ctx)
        if (!f.exists()) return null
        val raw = try { f.readBytes() } catch (_: Throwable) { return null }
        return pemToDer(raw) ?: raw  // fall back to treating it as DER
    }

    /** SHA-256 fingerprint of the CA cert (over DER bytes). */
    fun fingerprint(ctx: Context): ByteArray? {
        val der = readDer(ctx) ?: return null
        return sha256(der)
    }

    /** Pretty-print a fingerprint like "AA:BB:CC:...". */
    fun fingerprintHex(bytes: ByteArray): String =
        bytes.joinToString(":") { "%02X".format(it) }

    /**
     * Build the KeyChain install intent. The intent launches the system
     * certificate picker pre-loaded with our cert — the user confirms a
     * category (for modern Android that's "VPN and apps" or "Wi-Fi") and
     * gives it a display name.
     */
    fun buildInstallIntent(ctx: Context): Intent? {
        val der = readDer(ctx) ?: return null
        return KeyChain.createInstallIntent()
            .putExtra(KeyChain.EXTRA_CERTIFICATE, der)
            .putExtra(KeyChain.EXTRA_NAME, CA_FRIENDLY_NAME)
    }

    /**
     * Save a PEM copy of the CA to the user's Downloads folder so they
     * can find it in the Files app and pick it from Settings →
     * Encryption & credentials → Install a certificate → CA certificate.
     *
     * On Android 10+ (API 29) this goes through MediaStore so we don't need
     * WRITE_EXTERNAL_STORAGE. On older Android we fall back to the app's
     * external files dir — visible via Files app but not in the system
     * Downloads collection, so the user needs to navigate to
     * `Android/data/<pkg>/files/Download/` themselves.
     *
     * Returns a human-readable location string ("Downloads/mhrv-ca.crt" or
     * the filesystem path) on success, null on failure.
     */
    fun saveToDownloads(ctx: Context, displayName: String = "mhrv-ca.crt"): String? {
        val der = readDer(ctx) ?: return null
        // Rewrap as PEM so users can open the file in a text editor and
        // verify it's a cert before trusting it — also, the system cert
        // installer expects PEM or DER but PEM is the more common form
        // for user-visible files.
        val pem = derToPem(der)

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            saveViaMediaStore(ctx, displayName, pem)?.let { "Downloads/$displayName" }
        } else {
            // Pre-Q fallback: app-private external storage. Does NOT require
            // a storage permission. Less discoverable for the user, but
            // dodging the runtime-permission dance is worth it here — we
            // can still deep-link Settings and tell them the path.
            try {
                val dir = ctx.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: return null
                dir.mkdirs()
                val f = File(dir, displayName)
                f.writeBytes(pem)
                f.absolutePath
            } catch (_: Throwable) { null }
        }
    }

    private fun saveViaMediaStore(ctx: Context, displayName: String, bytes: ByteArray): Boolean? {
        val resolver = ctx.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
            put(MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
        }
        // Delete any previous copy with the same name before inserting, so
        // we don't accumulate `mhrv-ca (1).crt`, `mhrv-ca (2).crt` on repeat
        // installs (MediaStore appends suffixes instead of overwriting).
        try {
            val sel = "${MediaStore.MediaColumns.DISPLAY_NAME}=?"
            resolver.delete(MediaStore.Downloads.EXTERNAL_CONTENT_URI, sel, arrayOf(displayName))
        } catch (_: Throwable) { /* best-effort */ }

        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return null
        return try {
            resolver.openOutputStream(uri)?.use { it.write(bytes) } ?: return null
            true
        } catch (_: Throwable) { null }
    }

    /**
     * Intent that opens the TOP-LEVEL system Settings app. The Settings
     * search bar is the most portable way to get users to the CA-install
     * screen across OEMs — every Android vendor ships the CA install
     * flow under a subtly different menu path (Encryption & credentials,
     * Other security settings, Privacy → Credentials, etc.), but they
     * all respond to a search for "CA certificate".
     *
     * Earlier versions used `Settings.ACTION_SECURITY_SETTINGS` which
     * landed on Security & privacy directly, but on some OEMs (Samsung,
     * Xiaomi, newer Pixel builds) that screen doesn't have the cert
     * install entry one tap away and users got stuck. Top-level Settings
     * + "search for CA certificate" is the instruction that actually
     * works everywhere.
     *
     * We DO NOT use KeyChain.createInstallIntent — on Android 11+ that
     * intent opens a dialog that just says "Install CA certificates in
     * Settings" with a Close button and no forward path. Google
     * intentionally removed the inline install flow in that release.
     */
    fun buildSettingsIntent(): Intent = Intent(Settings.ACTION_SETTINGS)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * True iff a CA with this SHA-256 fingerprint lives in the
     * AndroidCAStore (union of system + user-installed CAs). This is how
     * we verify install success because the picker activity's result code
     * is not reliable across Android versions.
     */
    fun isInstalled(targetFingerprint: ByteArray): Boolean {
        return try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val cert = ks.getCertificate(alias) ?: continue
                val encoded = try { cert.encoded } catch (_: Throwable) { continue }
                if (sha256(encoded).contentEquals(targetFingerprint)) return true
            }
            false
        } catch (_: Throwable) { false }
    }

    /** Subject CN of the exported CA, for display. */
    fun subjectCn(ctx: Context): String? {
        val der = readDer(ctx) ?: return null
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(der.inputStream()) as java.security.cert.X509Certificate
            val dn = cert.subjectX500Principal.name  // RFC 2253, CN=foo,O=bar
            Regex("""CN=([^,]+)""").find(dn)?.groupValues?.get(1)
        } catch (_: Throwable) { null }
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Rewrap DER bytes as PEM. We intentionally produce a textual cert —
     * the user can `cat` it, the Settings cert picker accepts it, and it
     * survives any copy/paste or email round-trip without binary mangling.
     */
    private fun derToPem(der: ByteArray): ByteArray {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        val chunks = b64.chunked(64).joinToString("\n")
        val s = "-----BEGIN CERTIFICATE-----\n$chunks\n-----END CERTIFICATE-----\n"
        return s.toByteArray(Charsets.US_ASCII)
    }

    /**
     * Accept either DER or PEM bytes; return DER. PEM files carry a base64
     * payload between -----BEGIN CERTIFICATE----- markers.
     */
    private fun pemToDer(bytes: ByteArray): ByteArray? {
        val s = try { bytes.toString(Charsets.US_ASCII) } catch (_: Throwable) { return null }
        if (!s.contains("BEGIN CERTIFICATE")) return null  // caller falls back to treating as DER
        val body = s
            .substringAfter("-----BEGIN CERTIFICATE-----", "")
            .substringBefore("-----END CERTIFICATE-----", "")
            .replace(Regex("\\s+"), "")
        if (body.isEmpty()) return null
        return try { Base64.decode(body, Base64.DEFAULT) } catch (_: Throwable) { null }
    }
}
