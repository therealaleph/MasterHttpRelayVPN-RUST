package com.therealaleph.mhrv

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Profile storage. A profile is a named, complete snapshot of the user's
 * config (deployment IDs, mode, auth key, tuning knobs — everything that
 * lives in `config.json`). The Rust runtime keeps reading the single
 * `config.json`; profiles are a UI-only convenience that lets the user
 * keep several setups side by side (e.g. one Apps Script profile and
 * one Full tunnel profile) and switch between them without re-typing.
 *
 * Mirror of `src/profiles.rs` on the Rust desktop side. The on-disk
 * shape is intentionally identical so a profiles.json from desktop is
 * importable into Android by file copy (and vice versa).
 *
 * # Invariants (must match Rust side, see `src/profiles.rs`)
 *
 *  1. **Raw snapshot preservation.** A profile's `config` is stored as
 *     the raw JSON object exactly as it was written. Switching a profile
 *     writes that raw JSON to `config.json` byte-for-byte (subject to
 *     pretty-print) — any config fields this build doesn't model (e.g.
 *     `fronting_groups`, `exit_node`, `request_timeout_secs`) must
 *     round-trip without loss. NEVER pass the snapshot through
 *     `MhrvConfig` parse + `toJson()` on the apply path; that drops
 *     unknown fields silently.
 *
 *  2. **`active` means "matches the live config".** `active = "name"`
 *     promises that `profiles[name].config` equals the current
 *     `config.json`. Any operation that breaks that promise must set
 *     `active = ""`. In particular: deleting the active profile sets
 *     active="" (we don't auto-apply some other profile, which would
 *     silently rewrite the user's live config).
 *
 *  3. **Persist before in-memory state changes.** Always write to disk
 *     first, only update caller-visible state on success. Otherwise a
 *     failed write leaves the UI showing state that disappears on
 *     restart.
 *
 *  4. **Load failure is loud.** A file that exists but won't parse is
 *     NOT the same as a missing file. We surface the distinction so the
 *     UI can refuse to clobber a corrupted-but-recoverable
 *     profiles.json with an empty one.
 */

data class Profile(
    val name: String,
    /** Raw config JSON object — kept as a string so unknown fields
     *  round-trip even when this build doesn't know about them. */
    val configJson: String,
)

object ProfileStore {
    private const val FILE = "profiles.json"

    /** In-memory view of the profiles file. */
    data class State(
        val active: String,
        val profiles: List<Profile>,
    ) {
        fun find(name: String): Profile? = profiles.firstOrNull { it.name == name }
        fun names(): List<String> = profiles.map { it.name }
    }

    /**
     * Distinguishes "no profiles file yet" from "file present but
     * unreadable / unparseable". The unreadable case must NOT be
     * silently flattened to empty — the next save would clobber the
     * user's recoverable data with an empty file.
     */
    sealed class LoadResult {
        data class Ok(val state: State) : LoadResult()
        data class Missing(val state: State) : LoadResult()
        data class Corrupt(val raw: String?, val cause: Throwable) : LoadResult()
    }

    /** Strict load: distinguishes missing vs unreadable vs parsed. */
    fun loadStrict(ctx: Context): LoadResult {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) {
            return LoadResult.Missing(State(active = "", profiles = emptyList()))
        }
        val text = try {
            f.readText()
        } catch (e: Throwable) {
            return LoadResult.Corrupt(raw = null, cause = e)
        }
        if (text.isBlank()) {
            return LoadResult.Ok(State(active = "", profiles = emptyList()))
        }
        return try {
            LoadResult.Ok(parse(text))
        } catch (e: Throwable) {
            LoadResult.Corrupt(raw = text, cause = e)
        }
    }

    /**
     * Convenience load: returns an empty state for both "missing" AND
     * "corrupt". Callers that don't care about the difference (e.g.
     * read-only reads inside a click handler) can use this; callers
     * that are about to write should use [loadStrict] and refuse to
     * save over a corrupt file.
     */
    fun load(ctx: Context): State = when (val r = loadStrict(ctx)) {
        is LoadResult.Ok -> r.state
        is LoadResult.Missing -> r.state
        is LoadResult.Corrupt -> State(active = "", profiles = emptyList())
    }

    /**
     * Save the in-memory state. Returns true on success.
     *
     * Atomicity strategy:
     *   - Write to `profiles.json.tmp`.
     *   - On API 26+ use [java.nio.file.Files.move] with
     *     `REPLACE_EXISTING` for a true atomic replace.
     *   - On older Android (24/25 — we minSdk=24) fall back to a
     *     backup-and-restore pattern: rename target → .bak, rename
     *     tmp → target, delete .bak; if the second rename fails,
     *     restore .bak → target.
     *
     * NEVER delete the target first without a backup — that opens a
     * window where neither file exists if the subsequent rename
     * fails.
     */
    fun save(ctx: Context, state: State): Boolean {
        val f = File(ctx.filesDir, FILE)
        val tmp = File(ctx.filesDir, "$FILE.tmp")
        return try {
            tmp.writeText(encode(state))
            atomicReplace(tmp, f)
        } catch (_: Throwable) {
            tmp.delete()
            false
        }
    }

    /** Public wrapper around [atomicReplace] so ConfigStore can share
     *  the same safe replace pattern without duplicating the logic. */
    internal fun atomicReplacePublic(source: File, target: File): Boolean =
        atomicReplace(source, target)

    /** Replace `target` with `source` atomically. See [save] for the
     *  fallback rationale on minSdk 24/25.
     *
     *  Refuses to replace a directory: `config.json` / `profiles.json`
     *  being a directory is an invariant violation we shouldn't
     *  silently "fix" by renaming the dir aside. The caller (e.g.
     *  ConfigStore.save) returns failure so the UI surfaces the
     *  problem instead of papering over it. */
    private fun atomicReplace(source: File, target: File): Boolean {
        if (!source.exists()) return false
        if (target.exists() && target.isDirectory) {
            android.util.Log.w(
                "ProfileStore",
                "atomicReplace refused: target is a directory: ${target.absolutePath}",
            )
            // Clean up the source so we don't litter a stale .tmp file.
            source.delete()
            return false
        }
        // Prefer NIO atomic move when available (API 26+). It's the only
        // call that gives a real "no window where the file is missing"
        // guarantee on Android. We accept ATOMIC_MOVE as best-effort —
        // if the filesystem doesn't support it, REPLACE_EXISTING alone
        // is still a safe replace (just possibly not atomic).
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            return try {
                java.nio.file.Files.move(
                    source.toPath(),
                    target.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                )
                true
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                // Fall through to the older-Android pattern below if
                // the filesystem rejects ATOMIC_MOVE for some reason.
                replaceWithBackup(source, target)
            } catch (_: Throwable) {
                replaceWithBackup(source, target)
            }
        }
        return replaceWithBackup(source, target)
    }

    /** Backup-restore replace pattern for older Android.
     *  Also refuses directory targets (same rationale as [atomicReplace]). */
    private fun replaceWithBackup(source: File, target: File): Boolean {
        if (target.exists() && target.isDirectory) {
            source.delete()
            return false
        }
        if (!target.exists()) {
            // No backup needed.
            return source.renameTo(target).also {
                if (!it) source.delete()
            }
        }
        val backup = File(target.parentFile, "${target.name}.bak")
        // Stale backup from a previous failure — remove before renaming
        // onto it. If this fails we abort: a stale backup is the only
        // thing preserving the user's old data and we don't want to
        // delete that until we know the new file is in place.
        if (backup.exists() && !backup.delete()) return false
        if (!target.renameTo(backup)) return false
        if (source.renameTo(target)) {
            // Success — drop the backup.
            backup.delete()
            return true
        }
        // Roll back: put the backup back where the target was, leave
        // the (unrenamed) source for hand recovery.
        if (!backup.renameTo(target)) {
            // Worst case: backup move-back failed too. Leave the user
            // with a .bak file containing their previous data.
            android.util.Log.w(
                "ProfileStore",
                "atomicReplace rollback failed; user data is in ${backup.absolutePath}",
            )
        }
        source.delete()
        return false
    }

    /** Outcome of any mutating operation. Distinguishes "your input was
     *  bad" (Duplicate / NotFound / EmptyName) from "the disk is in a
     *  state we won't overwrite" (CorruptOnDisk) from "the disk write
     *  itself failed" (SaveFailed) from "config.json wrote OK but
     *  profiles.json didn't" (PartialConfigOnly). */
    sealed class MutationResult {
        object Ok : MutationResult()
        object EmptyName : MutationResult()
        object Duplicate : MutationResult()
        object NotFound : MutationResult()
        object SaveFailed : MutationResult()
        /** config.json was written successfully but the subsequent
         *  profiles.json write failed. The live config is the new
         *  bytes (equivalent to a Save config), but no profile entry
         *  was added/updated. Caller should warn the user and offer
         *  to retry the profile-write step. */
        object PartialConfigOnly : MutationResult()
        data class CorruptOnDisk(val cause: Throwable) : MutationResult()
    }

    /**
     * Outcome of [applyProfile]. Mirrors Rust's `ApplyOutcome`:
     *   - [Ok] — both `config.json` and `profiles.json` were written;
     *     the returned [cfg] is the new live config.
     *   - [PartialConfigOnly] — `config.json` IS the new profile but
     *     the `profiles.json` active-pointer save failed. The caller
     *     should still apply the [cfg] to the form (the live runtime
     *     reads `config.json` and will use the new bytes), but warn
     *     the user that the active marker on disk is stale.
     *   - [NotFound] — profile name doesn't exist; nothing was
     *     touched.
     *   - [Failed] — config.json write failed before anything else;
     *     nothing was touched. `reason` carries the underlying error
     *     when available.
     */
    sealed class ApplyResult {
        data class Ok(val cfg: MhrvConfig) : ApplyResult()
        data class PartialConfigOnly(val cfg: MhrvConfig) : ApplyResult()
        object NotFound : ApplyResult()
        data class Failed(val reason: String) : ApplyResult()
    }

    /**
     * Switch the live config to a stored profile. The snapshot is
     * written to `config.json` RAW (not through [MhrvConfig.toJson])
     * so any fields this build doesn't model survive — this is what
     * lets the native runtime keep seeing desktop-only / future
     * Rust-side keys.
     *
     * Outcome contract (mirrors Rust's `apply_profile`):
     *   - [ApplyResult.NotFound] — name not in the store; no writes.
     *   - [ApplyResult.Failed] — the `config.json` write failed
     *     before anything else; no writes succeeded.
     *   - [ApplyResult.Ok] — both writes succeeded.
     *   - [ApplyResult.PartialConfigOnly] — `config.json` IS the new
     *     profile (live runtime will use it on next start) but the
     *     `profiles.json` active-pointer save failed. The dropdown's
     *     active marker on disk is stale.
     */
    fun applyProfile(ctx: Context, name: String): ApplyResult {
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> return ApplyResult.NotFound
            is LoadResult.Corrupt -> return ApplyResult.Failed("profiles.json is corrupt")
        }
        val p = state.find(name) ?: return ApplyResult.NotFound

        val raw = try {
            JSONObject(p.configJson).toString(2)
        } catch (e: Throwable) {
            return ApplyResult.Failed("snapshot is not valid JSON: ${e.message}")
        }
        // Runtime-shape validation: refuse to write a snapshot the
        // native runtime would reject (missing/unknown mode, or
        // missing deployment ID / auth_key for apps_script/full).
        // Without this, applying a malformed profile would clobber
        // the user's working config.json with bytes Rust's
        // Config::load then errors out on. Decode is permissive (it
        // tolerates a missing mode by defaulting to apps_script),
        // so we re-check on the decoded result.
        val cfg = ConfigStore.decode(p.configJson)
            ?: return ApplyResult.Failed("snapshot did not decode into MhrvConfig")
        val shapeErr = validateRuntimeShape(JSONObject(p.configJson), cfg)
        if (shapeErr != null) {
            return ApplyResult.Failed("snapshot would not pass runtime validation: $shapeErr")
        }

        // 1. Write the RAW snapshot to config.json. On failure,
        //    nothing changed.
        val cfgFile = File(ctx.filesDir, "config.json")
        val cfgTmp = File(ctx.filesDir, "config.json.tmp")
        val cfgOk = try {
            cfgTmp.writeText(raw)
            atomicReplace(cfgTmp, cfgFile)
        } catch (_: Throwable) {
            cfgTmp.delete()
            false
        }
        if (!cfgOk) return ApplyResult.Failed("could not write config.json")

        // 2. Try to move the active pointer. If this fails, surface
        //    PartialConfigOnly so the caller can warn the user that
        //    the dropdown's marker on disk is stale, while still
        //    reloading the form from the new config.json.
        return if (save(ctx, state.copy(active = name))) {
            ApplyResult.Ok(cfg)
        } else {
            ApplyResult.PartialConfigOnly(cfg)
        }
    }

    /** Compatibility shim for callers that only need the cfg or null.
     *  New code should call [applyProfile] directly and pattern-match
     *  on [ApplyResult] so the partial-success case isn't swallowed. */
    fun applyProfileOrNull(ctx: Context, name: String): MhrvConfig? =
        when (val r = applyProfile(ctx, name)) {
            is ApplyResult.Ok -> r.cfg
            is ApplyResult.PartialConfigOnly -> r.cfg
            else -> null
        }

    /**
     * Insert or update a named profile.
     *
     * Write order: **`config.json` FIRST, then `profiles.json`**.
     *   - On config.json failure: nothing changed on disk.
     *   - On profiles.json failure: `config.json` is the new bytes
     *     (equivalent to a regular Save) but the profile entry
     *     wasn't saved. We return [MutationResult.PartialConfigOnly].
     *
     * The reverse order would corrupt the overwrite case: replacing
     * a profile's snapshot before discovering config.json couldn't
     * land would leave the profile entry pointing at bytes no file
     * on disk matched.
     */
    fun upsert(ctx: Context, name: String, cfg: MhrvConfig): MutationResult {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return MutationResult.EmptyName
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> r.state
            is LoadResult.Corrupt -> return MutationResult.CorruptOnDisk(r.cause)
        }
        val snapshot = cfg.toJson()
        val newList = if (state.find(trimmed) != null) {
            state.profiles.map { if (it.name == trimmed) Profile(trimmed, snapshot) else it }
        } else {
            state.profiles + Profile(trimmed, snapshot)
        }
        val newState = State(active = trimmed, profiles = newList)
        // Step 1: live config first. If this fails, nothing changed.
        if (!ConfigStore.save(ctx, cfg)) return MutationResult.SaveFailed
        // Step 2: profile entry. If this fails, the live config is
        // already the new bytes but the profile entry wasn't saved.
        if (!save(ctx, newState)) return MutationResult.PartialConfigOnly
        return MutationResult.Ok
    }

    /** Insert a new profile, refusing to overwrite an existing one of
     *  the same name. Same write-order + outcome semantics as [upsert]. */
    fun insertNew(ctx: Context, name: String, cfg: MhrvConfig): MutationResult {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return MutationResult.EmptyName
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> r.state
            is LoadResult.Corrupt -> return MutationResult.CorruptOnDisk(r.cause)
        }
        if (state.find(trimmed) != null) return MutationResult.Duplicate
        val newState = State(
            active = trimmed,
            profiles = state.profiles + Profile(trimmed, cfg.toJson()),
        )
        if (!ConfigStore.save(ctx, cfg)) return MutationResult.SaveFailed
        if (!save(ctx, newState)) return MutationResult.PartialConfigOnly
        return MutationResult.Ok
    }

    /** Rename. The active pointer moves if it was pointing at `from`. */
    fun rename(ctx: Context, from: String, to: String): MutationResult {
        val toTrimmed = to.trim()
        if (toTrimmed.isEmpty()) return MutationResult.EmptyName
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> return MutationResult.NotFound
            is LoadResult.Corrupt -> return MutationResult.CorruptOnDisk(r.cause)
        }
        if (state.find(from) == null) return MutationResult.NotFound
        if (from != toTrimmed && state.find(toTrimmed) != null) return MutationResult.Duplicate
        val newList = state.profiles.map {
            if (it.name == from) Profile(toTrimmed, it.configJson) else it
        }
        val newActive = if (state.active == from) toTrimmed else state.active
        return if (save(ctx, State(active = newActive, profiles = newList))) {
            MutationResult.Ok
        } else {
            MutationResult.SaveFailed
        }
    }

    /**
     * Delete. If the deleted profile was active, active becomes "" —
     * by invariant 2, we can't claim some OTHER profile matches the live
     * config without actually applying it, and silently rewriting the
     * user's config is the wrong call here. The user can explicitly
     * switch to a different profile if they want.
     */
    fun delete(ctx: Context, name: String): MutationResult {
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> return MutationResult.NotFound
            is LoadResult.Corrupt -> return MutationResult.CorruptOnDisk(r.cause)
        }
        val idx = state.profiles.indexOfFirst { it.name == name }
        if (idx < 0) return MutationResult.NotFound
        // Remove only the first match — duplicate names are rejected at
        // load time, so in a well-formed file there's exactly one, but
        // we still want to match Rust's "first match" semantics if a
        // hand-edited file slips a duplicate past us somehow. Previously
        // this used `filter { it.name != name }` which removed all
        // matches, diverging from Rust.
        val newList = state.profiles.toMutableList().also { it.removeAt(idx) }
        val newActive = if (state.active == name) "" else state.active
        return if (save(ctx, State(active = newActive, profiles = newList))) {
            MutationResult.Ok
        } else {
            MutationResult.SaveFailed
        }
    }

    /** Duplicate. Non-destructive: does NOT change the active pointer
     *  or touch `config.json`. */
    fun duplicate(ctx: Context, from: String, to: String): MutationResult {
        val toTrimmed = to.trim()
        if (toTrimmed.isEmpty()) return MutationResult.EmptyName
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            is LoadResult.Missing -> return MutationResult.NotFound
            is LoadResult.Corrupt -> return MutationResult.CorruptOnDisk(r.cause)
        }
        val src = state.find(from) ?: return MutationResult.NotFound
        if (state.find(toTrimmed) != null) return MutationResult.Duplicate
        val newState = State(
            active = state.active,
            profiles = state.profiles + Profile(toTrimmed, src.configJson),
        )
        return if (save(ctx, newState)) MutationResult.Ok else MutationResult.SaveFailed
    }

    /**
     * Clear the active pointer if it's non-empty. Used by [HomeScreen]
     * on every field edit to maintain invariant 2: any change to
     * config.json that wasn't a profile apply breaks the "active
     * matches live config" promise, so we have to clear the marker.
     *
     * Safe no-op if profiles.json is missing or already clean.
     * Refuses to write over a corrupt file (same guard as the
     * other mutations).
     */
    fun clearActiveIfAny(ctx: Context) {
        val state = when (val r = loadStrict(ctx)) {
            is LoadResult.Ok -> r.state
            // Missing file: nothing to clear, no need to materialize one.
            is LoadResult.Missing -> return
            // Corrupt: never overwrite.
            is LoadResult.Corrupt -> return
        }
        if (state.active.isEmpty()) return
        save(ctx, state.copy(active = ""))
    }

    /**
     * Mirror of `Config::validate` on the Rust side: returns null if
     * the snapshot is a shape the runtime would accept, or an error
     * string otherwise. Checked at [applyProfile] before writing to
     * `config.json` so a malformed snapshot can't clobber the user's
     * working live config with bytes Rust's `Config::load` then
     * errors on.
     *
     * Rules:
     *   - `mode` must be present and one of "apps_script" | "direct"
     *     | "full" (the legacy "google_only" alias is accepted as
     *     direct, mirroring `Config::mode_kind`).
     *   - apps_script / full modes require at least one non-empty
     *     deployment ID (under either `script_id` or `script_ids`)
     *     AND a non-empty, non-placeholder `auth_key`.
     */
    private fun validateRuntimeShape(raw: JSONObject, decoded: MhrvConfig): String? {
        val mode = raw.optString("mode", "")
        if (mode.isBlank()) return "missing required field `mode`"
        when (mode) {
            "apps_script", "full" -> {
                if (!decoded.hasDeploymentId) {
                    return "$mode mode requires script_id (or script_ids)"
                }
                val auth = decoded.authKey.trim()
                if (auth.isEmpty() || auth == "CHANGE_ME_TO_A_STRONG_SECRET") {
                    return "$mode mode requires a non-placeholder auth_key"
                }
            }
            "direct", "google_only" -> { /* no relay creds required */ }
            else -> return "unknown mode '$mode'"
        }
        return null
    }

    /** Pick a unique "name (copy)" / "name (copy 2)" etc. for a duplicate. */
    fun uniqueCopyName(state: State, base: String): String {
        var candidate = "$base (copy)"
        var n = 2
        while (state.find(candidate) != null) {
            candidate = "$base (copy $n)"
            n++
        }
        return candidate
    }

    // ---- I/O helpers ----

    /**
     * Strict parse: throws on ANY malformed entry. The caller
     * ([loadStrict]) catches and returns [LoadResult.Corrupt] so the
     * UI refuses to overwrite the file (invariant 4).
     *
     * We deliberately don't "skip and continue" on bad entries — that
     * was the previous behaviour and it silently dropped recoverable
     * data on the next save. If part of the file is malformed, the
     * whole file is treated as corrupt and the user is asked to
     * hand-recover.
     */
    private fun parse(text: String): State {
        if (text.isBlank()) return State(active = "", profiles = emptyList())
        val obj = JSONObject(text)
        val active = obj.optString("active", "")
        if (!obj.has("profiles")) {
            return State(active = active, profiles = emptyList())
        }
        val arr = obj.optJSONArray("profiles")
            ?: throw IllegalStateException("`profiles` key is not an array")
        val out = mutableListOf<Profile>()
        val seen = HashSet<String>(arr.length())
        for (i in 0 until arr.length()) {
            val p = arr.optJSONObject(i)
                ?: throw IllegalStateException("profiles[$i] is not an object")
            val name = p.optString("name", "")
            if (name.isBlank()) {
                throw IllegalStateException("profiles[$i] has empty/missing name")
            }
            // Duplicate names break every by-name op (apply / rename /
            // delete) — Android's `delete` removes all matches while
            // Rust's removes only the first, so we'd diverge on the
            // same file. Reject loudly so the user can hand-fix.
            if (!seen.add(name)) {
                throw IllegalStateException("profiles[$i] ('$name'): duplicate profile name")
            }
            val cfg = p.optJSONObject("config")
                ?: throw IllegalStateException("profiles[$i] ('$name') has no config object")
            out.add(Profile(name = name, configJson = cfg.toString()))
        }
        return State(active = active, profiles = out)
    }

    /**
     * Strict encode: throws on any malformed snapshot. Should never
     * happen in practice because snapshots come from [MhrvConfig.toJson]
     * (always valid) or were captured at parse time (already validated
     * by [parse]). A throw here means an invariant violation we'd
     * rather surface loudly than silently drop.
     */
    private fun encode(state: State): String {
        val arr = JSONArray()
        for (p in state.profiles) {
            val item = JSONObject()
            item.put("name", p.name)
            val cfg = try {
                JSONObject(p.configJson)
            } catch (e: Throwable) {
                throw IllegalStateException(
                    "profile '${p.name}' has malformed config snapshot",
                    e,
                )
            }
            item.put("config", cfg)
            arr.put(item)
        }
        val root = JSONObject()
        root.put("active", state.active)
        root.put("profiles", arr)
        return root.toString(2)
    }
}
