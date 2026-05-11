package com.therealaleph.mhrv

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Unit coverage for [ProfileStore] and the [ConfigStore]/[MhrvConfig]
 * surfaces it touches. These tests pin the invariants documented in
 * the class headers — drift here means desktop and Android can
 * diverge silently on the same profile data, which is the whole
 * point of the test matrix.
 *
 * Mirror of the Rust-side tests in `src/profiles.rs` — each invariant
 * has a counterpart so a behavioural delta between Rust and Kotlin
 * shows up as a test failure on at least one side.
 */
@RunWith(RobolectricTestRunner::class)
class ProfileStoreTest {
    private lateinit var ctx: Context
    private lateinit var profilesFile: File
    private lateinit var configFile: File

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        profilesFile = File(ctx.filesDir, "profiles.json")
        configFile = File(ctx.filesDir, "config.json")
        clearAll()
    }

    @After
    fun tearDown() {
        clearAll()
    }

    /**
     * Recursive cleanup so a test that mid-flight created a directory
     * at a file path (the injected-write-failure trick) doesn't leak
     * into the next test. Plain [File.delete] won't remove a non-empty
     * directory.
     */
    private fun clearAll() {
        listOf(
            profilesFile,
            configFile,
            File(ctx.filesDir, "profiles.json.tmp"),
            File(ctx.filesDir, "profiles.json.bak"),
            File(ctx.filesDir, "config.json.tmp"),
            File(ctx.filesDir, "config.json.bak"),
        ).forEach { deleteRecursively(it) }
    }

    private fun deleteRecursively(f: File) {
        if (!f.exists()) return
        if (f.isDirectory) {
            f.listFiles()?.forEach { deleteRecursively(it) }
        }
        f.delete()
    }

    // ---- Invariant 1: raw snapshot preservation ----

    /**
     * The whole point of storing snapshots as raw JSON: a profile
     * written by a desktop build (or a future Android build) with
     * config fields this build doesn't model must round-trip
     * losslessly through Save → Switch.
     */
    @Test
    fun applyProfile_preserves_unknown_fields_in_config_json() {
        val futureSnapshot = """
            {
              "mode": "apps_script",
              "script_ids": ["A"],
              "auth_key": "secret",
              "fronting_groups": [
                {"name": "vercel", "ip": "76.76.21.21", "sni": "react.dev",
                 "domains": ["vercel.com"]}
              ],
              "exit_node": {"enabled": true, "relay_url": "https://e.example",
                            "psk": "p", "mode": "selective",
                            "hosts": ["chatgpt.com"]},
              "request_timeout_secs": 45,
              "future_field_xyz": [1, 2, 3]
            }
        """.trimIndent()
        val written = """
            {"active":"future","profiles":[{"name":"future","config":$futureSnapshot}]}
        """.trimIndent()
        profilesFile.writeText(written)

        val applied = ProfileStore.applyProfile(ctx, "future")
        assertTrue(
            "apply should succeed on a valid future-shape snapshot, got ${applied::class.simpleName}",
            applied is ProfileStore.ApplyResult.Ok,
        )

        assertTrue("config.json should have been written", configFile.exists())
        val onDisk = JSONObject(configFile.readText())
        assertEquals("apps_script", onDisk.optString("mode"))
        assertEquals("secret", onDisk.optString("auth_key"))
        assertTrue("fronting_groups must survive", onDisk.has("fronting_groups"))
        assertEquals(1, onDisk.optJSONArray("fronting_groups")?.length() ?: 0)
        assertTrue("exit_node must survive", onDisk.has("exit_node"))
        assertEquals(45, onDisk.optInt("request_timeout_secs", -1))
        assertTrue(
            "completely unknown future field must survive",
            onDisk.has("future_field_xyz"),
        )
    }

    /**
     * The data-loss bug we fixed: unknown fields used to be dropped
     * the moment the user edited any form field (because persist()
     * runs cfg.toJson() which only emits modelled keys). The fix
     * was to capture unknown keys into MhrvConfig.extrasJson and
     * re-emit them. This test asserts: load → toJson round-trips
     * unknown fields.
     */
    @Test
    fun mhrvconfig_toJson_preserves_unknown_fields() {
        val originalJson = """
            {
              "mode": "apps_script",
              "script_ids": ["A"],
              "auth_key": "secret",
              "fronting_groups": [{"name":"x","ip":"1.2.3.4","sni":"a.b","domains":["c.com"]}],
              "request_timeout_secs": 99,
              "disable_padding": true
            }
        """.trimIndent()
        configFile.writeText(originalJson)
        val cfg = ConfigStore.load(ctx)
        // Round-trip via toJson — the path persist() takes on every edit.
        val roundTripped = JSONObject(cfg.toJson())
        assertEquals(99, roundTripped.optInt("request_timeout_secs"))
        assertTrue(roundTripped.optBoolean("disable_padding"))
        assertTrue(roundTripped.has("fronting_groups"))
    }

    /**
     * Critical: Rust writes `script_id` (singular, can be string or
     * array). Before this fix, Android only read `script_ids` (plural,
     * array only), so a desktop-saved profile applied on Android with
     * zero deployment IDs and the proxy would refuse to start.
     */
    @Test
    fun configstore_reads_rust_shaped_script_id_scalar() {
        val rustScalar = """
            {"mode":"apps_script","script_id":"DESKTOP_ID","auth_key":"k"}
        """.trimIndent()
        configFile.writeText(rustScalar)
        val cfg = ConfigStore.load(ctx)
        assertEquals(1, cfg.appsScriptUrls.size)
        assertTrue(cfg.appsScriptUrls.first().contains("DESKTOP_ID"))
        assertTrue("hasDeploymentId must be true", cfg.hasDeploymentId)
    }

    @Test
    fun configstore_reads_rust_shaped_script_id_array() {
        val rustArray = """
            {"mode":"apps_script","script_id":["A","B","C"],"auth_key":"k"}
        """.trimIndent()
        configFile.writeText(rustArray)
        val cfg = ConfigStore.load(ctx)
        assertEquals(3, cfg.appsScriptUrls.size)
    }

    @Test
    fun configstore_reads_both_script_id_and_script_ids_combined() {
        // Hand-edited config where someone added a key via "script_id"
        // and another via "script_ids". The union must be exposed.
        val combined = """
            {"mode":"apps_script","script_id":"X","script_ids":["Y","Z"],"auth_key":"k"}
        """.trimIndent()
        configFile.writeText(combined)
        val cfg = ConfigStore.load(ctx)
        assertEquals(3, cfg.appsScriptUrls.size)
    }

    // ---- Invariant 2: active == "matches the live config" ----

    @Test
    fun delete_active_clears_pointer() {
        ProfileStore.upsert(ctx, "a", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", MhrvConfig(appsScriptUrls = listOf("B"), authKey = "y"))
        ProfileStore.upsert(ctx, "c", MhrvConfig(appsScriptUrls = listOf("C"), authKey = "z"))
        assertEquals(ProfileStore.MutationResult.Ok, ProfileStore.delete(ctx, "c"))
        val state = ProfileStore.load(ctx)
        assertEquals("", state.active)
        assertNotNull(state.find("a"))
        assertNotNull(state.find("b"))
    }

    @Test
    fun delete_non_active_keeps_pointer() {
        ProfileStore.upsert(ctx, "a", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", MhrvConfig(appsScriptUrls = listOf("B"), authKey = "y"))
        ProfileStore.delete(ctx, "a")
        assertEquals("b", ProfileStore.load(ctx).active)
    }

    @Test
    fun upsert_writes_snapshot_to_live_config_json() {
        val cfg = MhrvConfig(
            mode = Mode.APPS_SCRIPT,
            appsScriptUrls = listOf("A"),
            authKey = "secret",
            googleIp = "1.2.3.4",
        )
        val r = ProfileStore.upsert(ctx, "home", cfg)
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertTrue("config.json must be written by upsert", configFile.exists())
        val onDisk = JSONObject(configFile.readText())
        assertEquals("apps_script", onDisk.optString("mode"))
        assertEquals("secret", onDisk.optString("auth_key"))
        assertEquals("1.2.3.4", onDisk.optString("google_ip"))
        assertEquals("home", ProfileStore.load(ctx).active)
    }

    @Test
    fun insertNew_writes_snapshot_to_live_config_json() {
        val cfg = MhrvConfig(appsScriptUrls = listOf("X"), authKey = "k")
        val r = ProfileStore.insertNew(ctx, "first", cfg)
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertTrue(configFile.exists())
        assertEquals("first", ProfileStore.load(ctx).active)
    }

    /**
     * Invariant 2 follow-up: clearActiveIfAny clears active when set,
     * is a no-op otherwise. Called on every persist() in HomeScreen.
     */
    @Test
    fun clearActiveIfAny_clears_when_set() {
        ProfileStore.upsert(ctx, "p", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "k"))
        assertEquals("p", ProfileStore.load(ctx).active)
        ProfileStore.clearActiveIfAny(ctx)
        val state = ProfileStore.load(ctx)
        assertEquals("", state.active)
        // Profile entry should still be there — we cleared the marker,
        // not the data.
        assertNotNull(state.find("p"))
    }

    @Test
    fun clearActiveIfAny_no_op_on_missing_file() {
        // Should not create profiles.json out of thin air.
        ProfileStore.clearActiveIfAny(ctx)
        assertFalse(profilesFile.exists())
    }

    @Test
    fun clearActiveIfAny_no_op_on_already_empty_active() {
        // Write a profiles.json with no active pointer.
        profilesFile.writeText("""{"active":"","profiles":[]}""")
        ProfileStore.clearActiveIfAny(ctx)
        // No write should have happened, but to be lenient we allow
        // a rewrite as long as content is the same on reload.
        assertEquals("", ProfileStore.load(ctx).active)
    }

    // ---- Invariant 3: persist before in-memory state changes ----

    @Test
    fun rename_collision_does_not_mutate_state() {
        ProfileStore.upsert(ctx, "a", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "x"))
        ProfileStore.upsert(ctx, "b", MhrvConfig(appsScriptUrls = listOf("B"), authKey = "y"))
        val r = ProfileStore.rename(ctx, "a", "b")
        assertEquals(ProfileStore.MutationResult.Duplicate, r)
        val state = ProfileStore.load(ctx)
        assertNotNull(state.find("a"))
        assertNotNull(state.find("b"))
    }

    @Test
    fun upsert_empty_name_is_rejected() {
        val r = ProfileStore.upsert(ctx, "   ", MhrvConfig())
        assertEquals(ProfileStore.MutationResult.EmptyName, r)
        assertFalse("nothing should be written for empty name", profilesFile.exists())
    }

    @Test
    fun insertNew_duplicate_returns_Duplicate_not_overwrite() {
        ProfileStore.insertNew(
            ctx,
            "p",
            MhrvConfig(appsScriptUrls = listOf("first"), authKey = "k"),
        )
        val r = ProfileStore.insertNew(
            ctx,
            "p",
            MhrvConfig(appsScriptUrls = listOf("second"), authKey = "k"),
        )
        assertEquals(ProfileStore.MutationResult.Duplicate, r)
        val applied = ProfileStore.applyProfile(ctx, "p")
        assertTrue(applied is ProfileStore.ApplyResult.Ok)
        val cfg = (applied as ProfileStore.ApplyResult.Ok).cfg
        assertEquals(
            listOf("https://script.google.com/macros/s/first/exec"),
            cfg.appsScriptUrls,
        )
    }

    // ---- Invariant 4: load failure is loud ----

    @Test
    fun corrupt_file_is_surfaced_via_loadStrict() {
        profilesFile.writeText("{ not valid json")
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Corrupt)
    }

    @Test
    fun missing_file_is_surfaced_as_Missing() {
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Missing)
    }

    /**
     * Partial-malformation strictness: a file where the top-level
     * shape is valid but one profile entry is broken must surface
     * as Corrupt, NOT a lenient "skip the bad entry and silently
     * drop it on next save". Before this was strict, the next save
     * would have permanently lost the broken entry.
     */
    @Test
    fun partial_malformed_profile_entry_surfaces_as_corrupt() {
        val partial = """
            {
              "active": "good",
              "profiles": [
                {"name": "good", "config": {"mode": "apps_script"}},
                {"name": "broken"}
              ]
            }
        """.trimIndent()
        profilesFile.writeText(partial)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(
            "expected Corrupt for missing config, got ${r::class.simpleName}",
            r is ProfileStore.LoadResult.Corrupt,
        )
    }

    @Test
    fun partial_malformed_profile_name_surfaces_as_corrupt() {
        val partial = """
            {
              "active": "good",
              "profiles": [
                {"name": "", "config": {"mode": "apps_script"}}
              ]
            }
        """.trimIndent()
        profilesFile.writeText(partial)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(r is ProfileStore.LoadResult.Corrupt)
    }

    /**
     * Duplicate names make every by-name operation (apply / rename /
     * delete) ambiguous, so we reject on load. Matches the Rust-side
     * test of the same name.
     */
    @Test
    fun duplicate_names_surface_as_corrupt() {
        val dup = """
            {
              "active": "p",
              "profiles": [
                {"name": "p", "config": {"mode": "apps_script"}},
                {"name": "p", "config": {"mode": "full"}}
              ]
            }
        """.trimIndent()
        profilesFile.writeText(dup)
        val r = ProfileStore.loadStrict(ctx)
        assertTrue(
            "expected Corrupt for duplicate names, got ${r::class.simpleName}",
            r is ProfileStore.LoadResult.Corrupt,
        )
        val msg = (r as ProfileStore.LoadResult.Corrupt).cause.message.orEmpty()
        assertTrue(
            "error should mention duplicate explicitly: $msg",
            msg.contains("duplicate", ignoreCase = true),
        )
    }

    @Test
    fun mutations_refuse_to_overwrite_corrupt_profiles_file() {
        profilesFile.writeText("{ corrupt")
        val before = profilesFile.readText()
        val r = ProfileStore.upsert(
            ctx,
            "p",
            MhrvConfig(appsScriptUrls = listOf("A"), authKey = "k"),
        )
        assertTrue(r is ProfileStore.MutationResult.CorruptOnDisk)
        assertEquals(before, profilesFile.readText())
    }

    @Test
    fun corrupt_then_delete_corrupt_then_save_works() {
        profilesFile.writeText("{ corrupt")
        profilesFile.delete()
        val r = ProfileStore.upsert(
            ctx,
            "p",
            MhrvConfig(appsScriptUrls = listOf("A"), authKey = "k"),
        )
        assertEquals(ProfileStore.MutationResult.Ok, r)
        assertEquals("p", ProfileStore.load(ctx).active)
    }

    // ---- Atomic-replace data-loss regression guard ----

    /**
     * Regression for the pre-delete data-loss bug: if [ProfileStore.save]
     * succeeds, the previous file's bytes are gone (replaced) — but
     * if it FAILED (which we can't easily simulate cleanly), the
     * previous file must still exist. We can at least verify the
     * happy path leaves no leftover temp/backup files.
     */
    @Test
    fun save_leaves_no_tmp_or_bak_behind_on_success() {
        ProfileStore.upsert(ctx, "p", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "k"))
        assertFalse(File(ctx.filesDir, "profiles.json.tmp").exists())
        assertFalse(File(ctx.filesDir, "profiles.json.bak").exists())
    }

    // ---- Cross-platform parity: applyProfile + decoded view ----

    @Test
    fun applyProfile_decoded_view_matches_snapshot_subset() {
        val cfg = MhrvConfig(
            mode = Mode.FULL,
            appsScriptUrls = listOf("Z"),
            authKey = "topsecret",
            parallelRelay = 3,
        )
        ProfileStore.upsert(ctx, "fullmode", cfg)
        ConfigStore.save(ctx, MhrvConfig(mode = Mode.DIRECT))
        val applied = ProfileStore.applyProfile(ctx, "fullmode")
        assertTrue(applied is ProfileStore.ApplyResult.Ok)
        val out = (applied as ProfileStore.ApplyResult.Ok).cfg
        assertEquals(Mode.FULL, out.mode)
        assertEquals("topsecret", out.authKey)
        assertEquals(3, out.parallelRelay)
    }

    /**
     * Snapshot with apps_script mode but no script_id/script_ids and
     * no auth_key would fail Rust's `Config::validate`. Apply must
     * refuse instead of clobbering config.json with bytes the runtime
     * rejects on its next start.
     */
    @Test
    fun applyProfile_refuses_runtime_invalid_snapshot() {
        val bad = """
            {
              "active": "bad",
              "profiles": [{"name": "bad", "config": {"mode": "apps_script"}}]
            }
        """.trimIndent()
        profilesFile.writeText(bad)
        // Plant a known-good live config so we can assert it's unchanged.
        ConfigStore.save(ctx, MhrvConfig(authKey = "preserve-me"))
        val before = configFile.readText()

        val r = ProfileStore.applyProfile(ctx, "bad")
        assertTrue(
            "expected Failed, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Failed,
        )
        // config.json must not have been touched.
        assertEquals(before, configFile.readText())
    }

    /**
     * A direct-mode snapshot doesn't need script_id or auth_key — the
     * runtime tolerates both being absent for direct. Apply must
     * succeed.
     */
    @Test
    fun applyProfile_accepts_minimal_direct_snapshot() {
        val ok = """
            {
              "active": "",
              "profiles": [{"name": "d", "config": {"mode": "direct"}}]
            }
        """.trimIndent()
        profilesFile.writeText(ok)
        val r = ProfileStore.applyProfile(ctx, "d")
        assertTrue(
            "minimal direct snapshot must apply, got ${r::class.simpleName}",
            r is ProfileStore.ApplyResult.Ok,
        )
    }

    @Test
    fun applyProfile_missing_returns_NotFound_without_side_effects() {
        ConfigStore.save(ctx, MhrvConfig(authKey = "preserve-me"))
        val before = configFile.readText()
        val applied = ProfileStore.applyProfile(ctx, "does-not-exist")
        assertTrue(applied is ProfileStore.ApplyResult.NotFound)
        assertEquals(before, configFile.readText())
    }

    @Test
    fun unique_copy_name_increments_on_collision() {
        ProfileStore.upsert(ctx, "p", MhrvConfig(appsScriptUrls = listOf("A"), authKey = "k"))
        ProfileStore.duplicate(ctx, "p", "p (copy)")
        val state = ProfileStore.load(ctx)
        val unique = ProfileStore.uniqueCopyName(state, "p")
        assertNotEquals("p (copy)", unique)
        assertEquals("p (copy 2)", unique)
    }

    // ---- Injected write-failure tests ----
    //
    // Trick: make a file path a *directory* on disk before the call.
    // The atomic-replace step (NIO Files.move or File.renameTo)
    // then fails because we can't overwrite a directory with a
    // file. This is portable across the Robolectric backing FS and
    // doesn't require mocking.

    /**
     * Step 1 (config.json) fails → upsert returns SaveFailed and
     * neither file is modified. Specifically guards against the
     * old order (profiles.json first), where an overwrite would
     * clobber an existing profile's snapshot before discovering
     * the live-config write would fail.
     */
    @Test
    fun upsert_config_write_failure_leaves_profiles_unchanged() {
        ProfileStore.upsert(
            ctx,
            "home",
            MhrvConfig(appsScriptUrls = listOf("OLD"), authKey = "old"),
        )
        val profilesBefore = profilesFile.readText()

        // Block config.json write by making the path a directory.
        // atomicReplace refuses to overwrite a directory target,
        // so the save fails — exactly what we want to test.
        configFile.delete()
        configFile.mkdirs()
        File(configFile, "sentinel").writeText("x")

        try {
            val r = ProfileStore.upsert(
                ctx,
                "home",
                MhrvConfig(appsScriptUrls = listOf("NEW"), authKey = "new"),
            )
            assertEquals(ProfileStore.MutationResult.SaveFailed, r)
            // profiles.json must be UNCHANGED — the bug guard.
            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            // Even if an assertion fires, leave a clean filesystem
            // for the next test. clearAll() in tearDown is recursive
            // but cheap insurance never hurts.
            deleteRecursively(configFile)
        }
    }

    /**
     * Step 2 (profiles.json) fails AFTER step 1 succeeded → returns
     * PartialConfigOnly. config.json is the new bytes, profiles.json
     * is unchanged.
     */
    @Test
    fun upsert_profiles_write_failure_returns_partial_config_only() {
        ProfileStore.upsert(
            ctx,
            "home",
            MhrvConfig(appsScriptUrls = listOf("OLD"), authKey = "old"),
        )
        val profilesBefore = profilesFile.readText()

        // Block profiles.json write by making profiles.json.tmp
        // a directory. The tmp.writeText() call inside save() then
        // throws (can't write a regular file at a directory path).
        val tmp = File(ctx.filesDir, "profiles.json.tmp")
        tmp.delete()
        tmp.mkdirs()
        File(tmp, "sentinel").writeText("x")

        try {
            val r = ProfileStore.upsert(
                ctx,
                "home",
                MhrvConfig(appsScriptUrls = listOf("NEW"), authKey = "new"),
            )
            assertEquals(ProfileStore.MutationResult.PartialConfigOnly, r)

            // config.json IS the new bytes — equivalent to a regular Save.
            val onDisk = JSONObject(configFile.readText())
            assertEquals("new", onDisk.optString("auth_key"))

            // profiles.json is byte-identical to before the call —
            // profile "home" still has its OLD snapshot.
            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            deleteRecursively(tmp)
        }
    }

    /**
     * Same injected failure on applyProfile (switch path): step 2
     * fails AFTER step 1 succeeds → ApplyResult.PartialConfigOnly,
     * config.json updated, profiles.json unchanged.
     */
    @Test
    fun applyProfile_profiles_write_failure_returns_partial() {
        ProfileStore.upsert(ctx, "home", MhrvConfig(authKey = "homekey"))
        ProfileStore.upsert(ctx, "other", MhrvConfig(authKey = "otherkey"))
        val profilesBefore = profilesFile.readText()
        assertEquals("other", ProfileStore.load(ctx).active)

        val tmp = File(ctx.filesDir, "profiles.json.tmp")
        tmp.delete()
        tmp.mkdirs()
        File(tmp, "sentinel").writeText("x")

        try {
            val r = ProfileStore.applyProfile(ctx, "home")
            assertTrue(
                "expected PartialConfigOnly, got ${r::class.simpleName}",
                r is ProfileStore.ApplyResult.PartialConfigOnly,
            )

            val onDisk = JSONObject(configFile.readText())
            assertEquals("homekey", onDisk.optString("auth_key"))

            assertEquals(profilesBefore, profilesFile.readText())
        } finally {
            deleteRecursively(tmp)
        }
    }
}
