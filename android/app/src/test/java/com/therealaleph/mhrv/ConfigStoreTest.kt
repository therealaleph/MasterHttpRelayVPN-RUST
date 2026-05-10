package com.therealaleph.mhrv

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the [ConfigStore.toJson] / [ConfigStore.loadFromJson]
 * round trip, with a focus on `fronting_groups` — which the Android UI
 * silently dropped on Save before this round of work. These tests exist
 * specifically to catch regressions of that data-loss path.
 *
 * The encode/decode (Base64 + DEFLATE) wrapper around the same JSON is
 * not tested here because `android.util.Base64` is stubbed in JVM unit
 * tests; the JSON payload it wraps is the same code path covered below.
 */
class ConfigStoreTest {
    private val sampleGroups = listOf(
        FrontingGroup(
            name = "github-direct",
            ip = "140.82.121.4",
            sni = "github.com",
            domains = listOf("gist.github.com"),
        ),
        FrontingGroup(
            name = "vercel",
            ip = "76.76.21.21",
            sni = "react.dev",
            domains = listOf("vercel.com", "vercel.app", "nextjs.org"),
        ),
    )

    @Test
    fun frontingGroups_roundTripsThroughJson() {
        val cfg = MhrvConfig(
            mode = Mode.DIRECT,
            frontingGroups = sampleGroups,
        )

        val json = cfg.toJson()
        val parsed = ConfigStore.loadFromJson(JSONObject(json))

        assertEquals(
            "fronting_groups must round-trip exactly — order, fields, and all",
            sampleGroups,
            parsed.frontingGroups,
        )
    }

    @Test
    fun frontingGroups_emptyListProducesNoKey() {
        val cfg = MhrvConfig(frontingGroups = emptyList())
        val json = JSONObject(cfg.toJson())
        // Skipping the key when empty matches the pattern used for the
        // other optional list fields (passthrough_hosts, sni_hosts) and
        // keeps the saved file tidy for users who don't use the feature.
        assertTrue(
            "fronting_groups should be omitted when the list is empty",
            !json.has("fronting_groups"),
        )
    }

    @Test
    fun frontingGroups_loadIgnoresMalformedEntries() {
        // Half-empty entries (missing ip / sni / domains) used to leak
        // through if the user hand-edited config.json. The Rust validator
        // would reject them at startup; the Kotlin loader skips them on
        // read so the UI never sees broken state.
        val raw = """
            {
              "mode": "direct",
              "fronting_groups": [
                {"name": "ok", "ip": "1.2.3.4", "sni": "example.com",
                 "domains": ["example.com"]},
                {"name": "no-ip", "ip": "", "sni": "x.com",
                 "domains": ["x.com"]},
                {"name": "no-domains", "ip": "1.2.3.4", "sni": "x.com",
                 "domains": []},
                {"name": "missing-fields"}
              ]
            }
        """.trimIndent()

        val parsed = ConfigStore.loadFromJson(JSONObject(raw))

        assertEquals(1, parsed.frontingGroups.size)
        assertEquals("ok", parsed.frontingGroups[0].name)
    }

    @Test
    fun frontingGroups_unknownConfigKeysIgnored() {
        // Curated.json carries a `_comment` array that JSONObject would
        // happily round-trip if the loader weren't selective. This test
        // pins that the loader only reads fields it knows about — same
        // defense the Rust serde layer gives us automatically.
        val raw = """
            {
              "mode": "direct",
              "_comment": ["a", "b"],
              "fronting_groups": [
                {"name": "g", "ip": "1.2.3.4", "sni": "s.example",
                 "domains": ["d.example"]}
              ]
            }
        """.trimIndent()

        val parsed = ConfigStore.loadFromJson(JSONObject(raw))

        assertEquals(1, parsed.frontingGroups.size)
        assertEquals(Mode.DIRECT, parsed.mode)
    }
}
