package com.therealaleph.mhrv

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for `MhrvConfig.toJson()` and the shared
 * `loadFromJson()` path that handles the `fronting_groups`
 * field. These pin the JSON-shape contract that flows:
 *
 *   `MhrvConfig` (Kotlin)
 *      → `toJson()` JSON string
 *      → Rust `Config` deserialization via `serde_json`
 *      → `proxy_server::ProxyServer::new()`
 *
 * Drift between Android encode and Rust deserialize is the single
 * highest-risk regression vector for this feature, because nothing
 * else exercises the wire format end-to-end except a manual install.
 *
 * Tests below use the real `org.json:json` artifact pulled in via
 * `testImplementation` in `build.gradle.kts` — Android's stub
 * `JSONObject` in `android.jar` throws at runtime in unit tests, so
 * the dependency is required, not optional.
 */
class ConfigStoreFrontingGroupsTest {

    @Test
    fun toJson_includes_fronting_groups_in_canonical_shape() {
        val cfg = MhrvConfig(
            mode = Mode.DIRECT,
            frontingGroups = listOf(
                FrontingGroup(
                    name = "fastly",
                    ip = "151.101.0.223",
                    sni = "python.org",
                    domains = listOf("reddit.com", "github.com"),
                ),
                FrontingGroup(
                    name = "akamai",
                    ip = "2.22.151.143",
                    sni = "www.bbc.com",
                    domains = listOf("microsoft.com"),
                ),
            ),
        )
        val parsed = JSONObject(cfg.toJson())
        // Field name MUST be snake_case `fronting_groups` to match
        // serde's deserialization on the Rust side. Don't rename.
        assertTrue("fronting_groups missing", parsed.has("fronting_groups"))

        val groups = parsed.getJSONArray("fronting_groups")
        assertEquals(2, groups.length())

        val first = groups.getJSONObject(0)
        assertEquals("fastly", first.getString("name"))
        assertEquals("151.101.0.223", first.getString("ip"))
        assertEquals("python.org", first.getString("sni"))
        val firstDomains = first.getJSONArray("domains")
        assertEquals(2, firstDomains.length())
        assertEquals("reddit.com", firstDomains.getString(0))
        assertEquals("github.com", firstDomains.getString(1))

        val second = groups.getJSONObject(1)
        assertEquals("akamai", second.getString("name"))
    }

    @Test
    fun toJson_drops_draft_groups_with_no_domains() {
        // `Config::validate()` on the Rust side rejects fronting
        // groups whose `domains` list is empty, so the proxy refuses
        // to start. The UI keeps draft groups visible (user is mid-
        // configuration) but the serializer must filter them out
        // before they reach disk / Native.startProxy. This test
        // pins that filter.
        val cfg = MhrvConfig(
            mode = Mode.DIRECT,
            frontingGroups = listOf(
                // Draft — no domains. Must be dropped.
                FrontingGroup(name = "draft", ip = "1.2.3.4", sni = "x.test", domains = emptyList()),
                // Draft via whitespace-only entries. Must be dropped.
                FrontingGroup(name = "whitespace", ip = "5.6.7.8", sni = "y.test", domains = listOf(" ", "\t", "")),
                // Real. Must survive.
                FrontingGroup(name = "real", ip = "9.9.9.9", sni = "z.test", domains = listOf("site.test")),
            ),
        )
        val parsed = JSONObject(cfg.toJson())
        val groups = parsed.getJSONArray("fronting_groups")
        assertEquals("only real group should survive", 1, groups.length())
        assertEquals("real", groups.getJSONObject(0).getString("name"))
    }

    @Test
    fun toJson_omits_field_when_no_groups_configured_at_all() {
        // Keep the on-disk JSON small for first-time users who
        // never touch fronting groups. Empty array would still
        // deserialize correctly on the Rust side but adds noise.
        val cfg = MhrvConfig(frontingGroups = emptyList())
        val parsed = JSONObject(cfg.toJson())
        assertFalse(
            "empty fronting_groups should be omitted entirely",
            parsed.has("fronting_groups"),
        )
    }

    @Test
    fun load_round_trips_fronting_groups_through_toJson() {
        // Full round-trip: build a config, serialize, parse via the
        // shared loadFromJson, check the result matches input. This
        // pins both the encoder AND the decoder; a drift on either
        // side breaks this test.
        val original = MhrvConfig(
            mode = Mode.DIRECT,
            frontingGroups = listOf(
                FrontingGroup(
                    name = "vercel",
                    ip = "76.76.21.21",
                    sni = "react.dev",
                    domains = listOf("vercel.com", "vercel.app", "nextjs.org"),
                ),
            ),
        )
        val json = original.toJson()
        val reloaded = ConfigStore.decode(json)
        assertTrue("decode returned null on valid JSON", reloaded != null)
        val groups = reloaded!!.frontingGroups
        assertEquals(1, groups.size)
        assertEquals("vercel", groups[0].name)
        assertEquals("76.76.21.21", groups[0].ip)
        assertEquals("react.dev", groups[0].sni)
        assertEquals(listOf("vercel.com", "vercel.app", "nextjs.org"), groups[0].domains)
    }

    @Test
    fun load_skips_groups_missing_required_fields() {
        // Defensive parse: a JSON entry missing `name` / `ip` / `sni`
        // is silently dropped rather than crashing the load. The
        // Rust side has stricter validation but it errors with a
        // clear message; for the Android UI we want to keep the
        // app launchable even on a partially-corrupted config so
        // the user can fix it.
        val json = """
            {
              "mode": "direct",
              "fronting_groups": [
                {"name": "ok", "ip": "1.1.1.1", "sni": "a.test", "domains": ["d.test"]},
                {"name": "", "ip": "2.2.2.2", "sni": "b.test", "domains": ["d.test"]},
                {"ip": "3.3.3.3", "sni": "c.test", "domains": ["d.test"]},
                {"name": "no-sni", "ip": "4.4.4.4", "domains": ["d.test"]}
              ]
            }
        """.trimIndent()
        val reloaded = ConfigStore.decode(json)
        assertTrue(reloaded != null)
        val groups = reloaded!!.frontingGroups
        assertEquals("only fully-specified entry should survive", 1, groups.size)
        assertEquals("ok", groups[0].name)
    }
}
