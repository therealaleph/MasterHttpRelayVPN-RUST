package com.therealaleph.mhrv.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the JSON contract between `Java_com_therealaleph_mhrv_Native_discoverFront`
 * (Rust, in src/android_jni.rs) and `parseDiscoverResult` (Kotlin, in
 * HomeScreen.kt). The Rust side now uses `serde_json::json!` so it
 * produces canonical JSON, but the parser still has to handle:
 *   - mixed ok=true / ok=false rows
 *   - top-level error (resolve / DNS failed) vs per-IP error
 *   - missing or zero-length `ips` array
 *
 * Drift between the two sides shows up as the UI silently rendering
 * nothing or rendering an Error variant the user can't act on.
 */
class DiscoverParserTest {

    @Test
    fun done_with_mix_of_ok_and_failed_rows() {
        // Canonical success payload — one reachable IP, one timed out.
        val json = """
            {
              "hostname": "python.org",
              "ips": [
                {"ip": "151.101.0.223", "ok": true, "latencyMs": 45},
                {"ip": "151.101.64.223", "ok": false, "error": "connect timeout"}
              ]
            }
        """.trimIndent()
        val s = parseDiscoverResult(json)
        assertTrue("expected Done, got $s", s is DiscoverState.Done)
        s as DiscoverState.Done
        assertEquals("python.org", s.hostname)
        assertEquals(2, s.ips.size)

        val ok = s.ips[0]
        assertEquals("151.101.0.223", ok.ip)
        assertTrue(ok.ok)
        assertEquals(45, ok.latencyMs)
        assertNull(ok.error)

        val bad = s.ips[1]
        assertEquals("151.101.64.223", bad.ip)
        assertTrue(!bad.ok)
        assertNull(bad.latencyMs)
        assertEquals("connect timeout", bad.error)
    }

    @Test
    fun top_level_error_becomes_error_state() {
        // Resolve itself failed — no `ips` array at all. The UI
        // must render an Error pill, not a "0 of 0 IPs" success.
        val json = """{"hostname":"bogus.invalid","error":"dns: NXDOMAIN"}"""
        val s = parseDiscoverResult(json)
        assertTrue("expected Error, got $s", s is DiscoverState.Error)
        s as DiscoverState.Error
        assertEquals("bogus.invalid", s.hostname)
        assertEquals("dns: NXDOMAIN", s.message)
    }

    @Test
    fun empty_ips_array_renders_as_done_zero_ok() {
        // Edge case: DNS resolved but every IP was filtered out as
        // non-public by the Rust public-IP filter. The Rust side
        // returns a top-level error in that case ("all N resolved
        // addresses were non-public"), so we shouldn't see this in
        // practice — but if a future Rust change returns an empty
        // `ips` array, the parser should still produce a Done with
        // a 0/0 banner rather than a silent no-op.
        val json = """{"hostname":"x.test","ips":[]}"""
        val s = parseDiscoverResult(json)
        assertTrue(s is DiscoverState.Done)
        s as DiscoverState.Done
        assertEquals(0, s.ips.size)
    }

    @Test
    fun rows_with_non_ascii_error_text_round_trip() {
        // Regression guard for hand-rolled JSON escaping the
        // earlier code used. serde_json on the Rust side now
        // handles control chars + non-ASCII automatically, but
        // the parser still needs to receive the bytes correctly.
        // Persian, Chinese, and control-char (\n) in error text.
        val json = """
            {
              "hostname": "x.test",
              "ips": [
                {"ip": "1.1.1.1", "ok": false, "error": "اتصال رد شد"},
                {"ip": "2.2.2.2", "ok": false, "error": "无法连接"},
                {"ip": "3.3.3.3", "ok": false, "error": "line1\nline2"}
              ]
            }
        """.trimIndent()
        val s = parseDiscoverResult(json)
        assertTrue(s is DiscoverState.Done)
        s as DiscoverState.Done
        assertEquals("اتصال رد شد", s.ips[0].error)
        assertEquals("无法连接", s.ips[1].error)
        assertEquals("line1\nline2", s.ips[2].error)
    }

    @Test
    fun null_or_blank_input_returns_error() {
        // Native side returns null/empty if the JNI bridge itself
        // failed (e.g. tokio runtime init). UI should surface that
        // rather than appearing frozen.
        val nullCase = parseDiscoverResult(null)
        assertTrue(nullCase is DiscoverState.Error)
        val blankCase = parseDiscoverResult("")
        assertTrue(blankCase is DiscoverState.Error)
    }

    @Test
    fun malformed_json_returns_error_not_crash() {
        // A garbage payload (corrupted JNI return, truncated socket
        // read, etc.) must produce an Error variant the UI renders
        // — never a thrown JSONException that crashes the user out
        // of the Discover panel. The parser catches Throwables for
        // exactly this reason.
        val s = parseDiscoverResult("not actually json {{{")
        assertTrue("expected Error, got $s", s is DiscoverState.Error)
    }
}
