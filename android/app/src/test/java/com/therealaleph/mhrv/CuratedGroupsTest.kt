package com.therealaleph.mhrv

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * JVM unit tests for [CuratedGroups.mergeInto]. The asset-loading half
 * (`loadCurated`) needs `android.content.Context` and is exercised
 * end-to-end by the desktop tests against the canonical curated.json,
 * so this file focuses on the merge semantics that decide whether a
 * user's hand-edited group survives the curated bundle being applied.
 */
class CuratedGroupsTest {
    private val curated = listOf(
        FrontingGroup("vercel", "76.76.21.21", "react.dev", listOf("vercel.com")),
        FrontingGroup("fastly", "151.101.0.223", "pypi.org", listOf("reddit.com")),
    )

    @Test
    fun emptyExisting_addsAllCurated() {
        val (merged, report) = CuratedGroups.mergeInto(emptyList(), curated)

        assertEquals(2, report.added)
        assertEquals(0, report.skipped)
        assertEquals(curated, merged)
    }

    @Test
    fun nameCollision_preservesUserEntry() {
        val userVercel = FrontingGroup(
            name = "vercel",
            ip = "1.2.3.4",
            sni = "user-edited.example",
            domains = listOf("user.example"),
        )
        val (merged, report) = CuratedGroups.mergeInto(listOf(userVercel), curated)

        assertEquals(1, report.added)
        assertEquals(1, report.skipped)
        // The user's vercel entry must be untouched — overwriting it
        // would silently destroy their hand-tuning. fastly should be
        // appended.
        val mergedVercel = merged.first { it.name == "vercel" }
        assertEquals(userVercel, mergedVercel)
        assertNotEquals(curated[0], mergedVercel)
    }

    @Test
    fun nameMatchIsCaseInsensitive() {
        // Real configs end up mixed-case after a copy/paste. "Vercel" /
        // " VERCEL " / "vercel" are all the same group as far as the
        // matcher is concerned.
        val userMixed = FrontingGroup("VERCEL", "1.1.1.1", "x", listOf("x.example"))
        val (_, report) = CuratedGroups.mergeInto(listOf(userMixed), curated)
        assertEquals(1, report.skipped)

        val userPadded = FrontingGroup(" vercel ", "1.1.1.1", "x", listOf("x.example"))
        val (_, paddedReport) = CuratedGroups.mergeInto(listOf(userPadded), curated)
        assertEquals(
            "Trim should be applied before case-insensitive compare",
            1, paddedReport.skipped,
        )
    }

    @Test
    fun mergeIsPure_doesNotMutateCallerList() {
        val existing = mutableListOf(
            FrontingGroup("user-only", "10.0.0.1", "x", listOf("x.example")),
        )
        val before = existing.toList()
        CuratedGroups.mergeInto(existing, curated)
        assertEquals(
            "mergeInto must not mutate the caller-supplied existing list",
            before, existing,
        )
    }
}
