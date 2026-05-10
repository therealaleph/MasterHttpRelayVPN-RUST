package com.therealaleph.mhrv

import android.content.Context
import android.util.Log
import java.io.IOException
import org.json.JSONException
import org.json.JSONObject

/**
 * Loader + merger for the curated fronting-group bundle shipped at
 * `assets/fronting-groups/curated.json` (synced from the Rust crate's
 * canonical copy at repo-root `assets/fronting-groups/curated.json` by
 * the `syncFrontingGroupsAssets` Gradle task).
 *
 * Same shape as `src/curated_groups.rs` on the Rust side: `mergeInto`
 * appends groups whose `name` isn't already present, leaving the user's
 * hand-edited entries alone. There's no in-app editor for the entries
 * yet, so this is the no-typing path to install Vercel / Fastly /
 * AWS-CloudFront / direct-GitHub coverage.
 *
 * Edge IPs rotate. If a group stops working, the remediation is the
 * same as desktop: re-resolve `sni` (`nslookup <sni>`) and edit the IP
 * by hand in `config.json`. There's no IP-refresh button in the UI yet.
 */
object CuratedGroups {
    private const val TAG = "CuratedGroups"
    private const val ASSET_PATH = "fronting-groups/curated.json"

    /** Result of [mergeInto], surfaced to the UI for snackbar text. */
    data class MergeReport(val added: Int, val skipped: Int)

    /**
     * Read the bundled curated.json from APK assets and parse the
     * `fronting_groups` array. Returns null on a packaging or parse
     * failure (UI surfaces a generic toast); both failure modes are
     * also logged at warn so a user reporting "the button does
     * nothing" can be debugged from logcat. Anything else propagates
     * — we don't want to swallow `OutOfMemoryError` or a coding bug
     * (NPE / IndexOutOfBounds) just because the call site is a
     * button-tap.
     */
    fun loadCurated(ctx: Context): List<FrontingGroup>? {
        val json = try {
            ctx.assets.open(ASSET_PATH).bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            Log.w(TAG, "asset $ASSET_PATH unreadable", e)
            return null
        }

        val arr = try {
            JSONObject(json).optJSONArray("fronting_groups")
        } catch (e: JSONException) {
            Log.w(TAG, "asset $ASSET_PATH is not valid JSON", e)
            return null
        } ?: return null

        return buildList {
            for (i in 0 until arr.length()) {
                val g = arr.optJSONObject(i) ?: continue
                val name = g.optString("name").trim()
                val ip = g.optString("ip").trim()
                val sni = g.optString("sni").trim()
                val domArr = g.optJSONArray("domains") ?: continue
                val domains = buildList {
                    for (j in 0 until domArr.length()) {
                        val d = domArr.optString(j).trim()
                        if (d.isNotEmpty()) add(d)
                    }
                }
                if (name.isEmpty() || ip.isEmpty() || sni.isEmpty() || domains.isEmpty()) continue
                add(FrontingGroup(name, ip, sni, domains))
            }
        }
    }

    /**
     * Append every curated group whose `name` isn't already in
     * [existing]. Names compare case-insensitively after trim — the
     * way humans actually edit configs. Returns a new list (does not
     * mutate [existing]) plus a report of how many were added vs.
     * already-present.
     */
    fun mergeInto(
        existing: List<FrontingGroup>,
        curated: List<FrontingGroup>,
    ): Pair<List<FrontingGroup>, MergeReport> {
        val merged = existing.toMutableList()
        var added = 0
        var skipped = 0
        for (g in curated) {
            val present = merged.any { it.name.trim().equals(g.name.trim(), ignoreCase = true) }
            if (present) {
                skipped += 1
            } else {
                merged.add(g)
                added += 1
            }
        }
        return merged to MergeReport(added, skipped)
    }
}
