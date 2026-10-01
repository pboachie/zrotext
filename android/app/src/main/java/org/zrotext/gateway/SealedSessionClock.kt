// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Bounded trusted session time for sealed execution (roadmap #628).
 *
 * Hub wall time is untrusted on its own; the phone anchors one trusted sample
 * (taken when the authenticated session proved the server) to the monotonic
 * elapsed clock and derives later times from the difference. The anchor is
 * only valid within one connection epoch and only while the monotonic clock
 * has not reset:
 *
 * - **Reboot invalidation:** `elapsedRealtime` resets at boot, so an elapsed
 *   reading at or below the anchor's cannot belong to this boot; time becomes
 *   unavailable rather than silently wrong.
 * - **Session invalidation:** the anchor belongs to one `connectionEpoch`; a
 *   clock from another epoch never matches, so a stale clock cannot vouch for
 *   a new session's grants.
 * - **Staleness bound:** an anchor older than [MAX_ANCHOR_AGE_MS] is refused,
 *   because hub drift grows with anchor age and a grant far from its anchor
 *   is exactly the replay shape the 35-second grant window exists to stop.
 * - **Unavailability:** [SealedDispatchExecutor] treats a null time as a
 *   refusal; the clock never invents a fallback wall time.
 */
internal class SealedSessionClock private constructor(
    private val connectionEpoch: Long,
    private val anchorHubMs: Long,
    private val anchorElapsedMs: Long,
) {
    /**
     * Trusted hub time now, or null when the monotonic reading predates the
     * anchor (reboot) or the anchor has aged out. Never falls back to the
     * local wall clock.
     */
    fun nowMs(currentElapsedMs: Long): Long? {
        if (currentElapsedMs <= anchorElapsedMs) return null
        val ageMs = currentElapsedMs - anchorElapsedMs
        if (ageMs > MAX_ANCHOR_AGE_MS) return null
        return anchorHubMs + ageMs
    }

    /** True only while the caller's session is the epoch this clock anchored. */
    fun isCurrentSession(currentConnectionEpoch: Long): Boolean =
        currentConnectionEpoch == connectionEpoch

    companion object {
        /**
         * A session clock is usable for one minute of monotonic age. Grant
         * expiries sit at most 35 seconds ahead of trusted time, so a fresh
         * anchor inside this bound cannot make an expired grant look live.
         */
        const val MAX_ANCHOR_AGE_MS: Long = 60_000

        /**
         * Establishes the session clock from one trusted hub sample. The
         * anchor itself is refused when the epoch is not positive or the hub
         * sample is not a sane wall time, because a broken anchor poisons
         * every later derivation.
         */
        fun establish(
            connectionEpoch: Long,
            trustedHubMs: Long,
            anchorElapsedMs: Long,
        ): SealedSessionClock? {
            if (connectionEpoch <= 0 || trustedHubMs <= 0 || anchorElapsedMs < 0) return null
            return SealedSessionClock(connectionEpoch, trustedHubMs, anchorElapsedMs)
        }
    }
}
