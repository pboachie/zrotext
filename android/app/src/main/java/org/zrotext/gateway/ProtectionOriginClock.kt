// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Setup-only clock. The caller must first correlate the actual challenge to its original
 * proof request and SAME authenticated host/epoch. This does not use a conversation session
 * or turn historical acceptance/status into effect permission. */
internal class ProtectionOriginClock private constructor(
    private val issuedMs: Long, private val receivedElapsedMs: Long, private val rttMs: Long,
    private val expiresMs: Long
) {
    private var lastElapsedMs = receivedElapsedMs
    private var withdrawn = false
    @Synchronized fun requireSigningTime(actualElapsedMs: Long): Long {
        try {
            require(!withdrawn && actualElapsedMs >= lastElapsedMs && actualElapsedMs >= receivedElapsedMs)
            val upper = Math.addExact(Math.addExact(issuedMs, rttMs), actualElapsedMs - receivedElapsedMs)
            require(upper >= issuedMs && upper < expiresMs)
            lastElapsedMs = actualElapsedMs
            return upper
        } catch (failure: Exception) {
            withdrawn = true // Observed expiry/regression cannot be undone by a later old reading.
            throw failure
        }
    }
    override fun toString() = "ProtectionOriginClock(setup-only)"
    companion object {
        fun fromChallenge(core: ProtectionOriginProof.Core, sentElapsedMs: Long,
            receivedElapsedMs: Long): ProtectionOriginClock {
            require(sentElapsedMs >= 0 && receivedElapsedMs >= sentElapsedMs)
            val rtt = receivedElapsedMs - sentElapsedMs
            require(rtt <= 2_000)
            return ProtectionOriginClock(core.issuedMs, receivedElapsedMs, rtt, core.expiresMs).also {
                it.requireSigningTime(receivedElapsedMs)
            }
        }
    }
}
