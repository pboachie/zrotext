// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** RAM-only upper time from ONE actual same-host nonce read. No history JSON, constructor,
 * key alias, projection flag or cold journal row can publish an accepted observation. */
internal object TypedHistory03Clock {
    class Sample internal constructor(private val owner: TypedHistory03Connections.Host,
        private val original: TypedHistory03Request, private val actualReply: TypedHistory03Wire.Reply,
        private val receivedElapsedMs: Long, private val rttMs: Long, private val exact: ByteArray) {
        private var lastElapsedMs = receivedElapsedMs
        val requestId get() = original.requestId
        fun bytes() = exact.copyOf()
        @Synchronized fun nowFor(row: TypedSubmit03Record, request: TypedHistory03Request): Long {
            owner.requireObservation(this)
            require(request.entered && request.copy(replyB64url = null) == original &&
                request.replyB64url?.let { TypedSubmit03Record.unbase(it).contentEquals(exact) } == true)
            request.requireOriginal(row)
            owner.requireOriginal(row)
            val elapsed = owner.elapsedMs()
            require(elapsed >= lastElapsedMs && rttMs in 0..2000)
            val now = Math.addExact(Math.addExact(actualReply.serverMs, rttMs), elapsed - receivedElapsedMs)
            require(now < actualReply.sampleExpiresMs && now < actualReply.leaseExpiresMs)
            owner.requireObservation(this)
            lastElapsedMs = elapsed
            return now
        }
        /** Separate proof-only observation checks. Actual primary and conservative upper
         * are independent; RTT can never conceal a primary regression below core issuance. */
        @Synchronized internal fun proofNow(row: TypedSubmit03Record, request: TypedHistory03Request,
            proof: TypedNoSubmit03Proof): Long {
            require(request.subjectKind == "proof" && request.subjectId == proof.requestId)
            proof.requireOriginal(row)
            val core = proof.challenge().core
            val upper = nowFor(row, request)
            require(actualReply.serverMs >= core.issuedMs && core.number(2) == owner.epoch &&
                core.number(3) == actualReply.deploymentEpoch && core.expiresMs <= actualReply.leaseExpiresMs &&
                core.digest(3).contentEquals(actualReply.sessionDigest()) && upper < core.expiresMs)
            owner.requireOriginal(row); return upper
        }
        @Synchronized internal fun requireExpiredProof(row: TypedSubmit03Record, request: TypedHistory03Request,
            core: TypedNoSubmit03Core) {
            require(proofExpired(row, request, core))
        }
        @Synchronized internal fun proofExpired(row: TypedSubmit03Record, request: TypedHistory03Request,
            core: TypedNoSubmit03Core): Boolean {
            require(request.subjectKind == "proof" && request.subjectId == core.proofRequestId)
            nowFor(row, request)
            return actualReply.serverMs >= core.expiresMs
        }
        /** Initial publication checks time before any candidate-result append or Room wait. */
        @Synchronized internal fun requireLiveAtPublication(): Long {
            owner.requireCurrent()
            val elapsed = owner.elapsedMs()
            require(elapsed >= lastElapsedMs && rttMs in 0..2000)
            return Math.addExact(Math.addExact(actualReply.serverMs, rttMs), elapsed - receivedElapsedMs).also {
                require(it < actualReply.sampleExpiresMs && it < actualReply.leaseExpiresMs)
                owner.requireCurrent()
                lastElapsedMs = elapsed
            }
        }
        override fun toString() = "TypedHistory03Clock(actual-passive-observation)"
    }
}
