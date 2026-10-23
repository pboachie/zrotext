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
