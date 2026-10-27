// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Explicit new complete-SIM observation for SAME-phone reapproval. These are pending local
 * observations only: no owner approval, signature, writer ACK, live installation or Ready03.
 */
internal class SamePhoneSelectionReview(private val inputs: Inputs) : AutoCloseable {
    interface Inputs {
        fun withdrawInstalled()
        fun retained(): Retained
        fun captureFresh(): SelectedLineLeaseV2?
        fun nowMs(): Long
        fun requireSession()
    }
    /** Exact retained public journal metadata, not proof of current physical SIM continuity. */
    class Retained(val origins: Profile03Origins, val binding: LocalLineBinding, val activation: LineActivationV2Record,
        val election: Profile03ElectionRecord, enrollmentPoint: ByteArray) {
        private val point = enrollmentPoint.copyOf()
        fun point() = point.copyOf()
        init {
            activation.requireShape(); election.requireShape()
            require(binding.protocolVersion == 2 && binding.v2Purpose == "sealed" && activation.isInstalled() &&
                activation.matchesBinding(binding) && election.state == "installed" &&
                election.accountId == binding.accountId && election.deviceId == binding.deviceId &&
                election.lineId == binding.lineId && election.oldGeneration == binding.generation &&
                origins.routing.accountId == binding.accountId && origins.routing.deviceId == binding.deviceId &&
                activation.originHash == origins.routingHash && election.originHash == origins.protocolHash &&
                activation.signerFingerprint == hex(sha(point)))
            DevicePayloadKeyStore.decodePoint(point)
            val core = Profile03ElectionEncoding.decode(election.coreB64url, 500)
            require(MessageDigest.isEqual(core.copyOfRange(288, 320),
                sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)))
        }
        fun same(other: Retained) = origins.routing == other.origins.routing && origins.protocolOrigin == other.origins.protocolOrigin &&
            binding == other.binding && activation == other.activation &&
            election == other.election && MessageDigest.isEqual(point, other.point)
        override fun toString() = "RetainedSamePhoneMetadata(historical-only)"
    }
    class Review private constructor(val account: UUID, val device: UUID, val line: UUID,
        val selectedSubscription: Int, val oldGeneration: Long, val selectedGeneration: Long,
        val newObservationKind: LineActivationV2Kind, val completeSimCount: Int,
        private val retained: Retained, private val lease: SelectedLineLeaseV2,
        private val preparedMs: Long, private val expiresMs: Long,
    ) {
        override fun toString() = "SamePhoneSelectionReview(pending, redacted)"
        companion object {
            internal fun create(retained: Retained, lease: SelectedLineLeaseV2, now: Long): Review {
                val observation = java.nio.ByteBuffer.wrap(lease.observation().bytes())
                val count = observation.getShort(2).toInt() and 65535
                val kind = when (observation.get(8).toInt()) {
                    1 -> LineActivationV2Kind.PHYSICAL
                    2 -> LineActivationV2Kind.EMBEDDED
                    else -> error("Selected SIM kind")
                }
                return Review(UUID.fromString(retained.binding.accountId), UUID.fromString(retained.binding.deviceId),
                    UUID.fromString(retained.binding.lineId), lease.selected.subscriptionId,
                    retained.binding.generation, retained.election.newGeneration, kind, count, retained, lease,
                    now, Math.addExact(now, REVIEW_MS))
            }
        }
        internal fun requireCurrent(inputs: Inputs, instant: Long) {
            requireTimeAndLease(instant)
            requireCurrentSelection(inputs, retained, lease)
        }
        internal fun requireTimeAndLease(instant: Long) {
            check(instant >= preparedMs && instant < expiresMs && lease.isCurrent())
        }
        internal fun requireCurrentSelectionOnly(inputs: Inputs) = requireCurrentSelection(inputs, retained, lease)
        internal fun requireLeaseOnly() { check(lease.isCurrent()) }
        internal fun pending(confirmedMs: Long, live: () -> Unit, ram: () -> Unit) = Pending(retained, lease, UUID.randomUUID(),
            confirmedMs, Math.addExact(confirmedMs, PENDING_MS), live, ram)
    }
    /** A phone decision only. Owner/MFA/signature acceptance must still be independently obtained
     * over a separately reviewed refresh operation before any live permit may be published.
     */
    class Pending internal constructor(val retained: Retained, private val lease: SelectedLineLeaseV2,
        val consentId: UUID, val confirmedMs: Long, val expiresMs: Long, private val live: () -> Unit,
        private val ram: () -> Unit) {
        fun observation(): ByteArray { live(); return lease.observation().bytes().also { live() } }
        fun requireCurrent() = live()
        internal fun currentLease(): SelectedLineLeaseV2 { live(); return lease.also { live() } }
        /** For an already held Room/custody boundary: no key, root storage or database lookup. */
        internal fun requireRamCurrent() = ram()
        override fun toString() = "SamePhoneSelectionPending(no-owner-or-effect-permission)"
    }
    @Volatile private var closed = false
    private val lock = Any()
    private val reviewEpoch = java.util.concurrent.atomic.AtomicLong(0)
    private var shown: Review? = null
    private var pending: Pending? = null
    private val lastNow = java.util.concurrent.atomic.AtomicLong(0)
    private fun now(): Long {
        check(!closed); inputs.requireSession()
        val value = inputs.nowMs()
        while (true) {
            val prior = lastNow.get()
            check(!closed && value > 0 && value >= prior)
            if (lastNow.compareAndSet(prior, value)) return value
        }
    }
    fun prepare(): Review? = synchronized(lock) {
        val expectedEpoch = reviewEpoch.incrementAndGet()
        shown = null; pending = null
        runCatching {
            now()
            inputs.withdrawInstalled() // Withdraw sending before any complete review/provider wait.
            val retained = inputs.retained()
            val lease = checkNotNull(inputs.captureFresh())
            requireCurrentSelection(inputs, retained, lease)
            Review.create(retained, lease, now()).also {
                check(reviewEpoch.get() == expectedEpoch && !closed)
                shown = it
            }
        }.getOrNull()
    }
    fun confirm(displayed: Review): Boolean = synchronized(lock) {
        if (shown !== displayed || closed) return false
        val expectedEpoch = reviewEpoch.get()
        shown = null // A failed decision is consumed too; redisplay the actual current values.
        runCatching {
            val instant = now()
            displayed.requireCurrent(inputs, instant)
            val confirmed = now()
            displayed.requireTimeAndLease(confirmed)
            check(reviewEpoch.get() == expectedEpoch && !closed)
            lateinit var accepted: Pending
            fun ram() {
                check(!closed && reviewEpoch.get() == expectedEpoch)
                val current = now()
                check(current >= accepted.confirmedMs && current < accepted.expiresMs)
                displayed.requireLeaseOnly()
            }
            accepted = displayed.pending(confirmed, {
                ram()
                displayed.requireCurrentSelectionOnly(inputs)
                val completed = now()
                check(completed >= accepted.confirmedMs && completed < accepted.expiresMs &&
                    !closed && reviewEpoch.get() == expectedEpoch)
                displayed.requireLeaseOnly()
            }, ::ram)
            pending = accepted
            accepted.requireCurrent()
            true
        }.getOrElse { pending = null; false }
    }
    /** Returns only the exact once-confirmed pending decision; no signature or permit is issued. */
    fun takePending(): Pending? = synchronized(lock) {
        val value = pending ?: return null
        pending = null
        runCatching { value.requireCurrent(); value }.getOrNull()
    }
    fun cancel() { reviewEpoch.incrementAndGet(); synchronized(lock) { shown = null; pending = null } }
    override fun close() { closed = true; cancel() }
    override fun toString() = "SamePhoneSelectionReview(redacted)"
    companion object {
        private const val REVIEW_MS = 30_000L
        private const val PENDING_MS = 300_000L
        private fun requireCurrentSelection(inputs: Inputs, retained: Retained, lease: SelectedLineLeaseV2) {
            inputs.requireSession()
            check(lease.selected.subscriptionId == retained.binding.subscriptionId &&
                lease.isCurrent() && inputs.captureFresh() === lease && lease.recheck() &&
                inputs.retained().same(retained) && inputs.captureFresh() === lease && lease.isCurrent())
            inputs.requireSession()
        }
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    }
}
