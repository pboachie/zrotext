// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.telephony.SmsManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Internal candidate preparation, used only behind explicit authenticated execution admission. */
internal object Draft02OutboundPreparation {
    /** Local authenticated adapter contract, not a wire frame or authority inferred from an envelope. */
    data class Grant(
        val accountId: String, val messageId: String, val attemptId: String,
        val deviceId: String, val lineId: String, val bindingGeneration: Long,
        val attemptGeneration: Long, val connectionEpoch: Long, val deploymentEpoch: Long,
        val sessionId: String, val originHash: String, val unsignedDigest: String,
        val manifestGeneration: Long, val manifestVersion: Long, val manifestDigest: String,
        val recipientDigest: String, val expiresAtMs: Long, val subscriptionId: Int, val cardId: Int,
        val installedProfile: InstalledEsimProfile? = null
    ) {
        init {
            require(listOf(accountId, messageId, attemptId, deviceId, lineId, sessionId).all {
                runCatching { UUID.fromString(it).toString() == it && UUID.fromString(it) != UUID(0, 0) }.getOrDefault(false)
            } && listOf(originHash, unsignedDigest, manifestDigest, recipientDigest).all {
                it.matches(Regex("[0-9a-f]{64}"))
            } && listOf(bindingGeneration, attemptGeneration, connectionEpoch, deploymentEpoch,
                manifestGeneration, manifestVersion, expiresAtMs).all { it > 0 } &&
                subscriptionId >= 0 && cardId >= 0) { "Candidate grant shape" }
        }
        internal fun identity(): String {
            val physical = hash(listOf(accountId, messageId, attemptId, deviceId, lineId,
            bindingGeneration, attemptGeneration, connectionEpoch, deploymentEpoch, sessionId, originHash,
            unsignedDigest, manifestGeneration, manifestVersion, manifestDigest, recipientDigest,
            expiresAtMs, subscriptionId, cardId).joinToString("|").toByteArray(Charsets.US_ASCII))
            val record = installedProfile?.record ?: return physical
            return hash(listOf("ZROtext/profile-record-grant/v1", physical, record.subscriptionId,
                record.cardId, record.portIndex, record.logicalSlotIndex, record.incarnation,
                record.observationEpoch, record.leaseId).joinToString("|").toByteArray(Charsets.US_ASCII))
        }
        internal fun selectedSim(): ActivatedSimCard? = if (installedProfile == null)
            ActivatedSimCard(subscriptionId, cardId) else installedProfile.takeIf {
                it.isCurrent() && it.record.subscriptionId == subscriptionId && it.record.cardId == cardId &&
                    it.authority == ProfileLineAuthority(accountId, deviceId, lineId, bindingGeneration)
            }?.let { ActivatedSimCard(subscriptionId, cardId, it.candidate) }
        internal fun matchesBinding(binding: LocalLineBinding): Boolean =
            if (installedProfile == null) binding.continuityKind == "physical" && binding.liveContinuity()
            else installedProfile.isCurrent() && binding.installedProfile() === installedProfile &&
                binding.profileRecord() == installedProfile.record && binding.profileAuthority() == installedProfile.authority
        override fun toString() = "CandidateGrant(redacted)"
    }

    /** Must be independently obtained each time, including after waits; null means unavailable. */
    class Current(val grant: Grant, val authority: Draft02ManifestAuthority,
                  val request: Draft02ManifestAuthority.Request, val trustedNowMs: Long,
                  val selectedSubscriptionId: Int, activeCards: List<ActiveSimCard>?) {
        private val cards = activeCards?.toList()
        internal fun cards() = cards?.toList()
        override fun toString() = "CandidateCurrent(redacted)"
    }

    sealed interface Result
    data object Unavailable : Result
    data object Unsupported : Result
    data object Rejected : Result

    /** Same-process, one-use text ownership only; never an intent acknowledgement or radio token. */
    sealed interface Prepared : Result, AutoCloseable {
        val segmentCount: Int
        fun consume(consumer: (CharArray) -> Unit)
    }
    /** Relays the executor's existing guarded consume closure; never manufactures plaintext. */
    internal fun relayPrepared(segments: Int, consume: ((CharArray) -> Unit) -> Unit): Prepared =
        RelayPrepared(segments, consume)
    private class RelayPrepared(override val segmentCount: Int,
        private val action: ((CharArray) -> Unit) -> Unit) : Prepared {
            private var used = false
            override fun consume(consumer: (CharArray) -> Unit) {
                check(!used); used = true; action(consumer)
            }
            override fun close() { used = true }
        }
    private class OwnedPrepared(private var chars: CharArray?, override val segmentCount: Int,
                                private val recheck: () -> Unit) : Prepared {
        @Synchronized override fun consume(consumer: (CharArray) -> Unit) {
            val owned = chars ?: error("Preparation closed")
            chars = null
            try { recheck(); consumer(owned) } finally { owned.fill('\u0000') }
        }
        @Synchronized override fun close() { chars?.fill('\u0000'); chars = null }
        override fun toString() = "PreparedSealedText(redacted)"
    }

    private class UnsupportedCustody : RuntimeException()

    /**
     * No injectable recipient or software-key fallback. Live adapters intentionally do not exist.
     * A trusted UTC lease must become unavailable on reboot/cold load; wall time alone is invalid.
     */
    fun prepare(input: ByteArray, grant: Grant, db: SmsJournalDatabase,
                keyStore: DevicePayloadKeyStore, current: () -> Current?): Result {
        if (input.size !in 557..34_213) return Rejected
        val owned = input.copyOf() // Before any external callback or blocking acquisition.
        if (Build.VERSION.SDK_INT < 31) return Unsupported
        var lastNow = 0L
        var reserved = false
        var handedOff = false
        var verified: Draft02OutboundEnvelope? = null
        var clear: CharArray? = null
        val dao = db.sealedPreparations()
        val record = SealedPreparationRecord(grant.accountId, grant.messageId, grant.attemptId,
            grant.unsignedDigest, grant.identity())
        fun fresh(): Current {
            val live = current() ?: error("Freshness unavailable")
            require(live.grant == grant && live.trustedNowMs > 0 && live.trustedNowMs >= lastNow &&
                live.trustedNowMs < grant.expiresAtMs && grant.expiresAtMs - live.trustedNowMs <= 35_000) {
                "Candidate lease changed"
            }
            val context = live.authority.context(live.request, live.trustedNowMs)
            require(uuid(context.accountId) == grant.accountId && uuid(context.messageId) == grant.messageId &&
                uuid(context.deviceId) == grant.deviceId && uuid(context.lineId) == grant.lineId &&
                context.generation == grant.manifestGeneration && context.version == grant.manifestVersion &&
                hex(context.manifestDigest) == grant.manifestDigest && hash(context.peer) == grant.recipientDigest &&
                live.selectedSubscriptionId == grant.subscriptionId &&
                SimCardContinuity.matches(grant.selectedSim(), live.cards())) {
                "Candidate context changed"
            }
            verified?.checkContext(live.authority, live.request, live.trustedNowMs)
            lastNow = live.trustedNowMs
            return live
        }
        fun line(binding: LocalLineBinding?) {
            fresh()
            require(binding != null && binding.accountId == grant.accountId && binding.deviceId == grant.deviceId &&
                binding.lineId == grant.lineId && binding.generation == grant.bindingGeneration &&
                binding.subscriptionId == grant.subscriptionId && binding.cardId == grant.cardId &&
                grant.matchesBinding(binding)) { "Candidate line changed" }
        }
        try {
            val initial = current() ?: return Unavailable
            val proof = Draft02OutboundEnvelope.verify(owned, initial.authority, initial.request) { fresh().trustedNowMs }
            verified = proof
            require(hex(proof.unsignedDigest) == grant.unsignedDigest) { "Candidate ciphertext changed" }
            fresh()
            dao.reserve(record, ::line)
            reserved = true
            fresh() // Reserve commit may itself have waited.
            val parts = proof.parts()
            val recipient = keyStore.existingPublic() // Never creates a replacement key.
            if (recipient.security !in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT)) {
                throw UnsupportedCustody()
            }
            require(MessageDigest.isEqual(recipient.keyId, parts.keyId)) { "Candidate recipient changed" }
            fresh()
            val cek = Draft02PublicJcaKeystoreHpke.openDeviceCek(keyStore, parts.header, parts.protected,
                1, parts.keyId, parts.enc, parts.wrap)
            try {
                fresh()
                clear = Draft02Body.open(proof, cek)
            } finally { cek.fill(0) }
            fresh()
            // Selected subscription only; divideMessage does not send. No SmsManager.send method is called.
            val manager = SmsManager.getSmsManagerForSubscriptionId(grant.subscriptionId)
            val count = segmentCount(clear, manager::divideMessage)
            val output = finish(db, record, clear, count, ::line) { fresh() }
            clear = null // Ownership moved only after commit and final freshness/continuity checks.
            handedOff = true
            return output
        } catch (_: UnsupportedCustody) {
            return Unsupported
        } catch (_: Exception) {
            return Rejected
        } finally {
            clear?.fill('\u0000')
            if (reserved && !handedOff) runCatching { dao.abort(grant.accountId, grant.messageId, grant.attemptId) }
            // Failed unwrap/commit may leave PREPARING/PREPARED. Every retained row is non-resumable.
        }
    }

    /** Private handoff seam; it cannot acquire keys and is called only after hardware-gated decryption. */
    private fun finish(db: SmsJournalDatabase, record: SealedPreparationRecord, chars: CharArray, count: Int,
                       line: (LocalLineBinding?) -> Unit, fresh: () -> Unit): Prepared {
        var moved = false
        try {
            db.sealedPreparations().finish(record, count, line)
            // Root/session state and Room are not jointly atomic. Recheck after the commit wait.
            line(db.attempts().currentLineBinding())
            fresh()
            return OwnedPrepared(chars, count) {
                line(db.attempts().currentLineBinding())
                fresh()
            }.also { moved = true }
        } finally { if (!moved) chars.fill('\u0000') }
    }

    internal fun segmentCount(chars: CharArray, divide: (String) -> List<String>): Int {
        val parts = divide(String(chars)) // Platform Strings cannot be reliably erased; retain none.
        require(parts.size in 1..6 && parts.all { it.isNotEmpty() } && parts.joinToString("") == String(chars)) {
            "Candidate segment limit"
        }
        return parts.size
    }
    internal fun hash(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    internal fun uuid(bytes: ByteArray): String = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long).toString() }
}
