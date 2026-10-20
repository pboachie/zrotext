// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

internal fun interface Profile03ManifestOriginalReader {
    fun read(evidence: Map<String, Any>, lineId: UUID, expectedBinding: UUID,
        session: SealedDispatchExecutor.Session): Profile03ManifestChain.Original
}

/** Actual existing stores/keys and authenticated socket lifetime. This completes historical
 * evidence only, including the SAME retained signed election after a lost acceptance response.
 * It neither creates keys nor reconstructs a physical selection, consent or current handle. */
internal class Profile03ManifestOriginal(private val origin: String, private val db: SmsJournalDatabase,
    private val trust: Draft02TrustStore, private val readers: () -> DevicePayloadKeyStore,
    private val signer: DeviceSigningKeyStore, private val clock: Profile03SessionTime,
    private val socketCurrent: () -> Boolean) : Profile03ManifestOriginalReader {
    override fun read(evidence: Map<String, Any>, lineId: UUID, expectedBinding: UUID,
        session: SealedDispatchExecutor.Session): Profile03ManifestChain.Original {
        fun now() = checkNotNull(clock.nowMs()).also {
            check(socketCurrent() && clock.snapshot()?.first?.session === session && it > 0)
        }
        now()
        require(evidence.keys == Profile03RetainedElection.EVIDENCE_KEYS)
        val bundle = Profile03Json.binary(evidence, "bundle", 628, 628)
        val challenge = ByteBuffer.wrap(bundle, 56, 16).let { UUID(it.long, it.long) }
        val retained = checkNotNull(db.profile03Elections().find(challenge.toString())).also { it.requireShape() }
        require(retained.accountId == session.accountId.toString() && retained.deviceId == session.deviceId.toString() &&
            retained.lineId == lineId.toString() && retained.newBindingId == expectedBinding.toString() && retained.originHash == session.originHash &&
            db.profile03Elections().closedUnaccepted(retained.challengeId) == null && retained.state in setOf("signed", "installed"))
        val line = checkNotNull(db.attempts().currentLineBinding())
        require(line.accountId == retained.accountId && line.deviceId == retained.deviceId && line.lineId == retained.lineId &&
            line.protocolVersion == 2 && line.v2Purpose == "sealed" && line.generation == retained.oldGeneration)
        val activation = checkNotNull(db.lineActivationsV2().find("sealed", checkNotNull(line.v2ChallengeId)))
        require(activation.isInstalled() && activation.matchesBinding(line))
        val hardware = readers().existingPublic()
        val point = signer.existingConversationPublicPoint()
        now()
        val original = Profile03RetainedElection.historicalAcceptance(evidence, retained, activation, trust,
            hardware, point, origin, ::now)
        fun unchanged() {
            now()
            require(db.attempts().currentLineBinding() == line && db.lineActivationsV2().find("sealed", activation.challengeId) == activation)
            val actual = readers().existingPublic()
            require(actual.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                same(actual.point, hardware.point) && same(actual.keyId, hardware.keyId) && same(point, signer.existingConversationPublicPoint()))
            now()
        }
        unchanged()
        if (retained.state == "signed") {
            // Existing DAO compares the exact reservation/signature, closure and all unresolved
            // preparations/effects in the SAME Room transaction. Callback contains RAM only.
            check(db.profile03Elections().install(original.installation) { actual ->
                check(actual == line); now()
            })
        } else require(retained == original.installation)
        unchanged()
        require(db.profile03Elections().find(challenge.toString()) == original.installation)
        // Fresh original verification after the writer/Keystore waits, outside Room. A root or
        // credential change cannot turn the newly recorded historical receipt into availability.
        val verified = Profile03RetainedElection.historical(evidence, original.installation, activation, trust,
            hardware, point, origin, ::now)
        unchanged()
        val accepted = verified.election.acceptedRecord()
        val scope = Profile03ManifestSuccessor.Scope(session.accountId, session.deviceId, lineId, expectedBinding, challenge,
            accepted.newBindingGeneration, accepted.rootFingerprint, accepted.electionCommitment, accepted.electionBundleSha256,
            sha(origin.toByteArray(Charsets.UTF_8)), listOf(point, verified.original.approvalPoint()))
        val first = Profile03ManifestHistory.Checkpoint(verified.authority, accepted.acceptedAtMs,
            scope.base(verified.authority, accepted.acceptedAtMs))
        val identity = hex(sha(checkNotNull(original.installation.acceptedEvidenceSha256).toByteArray(Charsets.US_ASCII) +
            Profile03ManifestChain.canonicalEvidence(evidence)))
        // Persist the exact already-verified original bytes for cold negative-only route
        // exclusion. Protection/key work is outside Room; its callback checks RAM only.
        Capture03IngressGate.requireOutside()
        val canonical = Profile03ManifestChain.canonicalEvidence(evidence)
        val protected = ConversationExistingJournalProtection().seal(
            canonical.toString(Charsets.UTF_8), "capture03-mode-v1|${challenge}|${identity}")
        unchanged()
        db.captures03().retainOriginal(Capture03Mode(challenge.toString(), retained.accountId,
            retained.deviceId, retained.lineId, retained.newBindingId, identity, hex(sha(canonical)),
            protected.ciphertext, protected.nonce)) { now() }
        unchanged()
        return Profile03ManifestChain.Original(challenge.toString(), identity, scope, first, evidence)
    }
    companion object {
        private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        private fun hex(b: ByteArray) = Draft02OutboundPreparation.hex(b)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
