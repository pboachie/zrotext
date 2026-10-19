// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Full original public proof verification for a retained installed election, before a fresh
 * physical selection exists. This creates neither a live SIM permit nor message permission.
 * Its caller must resolve the installed row and existing hardware independently of the packet.
 */
internal object Profile03RetainedElection {
    class Verified internal constructor(val election: Draft03PayloadElectionProof,
        val authority: Draft03ManifestAuthority, val original: Profile03OriginalBindingProof,
        private val device: ByteArray) {
        fun devicePoint() = device.copyOf()
        override fun toString() = "VerifiedRetainedElection03(historical-proof-only)"
    }
    val EVIDENCE_KEYS = setOf("root_pin", "prior_manifest02", "prior_accepted_ms", "accepted_manifest03", "accepted_ms",
        "bundle", "device_signing_point", "owner_approval_point", "registration_evidence", "activation_evidence")

    fun verify(evidence: Map<String, Any>, installed: Profile03ElectionRecord, activation: LineActivationV2Record,
        trust: Draft02TrustStore, hardware: DevicePayloadPublic, enrollment: ByteArray,
        origin: String, now: () -> Long): Verified {
        require(evidence.keys == EVIDENCE_KEYS)
        installed.requireShape(); activation.requireShape()
        require(installed.state == "installed" && hardware.security in
            setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
        val bundle = Profile03Json.binary(evidence, "bundle", 628, 628)
        val core = Profile03ElectionEncoding.decode(installed.coreB64url, 500)
        val old = Profile03Json.binary(evidence, "prior_manifest02", 364, 9751)
        val successor = Profile03Json.binary(evidence, "accepted_manifest03", 366, 9753)
        val acceptedMs = Profile03Json.decimal(evidence, "accepted_ms")
        require(same(core, bundle.copyOfRange(0, 500)) &&
            same(Profile03ElectionEncoding.decode(checkNotNull(installed.deviceSignatureB64url), 64), bundle.copyOfRange(500, 564)))
        fun number(at: Int) = ByteBuffer.wrap(core, at, 8).long.also { require(it > 0) }
        val accepted = Draft03PayloadElectionProof.AcceptedRecord03(
            uuid(installed.accountId), uuid(installed.deviceId), uuid(installed.lineId), core.copyOfRange(136, 168),
            number(168), uuid(installed.oldBindingId), installed.oldGeneration, core.copyOfRange(104, 136),
            uuid(installed.newBindingId), installed.newGeneration, hardware.keyId, number(176), core.copyOfRange(184, 216),
            sha(old), number(216), core.copyOfRange(224, 256), sha(successor), sha(core),
            sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/commitment/v1", core)), sha(bundle), acceptedMs)
        // The timestamp from this read is usable only if it is part of the EXACT retained identity.
        require(installed.acceptedEvidenceSha256 == Draft03OutboundPreparation.acceptedIdentity(accepted) &&
            installed.readerKeyId == hex(hardware.keyId) && installed.rootFingerprint == hex(accepted.rootFingerprint))
        now()
        val history = trust.retainedElectionHistory(acceptedMs, now)
        history.requireExactEvidence(Profile03Json.binary(evidence, "root_pin", 94, 94), old,
            Profile03Json.decimal(evidence, "prior_accepted_ms"))
        val original = Profile03OriginalBindingProof.verify(
            Profile03Json.binary(evidence, "registration_evidence", 1, 2048),
            Profile03Json.binary(evidence, "activation_evidence", 1, 2048), core, history.pin(), enrollment,
            hardware.keyId, origin)
        require(original.matchesLocal(activation) && original.acceptedMs <= number(384) && original.acceptedMs <= acceptedMs &&
            same(Profile03Json.binary(evidence, "device_signing_point", 65, 65), enrollment) &&
            same(Profile03Json.binary(evidence, "owner_approval_point", 65, 65), original.approvalPoint()))
        history.requireOriginalReader(uuid(installed.deviceId), uuid(installed.lineId), hardware.keyId, hardware.point)
        val election = Draft03PayloadElectionProof.verifyAccepted(bundle, core, accepted, history.proof, successor,
            enrollment, original.approvalPoint())
        val authority = history.current03(successor, now())
        now()
        return Verified(election, authority, original, enrollment.copyOf())
    }
    internal fun signingId(point: ByteArray) = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    private fun uuid(value: String) = ReviewedIntent03.uuid(UUID.fromString(value))
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
}
