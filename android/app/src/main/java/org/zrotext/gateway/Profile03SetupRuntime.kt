// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.telephony.SubscriptionManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** A first02→03 election on an actual current complete-v2 installation. Original server
 * statements are public evidence; the locally compared encrypted store and existing keys are
 * independent. No missing root/reader/history is provisioned by receiving this frame.
 */
internal class Profile03SetupRuntime(context: Context, private val origin: String,
    private val db: SmsJournalDatabase, private val trust: Draft02TrustStore,
    private val payloadKeys: DevicePayloadKeyStore, private val signingKeys: DeviceSigningKeyStore,
    private val clock: Profile03SessionTime, private val socketCurrent: () -> Boolean,
) {
    private val application = checkNotNull(context.applicationContext)
    private val originDigest = sha(origin.toByteArray(Charsets.UTF_8))

    /** Called only by the raw authenticated03 socket listener. Never retries signing. A signed
     * record is retained on transport loss and its exact proof may be re-emitted while the SAME
     * original live ceremony remains valid. A reserved crash/retired row is never re-signed.
     */
    fun challenge(raw: ByteArray): String {
        val frame = Profile03Json.objectValue(raw)
        require(frame.keys == setOf("v", "type", "challenge_id", "new_binding_id", "core", "successor_manifest03", "original", "closed_unaccepted") &&
            frame["v"] == Profile03Json.Integer(1) && frame["type"] == "payload_profile_challenge03")
        val challenge = id(frame, "challenge_id")
        val newBinding = id(frame, "new_binding_id")
        val core = Profile03Json.binary(frame, "core", 500, 500)
        val successor = Profile03Json.binary(frame, "successor_manifest03", 366, 9753)
        val closures = Profile03ClosedUnaccepted.decode(frame)
        val f = Profile03Json.nested(frame, "original")
        require(f.keys == ORIGINAL_KEYS && f["v"] == Profile03Json.Integer(1) &&
            f["envelope_profile"] == Profile03Json.Integer(2) && f["manifest_profile"] == Profile03Json.Integer(2))
        val evidence = Profile03Json.nested(f, "evidence")
        require(evidence.keys == EVIDENCE_KEYS)
        require(Profile03Json.nonnegativeDecimal(f, "selection_epoch") == 0L)
        fun number(name: String) = Profile03Json.decimal(f, name)
        fun bytes(name: String) = Profile03Json.binary(f, name, 32, 32)
        fun fieldId(name: String) = id(f, name)
        val identity = checkNotNull(clock.snapshot()).first
        val session = identity.session
        val lineId = fieldId("line_id")
        val oldBinding = fieldId("old_binding_id")
        var lastNow = 0L
        fun now(): Long = checkNotNull(clock.nowMs()).also {
            check(socketCurrent() && clock.snapshot()?.first?.session === session && it > 0 && it >= lastNow &&
                it >= number("compared_ms") && it < number("permission_expires_ms") &&
                it >= long(core, 384) && it < long(core, 392))
            lastNow = it
        }
        require(newBinding != oldBinding && newBinding != challenge && oldBinding != challenge &&
            same(core.copyOfRange(0, 8), byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3)) &&
            core.copyOfRange(496, 500).all { it == 0.toByte() } &&
            core.copyOfRange(352, 384).any { it != 0.toByte() } &&
            id(core.copyOfRange(56, 72)) == challenge && long(core, 392) > long(core, 384) &&
            long(core, 392) - long(core, 384) <= 300_000 && long(core, 96) > long(core, 88))
        require(fieldId("account_id") == session.accountId && fieldId("device_id") == session.deviceId &&
            number("connection_epoch") == session.connectionEpoch && number("deployment_epoch") == session.deploymentEpoch &&
            Profile03Json.text(f, "site_id") == identity.site && Profile03Json.text(f, "instance_id") == identity.instance &&
            same(bytes("origin_digest"), originDigest) && hex(originDigest) == session.originHash)
        for ((at, value) in listOf(8 to uuid(session.accountId), 24 to uuid(session.deviceId), 40 to uuid(lineId),
            72 to uuid(oldBinding), 104 to bytes("old_binding_proof_digest"), 136 to bytes("root_fingerprint"),
            184 to bytes("manifest_digest"), 256 to bytes("reader_key_id"), 288 to bytes("device_signing_key_id"),
            320 to bytes("approval_key_id"), 400 to originDigest, 432 to bytes("owner_session_digest"), 464 to bytes("device_session_digest"))) {
            require(same(core.copyOfRange(at, at + value.size), value))
        }
        require(long(core, 88) == number("old_binding_generation") && long(core, 168) == number("trust_generation") &&
            long(core, 176) == number("manifest_version") &&
            same(bytes("owner_session_digest"), sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
                uuid(session.accountId) + uuid(fieldId("user_id")) + uuid(fieldId("owner_session_id"))))))
        val prior = Profile03Json.binary(evidence, "prior_manifest02", 364, 9751)
        val pin = Profile03Json.binary(evidence, "root_pin", 94, 94)
        val originalEnrollment = Profile03Json.binary(evidence, "device_signing_point", 65, 65)
        val originalOwner = Profile03Json.binary(evidence, "owner_approval_point", 65, 65)
        val line = checkNotNull(db.attempts().currentLineBinding())
        val permit = checkNotNull(line.installedSelectionV2())
        fun ram(actual: LocalLineBinding?) {
            now()
            val selected = application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            check(actual == line && line.accountId == session.accountId.toString() && line.deviceId == session.deviceId.toString() &&
                line.lineId == lineId.toString() && line.protocolVersion == 2 && line.v2Purpose == "sealed" &&
                line.generation == long(core, 88) && line.subscriptionId == selected && permit.isCurrent() && permit.matches(line))
        }
        fun fresh() {
            ram(db.attempts().currentLineBinding())
            val history = trust.currentElectionHistory(::now)
            history.requireExactEvidence(pin, prior, Profile03Json.decimal(evidence, "prior_accepted_ms"))
            require(history.proof.version() == number("manifest_version") &&
                same(history.proof.digest(), bytes("manifest_digest")) && same(history.proof.fingerprint(), bytes("root_fingerprint")))
            val reader = payloadKeys.existingPublic()
            val enrolled = signingKeys.existingConversationPublicPoint()
            require(reader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                same(reader.keyId, bytes("reader_key_id")) && same(enrolled, originalEnrollment) &&
                same(signingId(enrolled), bytes("device_signing_key_id")) &&
                same(identity.deviceSessionDigest(enrolled), bytes("device_session_digest")))
            now()
            val original = Profile03OriginalBindingProof.verify(Profile03Json.binary(evidence, "registration_evidence", 1, 2048),
                Profile03Json.binary(evidence, "activation_evidence", 1, 2048), core, history.pin(), enrolled, reader.keyId, origin)
            require(same(original.approvalPoint(), originalOwner) && same(signingId(originalOwner), bytes("approval_key_id")) &&
                original.matchesLocal(permit.record) && original.acceptedMs <= long(core, 384))
            history.requireOriginalReader(uuid(session.deviceId), uuid(lineId), reader.keyId, reader.point)
            val candidate = history.current03(successor, now())
            require(candidate.version == long(core, 216) && same(candidate.digest, core.copyOfRange(224, 256)))
            candidate.requireSelectedReader(uuid(session.deviceId), uuid(lineId), reader.keyId, reader.point,
                now(), minOf(long(core, 392), number("permission_expires_ms")))
            check(SimCardContinuity.matches(line.activatedSim(), SimCardContinuity.observe(application)))
            ram(db.attempts().currentLineBinding())
        }
        fresh()
        val record = Profile03ElectionRecord(challenge.toString(), session.accountId.toString(), session.deviceId.toString(),
            lineId.toString(), oldBinding.toString(), newBinding.toString(), long(core, 88), long(core, 96),
            hex(bytes("root_fingerprint")), hex(bytes("reader_key_id")), session.originHash, session.connectionEpoch,
            session.deploymentEpoch, Profile03ElectionEncoding.encode(core))
        val dao = db.profile03Elections()
        val existing = dao.find(record.challengeId)
        val signature: ByteArray
        if (existing == null) {
            check(dao.reserveWithClosures(record, closures, now(), ::ram)) // Same writer before hardware signing; a crash burns it.
            signature = signingKeys.signPayloadElection03(core, originalEnrollment, ::fresh)
            val signed = record.copy(state = "signed", deviceSignatureB64url = Profile03ElectionEncoding.encode(signature))
            check(dao.recordSigned(signed, ::ram))
        } else {
            require(existing.sameReservation(record) && existing.state == "signed")
            dao.requireClosureHistory(record, closures, now(), ::ram)
            signature = Profile03ElectionEncoding.decode(checkNotNull(existing.deviceSignatureB64url), 64)
            require(ConversationContentCrypto.verifyRaw(signature, originalEnrollment,
                ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", core)))
        }
        fresh()
        return Profile03Json.render(mapOf("v" to Profile03Json.Integer(1), "type" to "payload_profile_proof03",
            "challenge_id" to challenge.toString(), "device_signature" to Profile03ElectionEncoding.encode(signature)))
            .toString(Charsets.UTF_8)
    }
    override fun toString() = "Profile03SetupRuntime(redacted)"
    companion object {
        private val ORIGINAL_KEYS = setOf("v", "envelope_profile", "manifest_profile", "account_id", "user_id", "owner_session_id",
            "device_id", "line_id", "selection_epoch", "origin_digest", "owner_session_digest", "device_session_digest", "site_id",
            "instance_id", "connection_epoch", "deployment_epoch", "old_binding_id", "old_binding_generation", "old_binding_proof_digest",
            "reader_key_id", "device_signing_key_id", "approval_key_id", "root_fingerprint", "trust_generation", "manifest_version",
            "manifest_digest", "compared_ms", "permission_expires_ms", "evidence")
        private val EVIDENCE_KEYS = setOf("root_pin", "prior_manifest02", "prior_accepted_ms", "device_signing_point",
            "owner_approval_point", "registration_evidence", "activation_evidence")
        private fun id(f: Map<String, Any>, name: String): UUID {
            val raw = Profile03Json.text(f, name)
            return UUID.fromString(raw).also { require(it != UUID(0, 0) && it.toString() == raw) }
        }
        private fun id(bytes: ByteArray) = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }
        private fun uuid(id: UUID) = ReviewedIntent03.uuid(id)
        private fun long(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it > 0) }
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun signingId(point: ByteArray) = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
}
