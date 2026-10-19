// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/** Fresh synthetic signing keys, real signed02/03/election/intent and body GCM. Opaque wraps do
 * not prove HPKE/provider interoperability. The real SIM observation/runtime fixture supplies
 * its process-only installed v2 permit; no persisted row or test boolean substitutes for it.
 */
internal class Profile03ExecutionFixture(private val selectedReaderUntilMs: Long = 900_000, canonicalOrigin: String? = null,
    distinctEventSigner: Boolean = false, private val includeEventSigner: Boolean = true) : AutoCloseable {
    val enrollment = pair()
    val eventSigning = if (distinctEventSigner) pair() else enrollment
    private val originHash = canonicalOrigin?.let { hex(sha(it.toByteArray(Charsets.UTF_8))) } ?: testEvidenceIdentity.originHash
    val line = LineActivationV2RuntimeFixture(true, enrollment, originHash)
    val binding = line.installSealed()
    val account = uuid(line.account)
    val device = uuid(line.device)
    val lineId = uuid(line.line)
    val message = UUID(0, 10)
    val attempt = UUID(0, 11)
    val ownerUser = UUID(0, 12)
    val ownerSession = UUID(0, 13)
    val interval = UUID(0, 14)
    val oldBinding = UUID(0, 15)
    val newBinding = UUID(0, 16)
    val challenge = UUID(0, 17)
    val session = SealedDispatchExecutor.Session(line.account, line.device, line.epoch, 1, UUID(0, 18), originHash)
    val root = pair()
    val reader = pair()
    val archive = pair()
    val approval = pair()
    val signer = pair()
    val now = 100_020L
    val acceptedAt = 100_010L
    val admittedAt = 100_011L
    val key = ByteArray(32) { (it + 1).toByte() }
    val peer = "+12".toByteArray(Charsets.US_ASCII)
    val body = "synthetic profile03 body".toByteArray(Charsets.UTF_8)
    val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
    val fingerprint = sha(ascii("ZTSE/root-pin/v2\u0000") + pin)
    val old = manifest(2, 1, ByteArray(32))
    val next = manifest(3, 2, unsigned(old))
    val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(pin, account, fingerprint, 1, 1,
        unsigned(old), ByteArray(32), sha(old), 100_000)
    val history = Draft03PayloadElectionProof.verifyHistorical02(old, checkpoint, 100_000, 100_000)
    val authority = Draft03ManifestAuthority.verifyFrom02(next, old, checkpoint, now)
    val core = ByteBuffer.allocate(500).put(byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3))
        .put(account).put(device).put(lineId).put(uuid(challenge)).put(uuid(oldBinding)).putLong(1).putLong(2)
        .put(ByteArray(32) { 7 }).put(fingerprint).putLong(1).putLong(1).put(unsigned(old))
        .putLong(2).put(unsigned(next)).put(keyId(reader, false)).put(keyId(enrollment, true))
        .put(keyId(approval, true)).put(ByteArray(32) { 8 }).putLong(99_900).putLong(101_000)
        .put(unhex(session.originHash)).put(ByteArray(32) { 9 }).put(ByteArray(32) { 10 }).putInt(0).array()
    val deviceProof = rawSign(enrollment, ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", core))
    val bundle = core + deviceProof + rawSign(approval,
        ReviewedIntent03.framed("ZTSE/line/payload-profile/owner/v1", core + sha(deviceProof)))
    val accepted = Draft03PayloadElectionProof.AcceptedRecord03(account, device, lineId, fingerprint, 1,
        uuid(oldBinding), 1, ByteArray(32) { 7 }, uuid(newBinding), 2, keyId(reader, false), 1, unsigned(old), sha(old),
        2, unsigned(next), sha(next), sha(core), sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/commitment/v1", core)),
        sha(bundle), acceptedAt)
    val election = Draft03PayloadElectionProof.verifyAccepted(bundle, core, accepted, history, next, point(enrollment), point(approval))
    val currentSelection get() = Draft03PayloadElectionProof.CurrentAuthority03(3, 3, account, device, lineId,
        uuid(newBinding), 2, keyId(reader, false), fingerprint, 1, 2, authority.digest,
        accepted.electionCommitment, accepted.electionBundleSha256, now, 101_000)
    val record = Profile03ElectionRecord(challenge.toString(), line.account.toString(), line.device.toString(),
        line.line.toString(), oldBinding.toString(), newBinding.toString(), 1, 2, hex(fingerprint),
        hex(keyId(reader, false)), session.originHash, session.connectionEpoch, session.deploymentEpoch,
        Profile03ElectionEncoding.encode(core))
    val installed = record.copy(state = "installed", deviceSignatureB64url = Profile03ElectionEncoding.encode(deviceProof),
        acceptedEvidenceSha256 = Draft03OutboundPreparation.acceptedIdentity(accepted))
    val envelope = envelope()
    val intentBytes = intent()
    val intent = ReviewedIntent03.decode(intentBytes)
    val intentSignature = signIntent(intentBytes)
    fun signIntent(bytes: ByteArray) = rawSign(signer, ReviewedIntent03.framed("zrotext/conversation/reviewed-send03/v1", bytes))
    val grant get() = SealedDispatch03Frames.grant(JSONObject().put("v", 1).put("type", "sealed_execution_grant")
        .put("grant_version", 3).put("envelope_profile", 3).put("manifest_profile", 3).put("reader_role", 1)
        .put("segment_count", 1).put("account_id", line.account).put("device_id", line.device).put("line_id", line.line)
        .put("message_id", message).put("attempt_id", attempt).put("connection_epoch", line.epoch).put("deployment_epoch", 1)
        .put("binding_generation", 2).put("attempt_generation", 1).put("expires_at_ms", 100_450)
        .put("trust_generation", 1).put("manifest_version", 2).put("reader_key_id", b64(keyId(reader, false)))
        .put("envelope_sha256", b64(sha(envelope))).put("unsigned_sha256", b64(unsigned(envelope)))
        .put("manifest_digest", b64(authority.digest)).put("root_fingerprint", b64(fingerprint))
        .put("election_digest", b64(accepted.electionCommitment)).toString())
    fun current(selected: Draft03PayloadElectionProof.CurrentAuthority03 = currentSelection,
        reviewed: ReviewedIntent03 = intent, signature: ByteArray = intentSignature,
        epoch: Long = 3, acceptedMs: Long = admittedAt) = Draft03OutboundPreparation.Current(election, authority, selected,
        installed, binding, reviewed, signature, acceptedMs, epoch, ownerUser, ownerSession, 1, 200_000, line.selected, line.cards())
    fun install() {
        val dao = line.db.profile03Elections()
        check(dao.reserve(record) {})
        check(dao.recordSigned(installed.copy(state = "signed", acceptedEvidenceSha256 = null)) {})
        check(dao.install(installed) {})
    }
    fun successor02() = manifest(2, 2, unsigned(old))
    private fun intent(): ByteArray = byteArrayOf(90, 84, 82, 73, 1, 3, 3, 0) +
        account + device + lineId + uuid(newBinding) + uuid(ownerUser) + uuid(ownerSession) + uuid(interval) + uuid(message) +
        long(2) + long(1) + long(2) + long(3) + long(100_010) + long(100_500) + long(100_010) + long(100_030) +
        keyId(reader, false) + fingerprint + authority.digest + accepted.electionCommitment + accepted.electionBundleSha256 +
        sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1", account + uuid(ownerUser) + uuid(ownerSession))) +
        unhex(session.originHash) + keyId(signer, true) + sha(envelope) + unsigned(envelope) + sha(body) +
        byteArrayOf(peer.size.toByte()) + peer + byteArrayOf(2, 1) + keyId(reader, false) + byteArrayOf(2) + keyId(archive, false) + byteArrayOf(1)
    private fun manifest(profile: Int, version: Long, previous: ByteArray): ByteArray {
        fun row(role: Int, key: KeyPair, scope: Int): ByteArray = byteArrayOf(role.toByte()) + keyId(key, role > 3) +
            point(key) + (if (role == 1 || role == 4) device else ByteArray(16)) +
            (if (role in setOf(1, 4, 5)) lineId else ByteArray(16)) + byteArrayOf(0, scope.toByte()) + long(1) +
            long(if (role == 1) selectedReaderUntilMs else 900_000) + byteArrayOf(1)
        val rows = row(1, reader, 4) + row(2, archive, 12) +
            (if (includeEventSigner) row(4, eventSigning, 2) else ByteArray(0)) + row(5, signer, 1) + row(6, root, 0)
        val header = if (profile == 2) ascii("ZTMA") + byteArrayOf(2) else ascii("ZTMA") + byteArrayOf(3, 3, 2)
        val unsigned = header + account + long(1) + long(version) + long(99_000) + long(900_000) + previous + point(root) +
            byteArrayOf((if (includeEventSigner) 5 else 4).toByte()) + rows
        return unsigned + rawSign(root, ReviewedIntent03.framed("ZTSE/manifest/v$profile", unsigned))
    }
    private fun envelope(): ByteArray {
        val protected = account + uuid(message) + device + lineId + long(2) + authority.digest + keyId(signer, true) +
            long(100_010) + long(100_500) + byteArrayOf(1, peer.size.toByte()) + peer
        val header = ascii("ZTSE") + byteArrayOf(3, 1, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
        val nonce = ByteArray(12) { 7 }
        val encrypted = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(ascii("ZTSE/body/v3\u0000") + header + protected); doFinal(body)
        }
        val wraps = byteArrayOf(1) + keyId(reader, false) + point(reader) + ByteArray(48) { 4 } +
            byteArrayOf(2) + keyId(archive, false) + point(archive) + ByteArray(48) { 5 }
        val unsigned = header + protected + nonce + ByteBuffer.allocate(4).putInt(encrypted.size).array() + encrypted + byteArrayOf(2) + wraps
        return unsigned + rawSign(signer, ReviewedIntent03.framed("ZTSE/sign/v3", unsigned))
    }
    override fun close() { key.fill(0); line.close() }
    companion object {
        fun pair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        fun point(key: KeyPair) = DevicePayloadKeyStore.encodePoint(key.public as ECPublicKey)
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        fun unsigned(bytes: ByteArray) = sha(bytes.copyOfRange(0, bytes.size - 64))
        fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        fun uuid(value: UUID) = ReviewedIntent03.uuid(value)
        fun keyId(key: KeyPair, signing: Boolean) = sha(ascii("ZTSE/key/v1\u0000") +
            (if (signing) byteArrayOf(1, 1) else byteArrayOf(0, 16)) + point(key))
        fun rawSign(key: KeyPair, transcript: ByteArray) = Draft01SignaturePrimitive.canonicalRawFromDer(
            Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(transcript); sign() })
        fun unhex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
    }
}
