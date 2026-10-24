// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONObject

/** Ephemeral RAM-only TEST keys, actual Room/Host/codec/worker components and independent
 * strict-lowS verification. Socket and signing are explicit test boundaries, not custody,
 * service authentication, SQL119 or radio acceptance. No private key is serialized. */
internal class TypedNoSubmit03Fixture(var epoch: Long = 12, val version: Int = 2,
    endpoint: String = "wss://proof.example.test/device") : AutoCloseable {
    private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val point = DevicePayloadKeyStore.encodePoint(keys.public as ECPublicKey)
    private val fixture = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use { JSONObject(it.bufferedReader().readText()) }
    private val original = TypedSubmit03Command.decode(unbase(fixture.getJSONArray("cases").getJSONObject(0).getString("submit")))
    val keyId = ProtectionOriginProof.signingKeyId(point)
    val command = TypedSubmit03Command.create(original.accountId, original.deviceId, original.eventId, original.messageId,
        original.attemptId, original.fetchSha256, session(11), 1, original.observedMs)
    val identity = EvidenceIdentity.fromStream(UUID.fromString(command.accountId), UUID.fromString(command.deviceId), endpoint)
    val elapsed = AtomicLong(1000)
    val actor = AtomicBoolean(true)
    val foreground = ConversationInterval03Foreground().apply { update(true) }
    var primary = 3_000_100L
    var leaseEnd = 4_000_000L
    var rtt = 10L
    var sends = 0
    var signs = 0
    var beforeSend: (JSONObject) -> Unit = {}
    var beforeReply: (JSONObject) -> Unit = {}
    var beforeSign: () -> Unit = {}
    var afterSign: () -> Unit = {}
    var state = "challenged"
    var wrongProofEpoch = false
    var issuedOffset = 0L
    var proofLifetime = 30_000L
    var beforePublishClock: ((JSONObject) -> Unit)? = null
    private val challenges = LinkedHashMap<String, JSONObject>()
    lateinit var host: TypedHistory03Connections.Host
        private set
    private val socket = object : WebSocket {
        override fun request() = Request.Builder().url("https://proof.example.test/device").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean {
            val request = JSONObject(text); sends++; beforeSend(request); elapsed.addAndGet(rtt)
            val type = request.getString("type")
            val reply = when (type) {
                "payload_profile_history_clock03_request" -> clockFrame(request)
                "payload_profile_no_submit_challenge03_request" -> {
                    val id = request.getString("proof_request_id")
                    val nested = challenges.getOrPut(id) { challengeFrame(request) }
                    JSONObject(nested.toString()).put("v", 1).put("type", "payload_profile_no_submit_challenge03").put("connection_epoch", epoch)
                }
                "payload_profile_no_submit_status03_request" -> statusFrame(request)
                "payload_profile_no_submit_proof03" -> {
                    val core = TypedNoSubmit03Core.decode(unbase(request.getString("core")))
                    check(ConversationContentCrypto.verifyRaw(unbase(request.getString("signature")), point, core.transcript()))
                    acceptedSignature = unbase(request.getString("signature"))
                    state = "accepted"
                    base("payload_profile_no_submit_ack03").put("proof_request_id", core.proofRequestId).put("closure_id", core.id(5))
                        .put("challenge_id", core.challengeId).put("message_id", command.messageId).put("attempt_id", command.attemptId)
                        .put("submit_command_sha256", b64(command.commitment())).put("closure_record_sha256", b64(core.digest(6)))
                        .put("accepted_ms", (core.issuedMs + 1).toString()).put("disposition", "closed_no_rearm")
                }
                else -> error("Unexpected test socket operation")
            }
            beforeReply(reply)
            if (type == "payload_profile_history_clock03_request") { beforePublishClock?.invoke(reply); host.accept(reply.toString().toByteArray()) }
            else host.acceptClosure(reply.toString().toByteArray())
            return true
        }
        override fun send(bytes: ByteString) = false
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
    init { host = TypedHistory03Connections.register(socket, identity, epoch, version, point, { check(actor.get()) }, elapsed::get) }
    fun reconnect() {
        host.close(); epoch++
        host = TypedHistory03Connections.register(socket, identity, epoch, version, point, { check(actor.get()) }, elapsed::get)
    }
    fun row() = TypedSubmit03Record.candidateWithOrigin(command, point, identity.originHash)
    fun closed(db: SmsJournalDatabase): TypedSubmit03Record {
        val row = db.typedSubmits03().reserve(row()) {}
        val closing = checkNotNull(db.typedSubmits03().beginClosing(row, id()))
        val (sample, request) = clock(db, closing, checkNotNull(closing.closingId), "closure")
        return checkNotNull(db.typedSubmits03().finishClosing(closing, request, sample))
    }
    fun action(row: TypedSubmit03Record) = TypedNoSubmit03Action.capture(row, host, foreground.decision())
    fun sign(entry: TypedNoSubmit03SignEntry, context: TypedNoSubmit03Context): ByteArray {
        val core = entry.consume(); context.requireCurrent(entry.original, entry.proof)
        beforeSign(); context.requireCurrent(entry.original, entry.proof); signs++
        val raw = rawSign(core)
        afterSign()
        check(ConversationContentCrypto.verifyRaw(raw, point, core.transcript()))
        return raw
    }
    fun rawSign(core: TypedNoSubmit03Core): ByteArray = Draft01SignaturePrimitive.canonicalRawFromDer(
        Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(core.transcript()); sign() })
    fun clock(db: SmsJournalDatabase, row: TypedSubmit03Record, subject: String, kind: String): Pair<TypedHistory03Clock.Sample, TypedHistory03Request> {
        val id = id(); val q = TypedHistory03Wire.Query(id, row.messageId, row.attemptId)
        val request = TypedHistory03Request(id, row.attemptId, row.messageId, row.commandSha256, subject, kind, row.accountId, row.deviceId,
            identity.originHash, row.originalEnrolledPoint, epoch, version, b64(TypedHistory03Wire.request(epoch, q)))
        check(db.typedHistory03().reserveClock(row, request, host::requireCurrent))
        val entry = checkNotNull(db.typedHistory03().enterClock(request, host::requireCurrent))
        val entered = checkNotNull(db.typedHistory03().clock(id)); val sample = host.request(row, entry)
        check(db.typedHistory03().retainClockReply(entered, sample.bytes()))
        return sample to checkNotNull(db.typedHistory03().clock(id))
    }
    fun exchange(db: SmsJournalDatabase, row: TypedSubmit03Record, p: TypedNoSubmit03Proof, kind: String,
        current: () -> Unit = {}): Pair<TypedNoSubmit03Io, TypedHistory03Connections.Host.ClosureReply> {
        val id = id(); val raw = when (kind) {
            "challenge" -> TypedNoSubmit03Wire.challengeRequest(row, p, epoch)
            "status" -> TypedNoSubmit03Wire.statusRequest(row, p, id, epoch)
            "proof" -> TypedNoSubmit03Wire.proofRequest(p, epoch)
            else -> error("test operation")
        }
        val io = TypedNoSubmit03Io(id, p.requestId, p.closureId, kind, epoch, b64(raw))
        val entry = checkNotNull(db.typedNoSubmits03().enter(row, p, io, current))
        val result = host.exchangeClosure(entry, current)
        check(db.typedNoSubmits03().retainReply(io, result.bytes()))
        return checkNotNull(db.typedNoSubmits03().io(id)) to result
    }
    data class Prepared(val action: TypedNoSubmit03Action, val proof: TypedNoSubmit03Proof,
        val status: TypedNoSubmit03Io, val context: TypedNoSubmit03Context)
    fun prepared(db: SmsJournalDatabase, row: TypedSubmit03Record = closed(db)): Prepared {
        val original = action(row)
        val receipt = checkNotNull(db.typedNoSubmits03().first(row, id(), original::requireCurrent))
        return reconcile(db, original.afterFirst(receipt), receipt.proof)
    }
    fun reconcile(db: SmsJournalDatabase, a: TypedNoSubmit03Action, initial: TypedNoSubmit03Proof): Prepared {
        val row = a.row
        val p = if (initial.coreB64url == null) {
            val challenge = exchange(db, row, initial, "challenge")
            val parsed = TypedNoSubmit03Wire.decodeChallenge(challenge.second.bytes(), row, initial, epoch)
            checkNotNull(db.typedNoSubmits03().retainChallenge(row, initial, challenge.first, parsed))
        } else initial
        val status = exchange(db, row, p, "status")
        val (sample, clock) = clock(db, row, p.requestId, "proof")
        return Prepared(a, p, status.first, TypedNoSubmit03Context.from(host, a.decision, row, p, status.first, status.second, sample, clock, a::requireCurrent))
    }
    /** Actual three-generation Room/Host history, not hand-inserted lineage. */
    fun successor(db: SmsJournalDatabase, previous: Prepared): Prepared {
        val a = action(previous.action.row); val old = previous.proof
        primary = old.challenge().core.expiresMs
        val status = exchange(db, a.row, old, "status")
        val (sample, request) = clock(db, a.row, old.requestId, "proof")
        val next = checkNotNull(db.typedNoSubmits03().replace(a.row, old, status.first, status.second, sample, request, id(), a::requireCurrent))
        return reconcile(db, a, next)
    }
    fun challengeFrame(request: JSONObject): JSONObject {
        val proofId = request.getString("proof_request_id"); val challengeId = id()
        val nonce = ByteArray(32).also(java.security.SecureRandom()::nextBytes)
        val closedFrom = when (request.getString("closed_from")) { "reserved" -> 0; "ack_authorized" -> 1; else -> error("Closure phase") }
        val closed = TypedNoSubmit03Record.create(command, request.getString("closure_id"), closedFrom, request.getString("closed_ms").toLong())
        val core = ByteBuffer.allocate(441).put(byteArrayOf(0x5a, 0x54, 0x4e, 0x53, 1, 3, 3, 0))
        for (value in listOf(command.accountId, command.deviceId, command.eventId, command.messageId, command.attemptId, closed.closureId, proofId, challengeId)) core.put(uuid(value))
        val issued = primary + issuedOffset
        for (value in listOf(11L, 2L, if (wrongProofEpoch) epoch + 1 else epoch, 2L, 1L, 1L, command.observedMs, closed.closedMs, issued, minOf(issued + proofLifetime, leaseEnd))) core.putLong(value)
        for (value in listOf(command.fetchSha256, command.commitment(), command.originalSessionSha256, session(epoch), keyId, sha(nonce), closed.commitment())) core.put(value)
        core.put(closed.closedFrom.toByte())
        val previousId = request.optString("previous_challenge_id").takeUnless { it == "null" || it.isEmpty() }
        val previous = previousId?.let { oldId ->
            val old = challenges.values.single { it.getString("challenge_id") == oldId }
            val oldCore = TypedNoSubmit03Core.decode(unbase(old.getString("core")))
            JSONObject().put("challenge_id", oldId).put("core_sha256", b64(oldCore.sha256())).put("closed_ms", primary.toString()).put("superseded_by_challenge_id", challengeId)
        }
        return JSONObject().put("proof_request_id", proofId).put("closure_id", closed.closureId).put("challenge_id", challengeId)
            .put("core", b64(core.array())).put("nonce", b64(nonce)).put("closed_predecessor", previous ?: JSONObject.NULL)
    }
    private fun statusFrame(request: JSONObject): JSONObject {
        val nested = challenges[request.getString("proof_request_id")]
        val actual = if (nested == null) "not_found" else state
        val core = nested?.let { TypedNoSubmit03Core.decode(unbase(it.getString("core"))) }
        // Random ECDSA is NOT used to fabricate an accepted receipt's signature hash.
        // Tests setting accepted use the exact locally retained result via acceptedSignature.
        val receipt = if (actual == "accepted") JSONObject().put("challenge_id", checkNotNull(core).challengeId)
            .put("core_sha256", b64(core.sha256())).put("signature_sha256", b64(sha(checkNotNull(acceptedSignature))))
            .put("accepted_ms", (core.issuedMs + 1).toString()).put("disposition", "closed_no_rearm") else JSONObject.NULL
        return base("payload_profile_no_submit_status03").put("request_id", request.getString("request_id"))
            .put("proof_request_id", request.getString("proof_request_id")).put("closure_id", request.getString("closure_id"))
            .put("message_id", command.messageId).put("attempt_id", command.attemptId)
            .put("submit_command_sha256", b64(command.commitment())).put("closure_record_sha256", request.getString("closure_record_sha256"))
            .put("status", actual).put("challenge", if (actual == "not_found") JSONObject.NULL else nested)
            .put("receipt", receipt)
    }
    var acceptedSignature: ByteArray? = null
    fun clockFrame(request: JSONObject): JSONObject = base("payload_profile_history_clock03").put("request_id", request.getString("request_id"))
        .put("message_id", command.messageId).put("attempt_id", command.attemptId).put("account_id", command.accountId).put("device_id", command.deviceId)
        .put("server_time_ms", primary.toString()).put("sample_expires_ms", minOf(primary + 30_000, leaseEnd).toString())
        .put("lease", JSONObject().put("site_id", "synthetic-site").put("instance_id", "synthetic-instance").put("deployment_epoch", "2")
            .put("line_activation_version", version).put("enrolled_signing_key_id", b64(keyId)).put("device_session_digest", b64(session(epoch)))
            .put("expires_ms", leaseEnd.toString()))
    fun session(epoch: Long): ByteArray = sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/device-session/v1",
        uuid(original.accountId) + uuid(original.deviceId) + text("synthetic-site") + text("synthetic-instance") +
            ByteBuffer.allocate(18).putLong(epoch).putLong(2).putShort(version.toShort()).array() + keyId))
    private fun base(type: String) = JSONObject().put("v", 1).put("type", type).put("connection_epoch", epoch)
    override fun close() { foreground.close(); actor.set(false); host.close() }
    companion object {
        fun id() = UUID.randomUUID().toString()
        fun b64(raw: ByteArray) = TypedSubmit03Record.base(raw)
        fun unbase(text: String) = TypedSubmit03Record.unbase(text)
        fun sha(raw: ByteArray) = TypedSubmit03Command.sha(raw)
        private fun uuid(value: String) = UUID.fromString(value).let { ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
        private fun text(value: String) = value.toByteArray().let { ByteBuffer.allocate(4).putInt(it.size).array() + it }
    }
}
