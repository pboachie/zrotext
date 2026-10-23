// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONObject

/** Actual component/Room paths over a synthetic socket. No original enrollment, service,
 * hardware, current permission or radio attestation is established by this fixture. */
internal class TypedHistory03Fixture(val version: Int = 2, val epoch: Long = 12,
    endpoint: String = "wss://history.example.test/device") : AutoCloseable {
    val fixture = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    val point = bytes(fixture.getString("enrolled_point"))
    val command = TypedSubmit03Command.decode(bytes(fixture.getJSONArray("cases").getJSONObject(0).getString("submit")))
    val identity = EvidenceIdentity.fromStream(UUID.fromString(command.accountId), UUID.fromString(command.deviceId), endpoint)
    val elapsed = AtomicLong(1000)
    val actor = AtomicBoolean(true)
    var primary = 3_000_100L
    var leaseEnd = 4_000_000L
    var roundTrip = 10L
    var sends = 0
    var elapsedRead: (() -> Long)? = null
    var beforeReply: () -> Unit = {}
    var respond: (JSONObject) -> Unit = { request -> host.accept(frame(request).toString().toByteArray()) }
    lateinit var host: TypedHistory03Connections.Host
        private set
    private val socket = object : WebSocket {
        override fun request() = Request.Builder().url("https://history.example.test/device").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean {
            sends++; elapsed.addAndGet(roundTrip); beforeReply(); respond(JSONObject(text)); return true
        }
        override fun send(bytes: ByteString) = false
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
    init {
        host = TypedHistory03Connections.register(socket, identity, epoch, version, point,
            { check(actor.get()) }, { elapsedRead?.invoke() ?: elapsed.get() })
    }
    fun row(command: TypedSubmit03Command = this.command) = TypedSubmit03Record.candidateWithOrigin(command, point, identity.originHash)
    fun reserve(db: SmsJournalDatabase, command: TypedSubmit03Command = this.command) = db.typedSubmits03().reserve(row(command)) {}
    fun entered(db: SmsJournalDatabase): TypedSubmit03Record {
        val original = reserve(db)
        check(db.typedSubmits03().retainFirstAck(original, byteArrayOf(1, 2, 3)) {})
        val acknowledged = checkNotNull(db.typedSubmits03().get(original.attemptId))
        check(db.typedSubmits03().retainPlatformEntry(acknowledged, command.observedMs + 1) {})
        return checkNotNull(db.typedSubmits03().get(original.attemptId))
    }
    fun pending(db: SmsJournalDatabase, row: TypedSubmit03Record, subject: String,
        kind: String = "assertion"): Pair<TypedHistory03Request, TypedHistory03Entry> {
        val id = UUID.randomUUID().toString()
        val query = TypedHistory03Wire.Query(id, row.messageId, row.attemptId)
        val candidate = TypedHistory03Request(id, row.attemptId, row.messageId, row.commandSha256, subject, kind,
            row.accountId, row.deviceId, identity.originHash, row.originalEnrolledPoint, epoch, version,
            TypedSubmit03Record.base(TypedHistory03Wire.request(epoch, query)))
        check(db.typedHistory03().reserveClock(row, candidate, host::requireCurrent))
        return candidate to checkNotNull(db.typedHistory03().enterClock(candidate, host::requireCurrent))
    }
    fun read(db: SmsJournalDatabase, row: TypedSubmit03Record, subject: String,
        kind: String = "assertion"): Pair<TypedHistory03Clock.Sample, TypedHistory03Request> {
        val (original, entry) = pending(db, row, subject, kind)
        val entered = checkNotNull(db.typedHistory03().clock(original.requestId))
        val sample = host.request(row, entry)
        check(db.typedHistory03().retainClockReply(entered, sample.bytes()))
        return sample to checkNotNull(db.typedHistory03().clock(original.requestId))
    }
    fun frame(request: JSONObject): JSONObject {
        val key = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
        val payload = uuid(command.accountId) + uuid(command.deviceId) + text("synthetic-site") + text("synthetic-instance") +
            ByteBuffer.allocate(18).putLong(epoch).putLong(2).putShort(version.toShort()).array() + key
        val label = "ZTSE/line/payload-profile/device-session/v1\u0000".toByteArray(Charsets.US_ASCII)
        val session = sha(label + ByteBuffer.allocate(4).putInt(payload.size).array() + payload)
        return JSONObject().put("v", 1).put("type", "payload_profile_history_clock03").put("connection_epoch", epoch)
            .put("request_id", request.getString("request_id")).put("message_id", request.getString("message_id"))
            .put("attempt_id", request.getString("attempt_id")).put("account_id", command.accountId).put("device_id", command.deviceId)
            .put("server_time_ms", primary.toString()).put("sample_expires_ms", minOf(primary + 30_000, leaseEnd).toString())
            .put("lease", JSONObject().put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
                .put("deployment_epoch", "2").put("line_activation_version", version)
                .put("enrolled_signing_key_id", b64(key)).put("device_session_digest", b64(session)).put("expires_ms", leaseEnd.toString()))
    }
    override fun close() { actor.set(false); host.close() }
    companion object {
        fun bytes(text: String) = Base64.getUrlDecoder().decode(text)
        fun id(n: Long) = UUID(0, n).toString()
        private fun b64(raw: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        private fun sha(raw: ByteArray) = MessageDigest.getInstance("SHA-256").digest(raw)
        private fun text(value: String) = value.toByteArray().let { ByteBuffer.allocate(4).putInt(it.size).array() + it }
        private fun uuid(value: String) = UUID.fromString(value).let {
            ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
    }
}
