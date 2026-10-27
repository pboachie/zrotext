// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

/** Actual host correlation/closed decoder over an in-process synthetic socket. Registering
 * this fixture is not a real device handshake, authenticated service or provider proof. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ProtectionOriginConnectionsTest {
    private val vector = javaClass.classLoader!!.getResourceAsStream("device-protection-origin-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private val p get() = vector.getJSONObject("parameters")
    private fun bytes(name: String) = java.util.Base64.getUrlDecoder().decode(p.getString(name))
    private fun command() = ProtectionSetupCommand(setupId = p.getString("setup_id"), openingId = p.getString("opening_id"),
        commandId = p.getString("command_id"), accountId = p.getString("account_id"), deviceId = p.getString("device_id"),
        originSha256 = hex(bytes("origin_digest")), enrolledSigningKeyId = hex(bytes("enrolled_key_id")), requestedMs = 2_990_000)
    private fun association() = ProtectionOriginProof.Association.decode(java.util.Base64.getUrlDecoder().decode(vector.getString("association")))
    private fun pending(): ProtectionOriginAttempt {
        val command = command(); val association = association(); val id = UUID(0, 8)
        val aes = bytes("journal_aes_probe") + bytes("withdrawal_aes_probe")
        val frame = ProtectionOriginWire.proofOpen(command, 7, id, association, aes, null)
        return ProtectionOriginAttempt(id.toString(), command.commandId, encode(association.bytes()), encode(aes), 2_997_000,
            requestEpoch = 7, requestB64url = encode(frame))
    }
    private fun socket(epoch: Long) = ProtectionOriginSocketFixture(
        EvidenceIdentity(command().accountId, command().deviceId, command().originSha256), bytes("enrolled_point"), epoch)
    private fun status(socket: ProtectionOriginSocketFixture): ProtectionOriginConnections.Received {
        val nonce = UUID.randomUUID(); val command = command(); val proof = UUID.fromString(pending().proofRequestId)
        return socket.host.request(command, ProtectionOriginWire.status(command, socket.host.epoch, nonce, proof), association(), beforeSend = {}) {
            it is ProtectionOriginWire.Status && it.requestId == nonce && it.proofRequestId == proof
        }
    }
    @Test fun sameConnectionNotFoundCannotAuthorizeAnotherInitialProofRequest() {
        socket(7).use { socket -> assertThrows(IllegalArgumentException::class.java) { status(socket).laterMissing(pending()) } }
    }
    @Test fun laterNonceCorrelatedReplyIsDistinctFromRawOrOldObservedCandidates() {
        socket(9).use { socket ->
            val observed = status(socket); val witness = observed.laterMissing(pending())
            witness.requireFor(pending()); assertEquals(9L, witness.epoch())
            val forged = ProtectionOriginConnections.Received(observed.reply, 0, 0, socket.host, observed.bytes())
            assertThrows(IllegalStateException::class.java) { forged.laterMissing(pending()) }
            status(socket) // A new RPC replaces the narrow current observation.
            assertThrows(IllegalStateException::class.java) { witness.requireFor(pending()) }
        }
    }
    @Test fun priorSignatureOrChallengeCannotBeConvertedIntoAbsenceRecovery() {
        socket(9).use { socket ->
            val old = pending().copy(attemptId = p.getString("attempt_id"), coreB64url = vector.getString("core"),
                nonceB64url = p.getString("attempt_nonce"), deviceEnteredMs = 3_000_001)
            assertThrows(IllegalArgumentException::class.java) { status(socket).laterMissing(old) }
        }
    }
    @Test fun delayedDifferentNonceDoesNotSatisfyTheActualPendingStatus() {
        socket(9).use { socket ->
            socket.beforeCorrect = { request -> socket.host.accept(socket.reply(request).apply {
                put("request_id", UUID.randomUUID().toString())
            }.let(ProtectionOriginJson::render)) }
            val observed = status(socket)
            assertEquals("not_found", (observed.reply as ProtectionOriginWire.Status).state)
            socket.host.close()
            assertThrows(IllegalStateException::class.java) { observed.laterMissing(pending()) }
        }
    }
    private fun hex(value: ByteArray) = Draft02OutboundPreparation.hex(value)
    private fun encode(value: ByteArray) = Profile03ElectionEncoding.encode(value)
}

internal class ProtectionOriginSocketFixture(identity: EvidenceIdentity, point: ByteArray, epoch: Long) : AutoCloseable {
    lateinit var host: ProtectionOriginConnections.Host
        private set
    var beforeCorrect: (Map<String, Any>) -> Unit = {}
    var actorCheck: () -> Unit = {}
    var sentCount = 0
        private set
    private val socket = object : WebSocket {
        override fun request(): Request = Request.Builder().url("https://gateway.example.test/").build()
        override fun queueSize() = 0L
        override fun send(bytes: ByteString) = error("Binary setup frame refused")
        override fun send(text: String): Boolean {
            sentCount++
            val request = ProtectionOriginJson.objectValue(text.toByteArray())
            beforeCorrect(request)
            host.accept(ProtectionOriginJson.render(reply(request)))
            return true
        }
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
    init { host = ProtectionOriginConnections.register(socket, identity, epoch, point) { actorCheck() } }
    fun reply(request: Map<String, Any>) = request.filterKeys { it in setOf("v", "connection_epoch", "setup_id", "opening_id", "command_id", "request_id", "proof_request_id") }
        .toMutableMap().apply {
            put("type", "protection_origin_status"); put("status", "not_found")
            put("opening", ProtectionOriginJson.Null); put("challenge", ProtectionOriginJson.Null); put("receipt", ProtectionOriginJson.Null)
        }
    override fun close() = host.close()
}
