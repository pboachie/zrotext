// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import androidx.test.platform.app.InstrumentationRegistry
import java.lang.reflect.Proxy
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.UUID
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.*

/** Explicit synthetic verifier/preparation seam. Exercises the real typed transport, private
 * context, Prepared holder, intent ownership, Room ACK and platform CAS with a no-radio driver.
 * It does not attest hardware custody or content cryptography; no TEE classification is supplied.
 */
internal class ConversationCompiledRadioFixture : AutoCloseable {
    private fun id() = UUID.randomUUID().toString()
    private fun bytes(id: String) = UUID.fromString(id).let { ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
    private fun text(value: String) = value.toByteArray(Charsets.US_ASCII)
    private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
    private fun int(value: Int) = ByteBuffer.allocate(4).putInt(value).array()
    private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun hex(value: ByteArray) = Draft02OutboundPreparation.hex(value)
    private val account = id(); private val device = id(); private val line = id()
    val message = id(); val attempt = id()
    var now = 100_000L
    val deadline = now + 20_000
    var live = true; var permitted = true; var uncertain = false
    var prepareHook: () -> Unit = {}
    var intentHook: () -> Unit = {}
    var selectedHook: () -> Unit = {}
    var suppressionHook: () -> Unit = {}
    var sends = 0; var intents = 0; var divisions = 0; var driverClosed = 0
    val body = "Synthetic compiled reply"
    val chars = body.toCharArray()
    private val manifest = ByteArray(32) { 3 }
    private val reader = ByteArray(32) { 4 }
    private val archive = ByteArray(32) { 5 }
    val scope = ConversationCaptureScope(account, device, line, 1, "+12", id(), id(), id(),
        "01".repeat(32), hex(archive), 1, 1, hex(manifest), "02".repeat(32))
    private val phone = ConversationPhoneSession(UUID.fromString(account), UUID.fromString(device), UUID.randomUUID(), 7, 3, "11".repeat(32))
    private val binding = LocalLineBinding(accountId = account, deviceId = device, lineId = line,
        generation = 1, subscriptionId = 3, installedAtMs = 1, cardId = 4)
    private val local = SealedDispatchExecutor.Local(binding, reader, 1, 1, hex(manifest), hex(sha(text(scope.peer))))
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    val db = Room.inMemoryDatabaseBuilder(context, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private val journal = Room.inMemoryDatabaseBuilder(context, ConversationSendDatabase::class.java).allowMainThreadQueries().build()
    private val protection = ConversationExistingJournalProtection { SecretKeySpec(ByteArray(32) { 7 }, "AES") }
    private val envelope: ByteArray
    private val evidence: ByteArray
    private val evidenceHash: String
    private val holder = Class.forName("org.zrotext.gateway.Draft02OutboundPreparation\$OwnedPrepared")
        .declaredConstructors.single().apply { isAccessible = true }
        .newInstance(chars, 1, { check(live && now < deadline) }) as Draft02OutboundPreparation.Prepared
    init {
        val point = DevicePayloadKeyStore.encodePoint(KeyPairGenerator.getInstance("EC").apply { initialize(256) }
            .generateKeyPair().public as ECPublicKey)
        val protected = bytes(account) + bytes(message) + bytes(device) + bytes(line) + long(1) + manifest +
            ByteArray(32) { 6 } + long(now) + long(deadline) + byteArrayOf(1, 3) + text(scope.peer)
        val prefix = text("ZTSE") + byteArrayOf(2, 1, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
        val wraps = byteArrayOf(1) + reader + point + ByteArray(48) + byteArrayOf(2) + archive + point + ByteArray(48)
        // Canonical structural scalars only, not a cryptographic signature claim.
        val signature = ByteArray(64).apply { this[31] = 1; this[63] = 1 }
        envelope = prefix + protected + ByteArray(12) + int(32) + ByteArray(32) + byteArrayOf(2) + wraps + signature
        val confirmation = text("ZTCS") + byteArrayOf(1) + bytes(account) + bytes(device) + bytes(line) +
            bytes(scope.intervalId) + bytes(scope.initiatingSessionId) + bytes(message) + long(1) + long(1) + long(1) +
            long(deadline) + byteArrayOf(3) + text(scope.peer) + ByteArray(32) { 6 } + archive + manifest + sha(envelope) + sha(text(body))
        evidence = ConversationContentCrypto.packConfirmedEvidence(envelope, confirmation, signature)
        evidenceHash = hex(sha(evidence))
        val sealed = protection.seal(Base64.getEncoder().encodeToString(evidence),
            "zrotext-conversation-send-v1:$message:${scope.intervalId}:$evidenceHash")
        journal.sends().receive(ConversationSendReceipt(message, scope.intervalId, evidenceHash, deadline, sealed.ciphertext, sealed.nonce))
        journal.sends().claim(message, attempt)
    }
    private fun consumer(): ConversationPreparedSubmission {
        val wireType = Class.forName("org.zrotext.gateway.ConversationRadioIntentWire")
        val driverType = Class.forName("org.zrotext.gateway.ConversationRadioDriver")
        val platformType = Class.forName("org.zrotext.gateway.ConversationRadioPlatform")
        val suppressionType = Class.forName("org.zrotext.gateway.ConversationExistingSuppressionTokens")
        val wire = Proxy.newProxyInstance(wireType.classLoader, arrayOf(wireType)) { _, method, args ->
            check(method.name == "submitIntent")
            assertEquals(phone, args!![0])
            val event = args[1] as AlphaRadioEvent
            assertEquals(event, db.attempts().getAlphaEvent(event.eventId))
            assertNull(event.acknowledgedAtMs)
            val registryType = Class.forName("org.zrotext.gateway.ConversationRadioIntentOwnership")
            assertEquals(true, registryType.getDeclaredMethod("owns", AlphaRadioEvent::class.java)
                .invoke(registryType.getField("INSTANCE").get(null), event))
            intents++; intentHook(); permitted
        }
        val driver = Proxy.newProxyInstance(driverType.classLoader, arrayOf(driverType)) { _, method, args ->
            when (method.name) {
                "requireSelected" -> { check(live); selectedHook(); Unit }
                "divide" -> { divisions++; arrayListOf(args!![0] as String) }
                "prepare" -> { prepareHook(); Unit }
                "send" -> {
                    assertEquals(AttemptState.RADIO_STARTED, db.attempts().getAttempt(attempt)!!.state)
                    assertEquals(scope.peer, args!![0]); assertEquals(attempt, args[1])
                    assertEquals(arrayListOf(body), args[2]); sends++
                    if (uncertain) error("Synthetic uncertain driver")
                    Unit
                }
                "close" -> { driverClosed++; Unit }
                else -> error("Unexpected driver operation")
            }
        }
        val suppression = suppressionType.getDeclaredConstructor(kotlin.jvm.functions.Function0::class.java)
            .newInstance({ suppressionHook(); SecretKeySpec(ByteArray(32) { 8 }, "HmacSHA256") })
        val platform = platformType.getDeclaredConstructor(LocalLineBinding::class.java, driverType, suppressionType,
            java.lang.Boolean.TYPE).newInstance(binding, driver, suppression, true)
        val fresh: (ConversationPreparedSubmissionContext) -> Long = { check(live); now }
        val platformProvider: (LocalLineBinding) -> Any = { assertEquals(binding, it); platform }
        val type = Class.forName("org.zrotext.gateway.ConversationPreparedRadioSubmission")
        return type.getDeclaredConstructor(SmsAttemptDao::class.java, wireType,
            kotlin.jvm.functions.Function1::class.java, kotlin.jvm.functions.Function1::class.java, java.lang.Boolean.TYPE)
            .newInstance(db.attempts(), wire, fresh, platformProvider, true) as ConversationPreparedSubmission
    }
    fun transport(): ConversationExecutionTransport {
        val wire = object : ConversationAuthenticatedWire {
            override fun currentSession() = if (live) phone else null
            override fun exchange(request: ByteArray): ConversationAuthenticatedWire.Reply {
                val selected = ConversationChannelCodec.parseExecutionRequest(request, phone)
                val json = JSONObject().put("v", 1).put("type", "sealed_execution_grant").put("grant_version", 1)
                    .put("account_id", account).put("device_id", device).put("line_id", line)
                    .put("message_id", message).put("attempt_id", attempt).put("connection_epoch", 7).put("deployment_epoch", 3)
                    .put("binding_generation", 1).put("attempt_generation", 1).put("reader_role", 1)
                    .put("reader_key_id", b64(reader)).put("envelope_sha256", b64(sha(envelope)))
                    .put("unsigned_sha256", b64(sha(envelope.copyOfRange(0, envelope.size - 64))))
                    .put("expires_at_ms", deadline - 1000).put("segment_count", 1)
                val payload = json.toString().toByteArray(Charsets.UTF_8)
                val header = ConversationChannelCodec.timeRequest(ConversationTrustedClock.Request(selected.challenge, phone)).also { it[5] = 19 }
                return ConversationAuthenticatedWire.Reply(phone, header + ByteBuffer.allocate(2).putShort(payload.size.toShort()).array() + payload)
            }
        }
        return ConversationExecutionTransport(journal.sends(), protection, object : ConversationSendVerifier {
            override fun verify(evidence: ByteArray) = VerifiedConversationSend(scope, message, deadline, body)
        }, wire, { if (!live) null else ConversationExecutionCurrent(SealedDispatchExecutor.Session(phone.account,
            phone.device, phone.connectionEpoch, phone.deploymentEpoch, phone.session, phone.originHash), local, now, deadline) },
            { _, _, _, _, _ -> SealedDispatchExecutor.Ready(holder) }, consumer())
    }
    fun claim() = ConversationClaimedEvidence(message, attempt, scope, evidenceHash, deadline, evidence)
    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    override fun close() { holder.close(); journal.close(); db.close(); evidence.fill(0) }
}
