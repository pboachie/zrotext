// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECPoint
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/** Fresh fixture keys and loopback server only. Implements no shipped transport or credentials. */
internal class ConversationSimulatorFixture(private val ready: JSONObject) : ConversationActivationVerifier {
    /** Session comes out-of-band from the isolated fixture server, never decoded from frame claims. */
    val channelSession: ConversationPhoneSession by lazy {
        val s=ready.getJSONObject("channelSession")
        ConversationPhoneSession(UUID.fromString(s.getString("account")),UUID.fromString(s.getString("device")),
            UUID.fromString(s.getString("session")),s.getLong("connectionEpoch"),s.getLong("deploymentEpoch"),s.getString("originHash"))
    }
    fun authenticatedWire() = object:ConversationAuthenticatedWire {
        override fun currentSession() = channelSession
        override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
            val response=command("channel",data=b64(request))
            check(response.getBoolean("ok")) { "Synthetic authenticated channel refused" }
            return ConversationAuthenticatedWire.Reply(channelSession,bytes(response.getString("frame")))
        }
    }
    val statement = bytes(ready.getString("statement"))
    val parsed = ConversationActivationCodec.decode(statement)
    private val parameters = AlgorithmParameters.getInstance("EC").apply {
        init(java.security.spec.ECGenParameterSpec("secp256r1"))
    }.getParameterSpec(ECParameterSpec::class.java)
    private val point = bytes(ready.getString("rootPoint"))
    private val root = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(
        ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65))), parameters))
    private val signer = KeyFactory.getInstance("EC").generatePrivate(
        ECPrivateKeySpec(BigInteger(1, bytes(ready.getString("eventScalar"))), parameters))
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    val protection = object : ConversationJournalProtection {
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        override fun seal(value: String, aad: String): InboundVault.Sealed {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key); cipher.updateAAD(aad.toByteArray(Charsets.US_ASCII))
            return InboundVault.Sealed(cipher.doFinal(value.toByteArray(Charsets.UTF_8)), cipher.iv)
        }
        override fun open(value: InboundVault.Sealed, aad: String): String {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, value.nonce)); cipher.updateAAD(aad.toByteArray(Charsets.US_ASCII))
            return cipher.doFinal(value.ciphertext).toString(Charsets.UTF_8)
        }
    }

    override fun verifiedPreparation(evidence: ByteArray): ConversationCaptureScope {
        check(evidence.contentEquals(statement) && System.currentTimeMillis() < parsed.expiresMs)
        val scope = parsed.scope
        fun uuid(s: String): ByteArray = UUID.fromString(s).let { ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
        val trust = Draft02ManifestAuthority.Trust(uuid(scope.accountId), bytes(ready.getString("fingerprint")), scope.trustGeneration,
            Draft02ManifestAuthority.Position.after(parsed.predecessorVersion, parsed.predecessorDigest))
        val authority = Draft02ManifestAuthority.verify(bytes(ready.getString("pin")), bytes(ready.getString("manifest")), trust, System.currentTimeMillis())
        check(authority.version == scope.activationVersion && authority.digest.contentEquals(hex(scope.activationDigest)))
        authority.context(Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.INBOUND,
            uuid(scope.accountId), uuid(scope.intervalId), uuid(scope.deviceId), uuid(scope.lineId), scope.peer.toByteArray(Charsets.US_ASCII),
            parsed.signerId, listOf(Draft02ManifestAuthority.Reader(2, hex(scope.readerKeyId)))), System.currentTimeMillis())
        return scope
    }

    override fun verifiedActiveLease(scope: ConversationCaptureScope, challenge: String, evidence: ByteArray): Long {
        check(scope == parsed.scope)
        val response = JSONObject(evidence.toString(Charsets.UTF_8))
        check(response.getBoolean("ok"))
        val duration = response.getLong("duration")
        val id = UUID.fromString(challenge)
        val wanted = "zrotext/fixture/active/v1\u0000".toByteArray(Charsets.US_ASCII) + hex(scope.transcriptDigest) +
            ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array() + ByteBuffer.allocate(8).putLong(duration).array()
        val proof = bytes(response.getString("proof")); val signature = bytes(response.getString("signature"))
        check(proof.contentEquals(wanted) && signature.size == 64 && BigInteger(1, signature.copyOfRange(32, 64)) <= order.shiftRight(1))
        check(Signature.getInstance("SHA256withECDSA").apply { initVerify(root); update(proof) }.verify(rawDer(signature)))
        return duration
    }

    fun sign(domain: ByteArray): String {
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(signer); update(ConversationActivationCodec.transcript(domain, statement))
        }.sign()
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        if (s > order.shiftRight(1)) {
            val low = order.subtract(s).toByteArray().takeLast(32).toByteArray()
            java.util.Arrays.fill(raw, 32, 64, 0.toByte())
            low.copyInto(raw, 64 - low.size)
        }
        return b64(raw)
    }

    fun command(op: String, data: String? = null, signature: String? = null,
                challenge: UUID? = null, event: UUID? = null, confirmation: String? = null): JSONObject {
        val port = ready.getInt("port")
        require(port in 1..65535)
        val uri = URI("http", null, "localhost", port, "/fixture", null, null)
        val connection = uri.toURL().openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000; connection.readTimeout = 10_000
        connection.requestMethod = "POST"; connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json"); connection.setRequestProperty("Connection", "close")
        val json = JSONObject().put("token", ready.getString("token")).put("op", op)
        data?.let { json.put("data", it) }; signature?.let { json.put("signature", it) }
        challenge?.let { json.put("challenge", it.toString()) }; event?.let { json.put("event", it.toString()) }
        confirmation?.let { json.put("confirmation", it) }
        try {
            connection.outputStream.use { it.write(json.toString().toByteArray(Charsets.UTF_8)) }
            return JSONObject((if (connection.responseCode == 200) connection.inputStream else connection.errorStream).use {
                it.readBytes().toString(Charsets.UTF_8)
            })
        } finally { connection.disconnect() }
    }

    fun envelope(body: String, capture: String, observed: Long, sequence: Long): JSONObject = sdk(
        JSONObject().put("op", "prepare").put("body", body).put("capture", capture).put("observed", observed).put("sequence", sequence))
    fun open(envelope: String): JSONObject = sdk(JSONObject().put("op", "open").put("envelope", envelope))
    fun browser(event: UUID, inbound: String): JSONObject = sdk(JSONObject().put("event", event.toString()).put("inbound", inbound).put("closeDuringDecrypt", System.getenv("ZT_CONVERSATION_SIM_MODE") == "send_close"), ready.getString("browserTool"))
    fun verifiedSend(evidence: ByteArray, closeAfterDecrypt: Boolean = false): VerifiedConversationSend {
        val packet = JSONObject(evidence.toString(Charsets.UTF_8))
        val tool = java.io.File(java.io.File(ready.getString("browserTool")).parentFile, "conversation-phone-send-verifier.mjs").path
        val expected = JSONObject().put("account", parsed.scope.accountId).put("device", parsed.scope.deviceId)
            .put("line", parsed.scope.lineId).put("interval", parsed.scope.intervalId).put("session", parsed.scope.initiatingSessionId)
            .put("generation", parsed.scope.bindingGeneration.toString()).put("peer", parsed.scope.peer)
            .put("reader", b64(hex(parsed.scope.readerKeyId)))
        val value = sdk(JSONObject().put("evidencePacket", packet).put("expectedScope", expected).put("closeAfterDecrypt", closeAfterDecrypt), tool)
        val authenticated = value.getJSONObject("scope")
        expected.keys().forEach { field -> check(authenticated.getString(field) == expected.getString(field)) }
        return VerifiedConversationSend(parsed.scope, value.getString("message"), value.getString("deadline").toLong(), value.getString("body"))
    }
    // Verified deadline comes from the independently checked signed proof. The
    // clock executes inside the shared monitor, after any admission-lock wait.
    fun recordVerifiedAcceptance(admission: ConversationCaptureAdmission, deadline: Long,
                                 now: () -> Long = System::currentTimeMillis, record: () -> Unit): Boolean = synchronized(admission) {
        if (!admission.captureEligible() || now() >= deadline) false
        else { record(); true }
    }
    private fun sdk(input: JSONObject, tool: String = ready.getString("sdkTool")): JSONObject {
        input.put("ready", ready).put("device", parsed.scope.deviceId).put("line", parsed.scope.lineId).put("peer", parsed.scope.peer)
        if (ready.has("hostBridgePort")) {
            val port = ready.getInt("hostBridgePort"); require(port in 1..65535)
            val connection = URI("http", null, "localhost", port, "/sdk", null, null).toURL().openConnection() as HttpURLConnection
            connection.connectTimeout=10000;connection.readTimeout=30000;connection.requestMethod="POST";connection.doOutput=true
            connection.setRequestProperty("Content-Type","application/json")
            val request=JSONObject().put("token",ready.getString("token")).put("tool",tool.replace('\\','/').substringAfterLast('/')).put("input",input)
            try {
                connection.outputStream.use {it.write(request.toString().toByteArray(Charsets.UTF_8))}
                check(connection.responseCode==200) { "Fixture host bridge failed" }
                return JSONObject(connection.inputStream.use {it.readBytes().toString(Charsets.UTF_8)})
            } finally {connection.disconnect()}
        }
        val file = java.io.File.createTempFile("conversation-sdk-", ".json")
        val process = ProcessBuilder("node", tool).redirectErrorStream(true).redirectOutput(file).start()
        try {
            process.outputStream.use { it.write(input.toString().toByteArray(Charsets.UTF_8)) }
            check(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) { "Synthetic SDK adapter timed out" }
            check(process.exitValue() == 0) { "Synthetic SDK adapter failed: ${file.readText().take(1000)}" }
            return JSONObject(file.readText())
        } finally {
            if (process.isAlive) { process.destroyForcibly(); process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS) }
            file.delete()
        }
    }
    private fun rawDer(raw:ByteArray):ByteArray {
        require(raw.size==64)
        fun integer(bytes:ByteArray):ByteArray {
            val encoded=BigInteger(1,bytes).toByteArray()
            return byteArrayOf(2,encoded.size.toByte())+encoded
        }
        val values=integer(raw.copyOfRange(0,32))+integer(raw.copyOfRange(32,64))
        return byteArrayOf(0x30,values.size.toByte())+values
    }
    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    private fun bytes(s: String) = Base64.getDecoder().decode(s)
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
