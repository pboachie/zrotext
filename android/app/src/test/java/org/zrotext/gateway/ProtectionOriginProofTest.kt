// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Exact shared public producer, not an enrollment/provider/network fixture. No private key,
 * Android provider generation, pin, radio or genuine service is used by these tests. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ProtectionOriginProofTest {
    private val vector = javaClass.classLoader!!.getResourceAsStream("device-protection-origin-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private val p get() = vector.getJSONObject("parameters")
    private fun value(name: String) = decode(vector.getString(name))
    private fun parameter(name: String) = decode(p.getString(name))
    private fun association() = ProtectionOriginProof.Association.decode(value("association"))
    private fun core() = ProtectionOriginProof.Core.decode(value("core"))
    private fun bundle() = ProtectionOriginProof.Bundle.verify(value("bundle"), association(), parameter("enrolled_point"))
    private fun command() = ProtectionSetupCommand(setupId = p.getString("setup_id"), openingId = p.getString("opening_id"),
        commandId = p.getString("command_id"), accountId = p.getString("account_id"), deviceId = p.getString("device_id"),
        originSha256 = hex(parameter("origin_digest")), enrolledSigningKeyId = hex(parameter("enrolled_key_id")), requestedMs = 2_990_000)

    @Test fun sharedOriginalProofChecksBothGenuineSignaturesAndExactOffsets() {
        val proof = bundle(); val a = proof.core.association
        assertArrayEquals(value("association"), a.bytes()); assertArrayEquals(value("core"), proof.core.bytes())
        assertArrayEquals(value("bundle"), proof.bytes()); assertArrayEquals(value("device_signature"), proof.deviceSignature())
        assertArrayEquals(value("canary_signature"), proof.canarySignature())
        assertArrayEquals(parameter("enrolled_key_id"), ProtectionOriginProof.signingKeyId(parameter("enrolled_point")))
        assertEquals(UUID.fromString(p.getString("attempt_id")), proof.core.attemptId)
        assertEquals(3_000_000L, proof.core.issuedMs); assertEquals(3_030_000L, proof.core.expiresMs)
        for ((name, digest) in listOf("association" to a.sha256(), "core" to proof.core.sha256(), "bundle" to proof.sha256()))
            assertArrayEquals(decode(vector.getJSONObject("sha256").getString(name)), digest)
        a.requireOriginal(command()); a.requireProviderClaims(parameter("opening_nonce"), parameter("aes_probe"))
        proof.core.requireNonce(parameter("attempt_nonce"))
    }

    @Test fun originalAssociationAndAllProbeDomainsMatchTheSharedProducer() {
        val expected = association()
        val created = ProtectionOriginProof.Association.create(command(), UUID.fromString(p.getString("source_pairing_id")),
            parameter("opening_nonce"), parameter("hmac_probe"), parameter("aes_probe"), parameter("canary_point"))
        assertArrayEquals(expected.bytes(), created.bytes())
        val context = created.probeContext(parameter("opening_nonce"))
        assertEquals(192, context.size)
        assertArrayEquals(value("association").copyOfRange(8, 168) + parameter("opening_nonce"), context)
        val journal = ProtectionOriginProof.aesPlaintext("journal", context)
        val withdrawal = ProtectionOriginProof.aesPlaintext("withdrawal", context)
        assertFalse(journal.contentEquals(withdrawal))
        assertFalse(ProtectionOriginProof.aesAad("journal", context).contentEquals(ProtectionOriginProof.aesAad("withdrawal", context)))
        assertFalse(ProtectionOriginProof.hmacTranscript(context).contentEquals(ProtectionOriginProof.aesAad("journal", context)))
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginProof.aesAad("other", context) }
        assertThrows(IllegalArgumentException::class.java) { created.requireProviderClaims(parameter("attempt_nonce"), parameter("aes_probe")) }
        assertThrows(IllegalArgumentException::class.java) { created.requireProviderClaims(parameter("opening_nonce"),
            parameter("withdrawal_aes_probe") + parameter("journal_aes_probe")) }
    }

    @Test fun immutableOwnedBytesSurviveCallerAndGetterMutation() {
        val raw = value("bundle"); val aRaw = value("association"); val cRaw = value("core")
        val a = ProtectionOriginProof.Association.decode(aRaw); val c = ProtectionOriginProof.Core.decode(cRaw)
        val proof = ProtectionOriginProof.Bundle.verify(raw, a, parameter("enrolled_point"))
        raw.fill(0); aRaw.fill(0); cRaw.fill(0)
        proof.bytes().fill(0); a.canaryPoint.fill(0); c.bytes().fill(0)
        assertArrayEquals(value("bundle"), proof.bytes()); assertArrayEquals(value("association"), a.bytes())
        assertArrayEquals(value("core"), c.bytes())
    }

    @Test fun malformedVersionZeroScopePointAndSignedRangeRefuse() {
        for (size in listOf(0, 328, 330)) assertThrows(IllegalArgumentException::class.java) {
            ProtectionOriginProof.Association.decode(ByteArray(size))
        }
        for (offset in listOf(0, 4, 5, 6, 7)) assertThrows(IllegalArgumentException::class.java) {
            ProtectionOriginProof.Association.decode(value("association").apply { this[offset] = 9 })
        }
        for ((at, width) in listOf(8 to 16, 104 to 32, 264 to 65)) assertThrows(Exception::class.java) {
            ProtectionOriginProof.Association.decode(value("association").apply { fill(0, at, at + width) })
        }
        for ((issued, expires) in listOf(0L to 1L, 1L to 30_002L, 300L to 300L, -1L to Long.MAX_VALUE))
            assertThrows(IllegalArgumentException::class.java) { ProtectionOriginProof.Core.decode(value("core").apply {
                ByteBuffer.wrap(this, 345, 16).putLong(issued).putLong(expires)
            }) }
    }

    @Test fun everySignatureDomainAndOriginalBindingMutationRefuses() {
        for (at in listOf(24, 104, 345, 393, 457)) assertThrows(Exception::class.java) {
            ProtectionOriginProof.Bundle.verify(value("bundle").apply { this[at] = (this[at].toInt() xor 1).toByte() },
                association(), parameter("enrolled_point"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProtectionOriginProof.Bundle.verify(value("core") + value("canary_signature") + value("device_signature"),
                association(), parameter("enrolled_point"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProtectionOriginProof.Bundle.verify(value("bundle"), association(), parameter("canary_point"))
        }
        for (offset in listOf(393, 457)) {
            val raw = value("bundle")
            val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
            val high = order.subtract(BigInteger(1, raw.copyOfRange(offset + 32, offset + 64))).toByteArray().takeLast(32).toByteArray()
            high.copyInto(raw, offset + 32)
            assertThrows(IllegalArgumentException::class.java) { ProtectionOriginProof.Bundle.verify(raw, association(), parameter("enrolled_point")) }
        }
    }

    @Test fun setupClockUsesConservativeActualRttAndNeverRebasesAnOldSample() {
        val clock = ProtectionOriginClock.fromChallenge(core(), 1000, 3000)
        assertEquals(3_002_000L, clock.requireSigningTime(3000))
        assertEquals(3_029_999L, clock.requireSigningTime(30_999))
        assertThrows(IllegalArgumentException::class.java) { clock.requireSigningTime(31_000) }
        assertThrows(IllegalArgumentException::class.java) { clock.requireSigningTime(3001) }
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginClock.fromChallenge(core(), 1, 2002) }
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginClock.fromChallenge(core(), 2002, 1) }
        val expired = ProtectionOriginClock.fromChallenge(core(), 1, 1)
        expired.requireSigningTime(2)
        assertThrows(IllegalArgumentException::class.java) { expired.requireSigningTime(30_001) }
        assertThrows(IllegalArgumentException::class.java) { expired.requireSigningTime(100) }
        // A new object over a historical reply must NOT be minted by the actual controller;
        // only a newly committed first request has that authority. This pure helper has none.
        core().requireAcceptedTime(3_000_000)
        core().requireAcceptedTime(3_029_999)
        assertThrows(IllegalArgumentException::class.java) { core().requireAcceptedTime(3_030_000) }
    }

    @Test fun controlGrammarRejectsDuplicateFieldsCoercionMalformedUtf8AndOversize() {
        for (raw in listOf("{\"v\":1,\"v\":1}", "{\"v\":1.0}", "{\"v\":01}", "{\"v\":0}",
            "{\"v\":true}", "{\"v\":[]}", "{\"v\":9223372036854775808}", "{}{}"))
            assertThrows(Exception::class.java) { ProtectionOriginJson.objectValue(raw.toByteArray()) }
        assertThrows(Exception::class.java) { ProtectionOriginJson.objectValue(byteArrayOf(123, 34, -1, 34, 58, 49, 125)) }
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginJson.objectValue(ByteArray(4097)) }
        val map = ProtectionOriginJson.objectValue("{\"v\":1,\"previous\":null}".toByteArray())
        assertEquals(ProtectionOriginJson.Integer(1), map["v"]); assertSame(ProtectionOriginJson.Null, map["previous"])
        assertEquals(map, ProtectionOriginJson.objectValue(ProtectionOriginJson.render(map)))
    }

    @Test fun actualClosedOpeningMatchesIndependentLocalScopeWithoutAnElectionOrLine() {
        val fields = header("protection_origin_opened").apply { put("opening", opening()) }
        val reply = wire(fields) as ProtectionOriginWire.Opened
        assertArrayEquals(parameter("opening_nonce"), reply.opening.nonce)
        val retained = ProtectionOriginWire.retainedOpening(reply.opening.bytes(), command(), parameter("enrolled_point"))
        assertArrayEquals(reply.opening.bytes(), retained.bytes())
        for ((key, value) in listOf("connection_epoch" to "7", "extra" to "unexpected")) {
            assertThrows(IllegalArgumentException::class.java) { wire(LinkedHashMap(fields).apply { put(key, value) }) }
        }
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginWire.decode(ProtectionOriginJson.render(fields),
            command().copy(originSha256 = "a".repeat(64)), 7, parameter("enrolled_point")) }
        assertThrows(IllegalArgumentException::class.java) { ProtectionOriginWire.decode(ProtectionOriginJson.render(fields),
            command(), 8, parameter("enrolled_point")) }
    }

    @Test fun challengeAndReceiptKeepOriginalHashesAndAcceptanceWindow() {
        val fields = header("protection_origin_proof_challenge").apply { putAll(challenge()) }
        val reply = wire(fields) as ProtectionOriginWire.ProofChallenge
        assertArrayEquals(value("core"), reply.challenge.core.bytes())
        assertArrayEquals(parameter("attempt_nonce"), reply.challenge.nonce()); assertNull(reply.challenge.predecessor)
        val accepted = header("protection_origin_accepted").apply {
            put("proof_request_id", id(8)); put("attempt_id", p.getString("attempt_id")); put("receipt", receipt())
        }
        (wire(accepted) as ProtectionOriginWire.Accepted).receipt.requireMatches(bundle())
        val expired = LinkedHashMap(accepted).apply { put("receipt", receipt().apply { put("accepted_ms", "3030000") }) }
        assertThrows(IllegalArgumentException::class.java) { (wire(expired) as ProtectionOriginWire.Accepted).receipt.requireMatches(bundle()) }
        assertThrows(IllegalArgumentException::class.java) { wire(LinkedHashMap(fields).apply { put("nonce", p.getString("opening_nonce")) }) }
        assertThrows(IllegalArgumentException::class.java) { wire(LinkedHashMap(fields).apply { put("attempt_id", id(10)) }) }
    }

    @Test fun passiveStatusNeverAttributesSuccessToAnotherProofCommand() {
        val fields = header("protection_origin_status").apply {
            put("request_id", id(9)); put("proof_request_id", id(8)); put("status", "accepted")
            put("opening", opening()); put("challenge", challenge()); put("receipt", receipt())
        }
        val status = wire(fields) as ProtectionOriginWire.Status
        assertEquals("accepted", status.state); status.receipt!!.requireMatches(bundle())
        assertThrows(IllegalArgumentException::class.java) { wire(LinkedHashMap(fields).apply { put("proof_request_id", id(11)) }) }
        assertThrows(IllegalArgumentException::class.java) { wire(LinkedHashMap(fields).apply { put("status", "superseded") }) }
        val unknown = LinkedHashMap(fields).apply {
            put("status", "not_found"); put("opening", ProtectionOriginJson.Null)
            put("challenge", ProtectionOriginJson.Null); put("receipt", ProtectionOriginJson.Null)
        }
        assertEquals("not_found", (wire(unknown) as ProtectionOriginWire.Status).state)
    }

    private fun wire(fields: Map<String, Any>) = ProtectionOriginWire.decode(ProtectionOriginJson.render(fields),
        command(), 7, parameter("enrolled_point"), association())
    private fun header(type: String) = linkedMapOf<String, Any>("v" to ProtectionOriginJson.Integer(1), "type" to type,
        "connection_epoch" to ProtectionOriginJson.Integer(7), "setup_id" to command().setupId,
        "opening_id" to command().openingId, "command_id" to command().commandId)
    private fun opening() = linkedMapOf<String, Any>("account_id" to command().accountId, "device_id" to command().deviceId,
        "source_pairing_id" to p.getString("source_pairing_id"), "origin_digest" to p.getString("origin_digest"),
        "enrolled_point" to p.getString("enrolled_point"), "enrolled_key_id" to p.getString("enrolled_key_id"),
        "opening_nonce" to p.getString("opening_nonce"), "created_ms" to "2995000", "pairing_created_ms" to "2980000",
        "pairing_claimed_ms" to "2981000", "pairing_approved_ms" to "2982000", "pairing_expires_ms" to "2983000")
    private fun challenge() = linkedMapOf<String, Any>("proof_request_id" to id(8), "attempt_id" to p.getString("attempt_id"),
        "core" to vector.getString("core"), "nonce" to p.getString("attempt_nonce"), "closed_predecessor" to ProtectionOriginJson.Null)
    private fun receipt() = linkedMapOf<String, Any>("association_sha256" to vector.getJSONObject("sha256").getString("association"),
        "core_sha256" to vector.getJSONObject("sha256").getString("core"), "bundle_sha256" to vector.getJSONObject("sha256").getString("bundle"),
        "accepted_ms" to "3000001")
    private fun id(n: Long) = UUID(0, n).toString()
    private fun decode(value: String) = java.util.Base64.getUrlDecoder().decode(value)
    private fun hex(value: ByteArray) = Draft02OutboundPreparation.hex(value)
}
