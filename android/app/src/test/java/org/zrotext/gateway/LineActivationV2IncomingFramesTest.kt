// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class LineActivationV2IncomingFramesTest {
    // Public synthetic shapes only. accepted=true is not authenticated activation authority.
    private data class Literal(val purpose: LineActivationV2Purpose, val raw: String)
    private val literals = listOf(
        Literal(LineActivationV2Purpose.SMS, """{"type":"sms_line_challenge_v2","v":2,"challenge_id":"00000000-0000-4000-8000-000000000004","account_id":"00000000-0000-4000-8000-000000000001","line_id":"00000000-0000-4000-8000-000000000002","device_id":"00000000-0000-4000-8000-000000000003","generation":"1","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","expires_at_ms":1700000300000}"""),
        Literal(LineActivationV2Purpose.SMS, """{"type":"sms_line_proof_ack_v2","v":2,"challenge_id":"00000000-0000-4000-8000-000000000004","accepted":true}"""),
        Literal(LineActivationV2Purpose.SMS, """{"type":"sms_line_activated_v2","v":2,"challenge_id":"00000000-0000-4000-8000-000000000004","account_id":"00000000-0000-4000-8000-000000000001","line_id":"00000000-0000-4000-8000-000000000002","device_id":"00000000-0000-4000-8000-000000000003","generation":"1","device_statement_sha256":"4eTJkC_2cL8nU6aSW9Vet_Vwq7qdePrtNRuDh-kGUg8","device_signature_sha256":"Vwk5RML3MPXVVBc8s1VXlcGk9oxke-D_jjrbhAt1dnU"}"""),
        Literal(LineActivationV2Purpose.SEALED, """{"type":"sealed_line_challenge_v2","v":2,"connection_epoch":"1","challenge_id":"00000000-0000-4000-8000-000000000004","account_id":"00000000-0000-4000-8000-000000000001","line_id":"00000000-0000-4000-8000-000000000002","device_id":"00000000-0000-4000-8000-000000000003","generation":"1","nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","expires_at_ms":1700000300000}"""),
        Literal(LineActivationV2Purpose.SEALED, """{"type":"sealed_line_proof_ack_v2","v":2,"connection_epoch":"1","challenge_id":"00000000-0000-4000-8000-000000000004","accepted":true}"""),
        Literal(LineActivationV2Purpose.SEALED, """{"type":"sealed_line_activated_v2","v":2,"connection_epoch":"1","challenge_id":"00000000-0000-4000-8000-000000000004","account_id":"00000000-0000-4000-8000-000000000001","line_id":"00000000-0000-4000-8000-000000000002","device_id":"00000000-0000-4000-8000-000000000003","generation":"1","device_statement_sha256":"PHsRMCKe3cs5yqidBZihrJ57ZzC4RgFm3sl566Tl14I","device_signature_sha256":"Vwk5RML3MPXVVBc8s1VXlcGk9oxke-D_jjrbhAt1dnU"}"""),
        Literal(LineActivationV2Purpose.SEALED, """{"type":"sealed_line_installed_v2","v":2,"connection_epoch":"1","challenge_id":"00000000-0000-4000-8000-000000000004","account_id":"00000000-0000-4000-8000-000000000001","line_id":"00000000-0000-4000-8000-000000000002","device_id":"00000000-0000-4000-8000-000000000003","generation":"1","device_statement_sha256":"PHsRMCKe3cs5yqidBZihrJ57ZzC4RgFm3sl566Tl14I","device_signature_sha256":"Vwk5RML3MPXVVBc8s1VXlcGk9oxke-D_jjrbhAt1dnU"}"""),
        Literal(LineActivationV2Purpose.SEALED, """{"type":"sealed_line_install_ack_v2","v":2,"connection_epoch":"1","challenge_id":"00000000-0000-4000-8000-000000000004","accepted":true}""")
    )
    private val jsonEscape = '\\'
    private fun bytes(text: String) = text.toByteArray(Charsets.UTF_8)
    private fun decode(index: Int, frame: JSONObject = JSONObject(literals[index].raw)) =
        LineActivationV2IncomingFrames.parse(bytes(frame.toString()), literals[index].purpose)
    private fun reject(text: String, purpose: LineActivationV2Purpose = LineActivationV2Purpose.SMS) {
        assertThrows(IllegalArgumentException::class.java) {
            LineActivationV2IncomingFrames.parse(bytes(text), purpose)
        }
    }
    private fun rejectBytes(raw: ByteArray) {
        assertThrows(IllegalArgumentException::class.java) {
            LineActivationV2IncomingFrames.parse(raw, LineActivationV2Purpose.SMS)
        }
    }
    private fun id(n: Int) = UUID(0x4000L, Long.MIN_VALUE or n.toLong())
    private fun expectedBytes(value: String) = Base64.getUrlDecoder().decode(value)
    private fun assertIdentity(value: LineActivationV2IncomingFrames.Receipt) {
        assertEquals(id(4), value.challengeId)
        assertEquals(id(1), value.accountId)
        assertEquals(id(2), value.lineId)
        assertEquals(id(3), value.deviceId)
        assertEquals(1L, value.generation)
    }

    @Test fun allEightLiteralShapesDecodeToDistinctInertData() {
        literals.forEachIndexed { index, literal ->
            val value = decode(index)
            assertEquals(literal.purpose, value.purpose)
            when (value) {
                is LineActivationV2IncomingFrames.Challenge -> {
                    assertEquals(id(4), value.challengeId)
                    assertEquals(id(1), value.accountId)
                    assertEquals(id(2), value.lineId)
                    assertEquals(id(3), value.deviceId)
                    assertEquals(1L, value.generation)
                    assertEquals(1_700_000_300_000L, value.expiresAtMs)
                    assertArrayEquals(ByteArray(32) { it.toByte() }, value.nonce())
                }
                is LineActivationV2IncomingFrames.ProofAck -> {
                    assertEquals(id(4), value.challengeId)
                    assertTrue(value.accepted)
                }
                is LineActivationV2IncomingFrames.Receipt -> {
                    assertIdentity(value)
                    val frame = JSONObject(literal.raw)
                    assertArrayEquals(expectedBytes(frame.getString("device_statement_sha256")),
                        value.deviceStatementSha256())
                    assertArrayEquals(expectedBytes(frame.getString("device_signature_sha256")),
                        value.deviceSignatureSha256())
                }
                is LineActivationV2IncomingFrames.SealedInstallAck -> {
                    assertEquals(id(4), value.challengeId)
                    assertEquals(1L, value.connectionEpoch)
                    assertTrue(value.accepted)
                }
            }
        }
        assertTrue(decode(0) is LineActivationV2IncomingFrames.SmsChallenge)
        assertTrue(decode(1) is LineActivationV2IncomingFrames.SmsProofAck)
        assertTrue(decode(2) is LineActivationV2IncomingFrames.SmsActivated)
        assertTrue(decode(3) is LineActivationV2IncomingFrames.SealedChallenge)
        assertTrue(decode(4) is LineActivationV2IncomingFrames.SealedProofAck)
        assertTrue(decode(5) is LineActivationV2IncomingFrames.SealedActivated)
        assertTrue(decode(6) is LineActivationV2IncomingFrames.SealedInstalled)
        assertTrue(decode(7) is LineActivationV2IncomingFrames.SealedInstallAck)
        assertEquals(1L, (decode(3) as LineActivationV2IncomingFrames.SealedChallenge).connectionEpoch)
        assertEquals(1L, (decode(4) as LineActivationV2IncomingFrames.SealedProofAck).connectionEpoch)
        assertEquals(1L, (decode(5) as LineActivationV2IncomingFrames.SealedActivated).connectionEpoch)
        assertEquals(1L, (decode(6) as LineActivationV2IncomingFrames.SealedInstalled).connectionEpoch)
    }

    @Test fun everyShapeRejectsMissingUnknownAndNullFields() {
        literals.forEachIndexed { index, literal ->
            val fields = JSONObject(literal.raw).keys().asSequence().toList()
            fields.forEach { key ->
                val missing = JSONObject(literal.raw).also { it.remove(key) }
                reject(missing.toString(), literal.purpose)
                val nil = JSONObject(literal.raw).put(key, JSONObject.NULL)
                reject(nil.toString(), literal.purpose)
            }
            reject(JSONObject(literal.raw).put("extra", true).toString(), literal.purpose)
            assertEquals(literal.purpose, decode(index).purpose)
        }
    }

    @Test fun smsResponseFieldSetsHaveNoEpochAndAllSealedSetsRequireIt() {
        for (index in 0..2) reject(JSONObject(literals[index].raw).put("connection_epoch", "1").toString())
        for (index in 3..7) {
            val value = JSONObject(literals[index].raw).also { it.remove("connection_epoch") }
            reject(value.toString(), LineActivationV2Purpose.SEALED)
        }
    }

    @Test fun duplicateAndEscapedDuplicateKeysAreRejectedBeforeOverwrite() {
        literals.forEach { literal ->
            val type = JSONObject(literal.raw).getString("type")
            reject(literal.raw.dropLast(1) + ",\"type\":\"$type\"}", literal.purpose)
            reject(literal.raw.dropLast(1) + ",\"${jsonEscape}u0074ype\":\"$type\"}", literal.purpose)
            reject(literal.raw.dropLast(1) + ",\"v\":2}", literal.purpose)
            reject(literal.raw.dropLast(1) + ",\"${jsonEscape}u0076\":2}", literal.purpose)
        }
    }

    @Test fun oneEscapedKeyAndMemberReorderingAreValidJsonWithoutDuplicateLoss() {
        val escaped = literals[1].raw.replace("\"type\"", "\"${jsonEscape}u0074ype\"")
        assertTrue(LineActivationV2IncomingFrames.parse(bytes(escaped), LineActivationV2Purpose.SMS)
            is LineActivationV2IncomingFrames.SmsProofAck)
        val reversed = "{\"accepted\":false,\"challenge_id\":\"00000000-0000-4000-8000-000000000004\",\"v\":2,\"type\":\"sms_line_proof_ack_v2\"}"
        assertFalse((LineActivationV2IncomingFrames.parse(bytes(reversed), LineActivationV2Purpose.SMS)
            as LineActivationV2IncomingFrames.SmsProofAck).accepted)
    }

    @Test fun rawVersionMustBeExactlyIntegerTwoWithoutCoercion() {
        listOf("2.0", "2e0", "2E0", "+2", "02", "-2", "0", "1", "\"2\"", "true", "null", "NaN", "Infinity")
            .forEach { bad -> reject(literals[1].raw.replace("\"v\":2", "\"v\":$bad")) }
    }

    @Test fun decimalStringEpochAndGenerationRetainLongMaximumExactly() {
        val frame = JSONObject(literals[3].raw).put("generation", Long.MAX_VALUE.toString())
            .put("connection_epoch", Long.MAX_VALUE.toString())
        val value = decode(3, frame) as LineActivationV2IncomingFrames.SealedChallenge
        assertEquals(Long.MAX_VALUE, value.generation)
        assertEquals(Long.MAX_VALUE, value.connectionEpoch)
        listOf("0", "01", "+1", "-1", "1.0", "1e0", "", " 1", "9223372036854775808").forEach { bad ->
            for (key in listOf("generation", "connection_epoch"))
                reject(JSONObject(literals[3].raw).put(key, bad).toString(), LineActivationV2Purpose.SEALED)
        }
        for (key in listOf("generation", "connection_epoch")) {
            for (bad in listOf<Any>(1L, true, JSONObject.NULL))
                reject(JSONObject(literals[3].raw).put(key, bad).toString(), LineActivationV2Purpose.SEALED)
        }
    }

    @Test fun expiryIsExactRawIntegerAndPurposeSpecificOverflowBoundsRemain() {
        val sms = decode(0, JSONObject(literals[0].raw).put("expires_at_ms", Long.MAX_VALUE))
            as LineActivationV2IncomingFrames.SmsChallenge
        assertEquals(Long.MAX_VALUE, sms.expiresAtMs)
        val beyondDouble = 9_007_199_254_740_993L
        assertEquals(beyondDouble, (decode(0, JSONObject(literals[0].raw).put("expires_at_ms", beyondDouble))
            as LineActivationV2IncomingFrames.SmsChallenge).expiresAtMs)
        val end = Long.MAX_VALUE - SealedLineActivationTranscript.ACK_GRACE_MS
        assertEquals(end, (decode(3, JSONObject(literals[3].raw).put("expires_at_ms", end))
            as LineActivationV2IncomingFrames.SealedChallenge).expiresAtMs)
        reject(JSONObject(literals[3].raw).put("expires_at_ms", end + 1).toString(), LineActivationV2Purpose.SEALED)
        reject(literals[0].raw.replace("1700000300000", "9223372036854775808"))
        listOf("0", "-1", "1700000300000.0", "17000003e5", "+1700000300000", "\"1700000300000\"", "true", "null")
            .forEach { bad -> reject(literals[0].raw.replace("1700000300000", bad)) }
    }

    @Test fun acceptedIsARealBooleanAndNeverChangesTheReceiptPhase() {
        for (index in listOf(1, 4, 7)) {
            val literal = literals[index]
            for (bad in listOf("\"true\"", "1", "TRUE", "True", "FALSE", "null"))
                reject(literal.raw.replace("\"accepted\":true", "\"accepted\":$bad"), literal.purpose)
            val falseValue = decode(index, JSONObject(literal.raw).put("accepted", false))
            val accepted = if (falseValue is LineActivationV2IncomingFrames.ProofAck) falseValue.accepted
                else (falseValue as LineActivationV2IncomingFrames.SealedInstallAck).accepted
            assertFalse(accepted)
            assertFalse(falseValue is LineActivationV2IncomingFrames.Receipt)
        }
    }

    @Test fun uuidsAreCanonicalLowercaseAndNonnilWithoutInventingV4Restriction() {
        val nil = "00000000-0000-0000-0000-000000000000"
        val bad = listOf(nil, "00000000-0000-4000-8000-4", "A0000000-0000-4000-8000-000000000004",
            "00000000000040008000000000000004", "00000000-0000-4000-8000-000000000004 ")
        bad.forEach { value ->
            for (key in listOf("challenge_id", "account_id", "line_id", "device_id"))
                reject(JSONObject(literals[0].raw).put(key, value).toString())
        }
        reject(JSONObject(literals[1].raw).put("challenge_id", 4).toString())
        val otherVersion = "00000000-0000-1000-0000-000000000004"
        assertEquals(UUID.fromString(otherVersion), (decode(1, JSONObject(literals[1].raw)
            .put("challenge_id", otherVersion)) as LineActivationV2IncomingFrames.SmsProofAck).challengeId)
    }

    @Test fun base64BytesRejectPaddingAlphabetLengthAndNoncanonicalFinalBits() {
        for ((index, key) in listOf(0 to "nonce", 3 to "nonce", 2 to "device_statement_sha256",
                2 to "device_signature_sha256")) {
            val literal = literals[index]
            val original = JSONObject(literal.raw).getString(key)
            val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            val alternative = original.dropLast(1) + alphabet[alphabet.indexOf(original.last()) xor 1]
            val wrong = listOf(original + "=", "+" + original.drop(1), original.dropLast(1),
                original + "A", alternative, "")
            wrong.forEach { bad -> reject(JSONObject(literal.raw).put(key, bad).toString(), literal.purpose) }
        }
    }

    @Test fun nonceAndHashZeroRulesPreserveTheirActualPurposeAsymmetry() {
        val zero = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        assertArrayEquals(ByteArray(32), (decode(0, JSONObject(literals[0].raw).put("nonce", zero))
            as LineActivationV2IncomingFrames.SmsChallenge).nonce())
        reject(JSONObject(literals[3].raw).put("nonce", zero).toString(), LineActivationV2Purpose.SEALED)
        val value = decode(2, JSONObject(literals[2].raw).put("device_statement_sha256", zero))
            as LineActivationV2IncomingFrames.SmsActivated
        assertArrayEquals(ByteArray(32), value.deviceStatementSha256())
        // Syntactic digest data is not an exact-proof match or authenticated activation.
    }

    @Test fun purposeVersionAndBothSeparateProofTypesAreRefused() {
        literals.forEach { literal ->
            val other = if (literal.purpose == LineActivationV2Purpose.SMS) LineActivationV2Purpose.SEALED
                else LineActivationV2Purpose.SMS
            reject(literal.raw, other)
            reject(literal.raw.replace("_v2\"", "\""), literal.purpose)
        }
        reject(literals[1].raw.replace("sms_line_proof_ack_v2", "sms_line_proof_v2"))
        reject(literals[7].raw.replace("sealed_line_install_ack_v2", "sealed_line_proof_v2"),
            LineActivationV2Purpose.SEALED)
    }

    @Test fun onlyOneStrictFlatJsonObjectWithoutCommentsOrTrailingInputIsAccepted() {
        val raw = literals[1].raw
        listOf("[$raw]", "/*comment*/$raw", "$raw//comment", "$raw {}", "$raw true", "$raw 0",
            raw.dropLast(1) + ",}", raw.replace("\"v\":", "v:"), raw.replace("\"type\"", "'type'"),
            raw.replace("\"accepted\":true", "\"accepted\":[]"),
            raw.replace("\"accepted\":true", "\"accepted\":{}"), raw.dropLast(1), "", " ")
            .forEach { reject(it) }
    }

    @Test fun invalidEscapesAndUnescapedStringControlsAreNotNormalized() {
        reject(literals[1].raw.replace("\"type\"", "\"t${jsonEscape}ype\""))
        reject(literals[1].raw.replace("sms_line_proof_ack_v2", "sms_line_proof_ack_\\v2"))
        reject(literals[1].raw.replace("sms_line_proof_ack_v2", "sms_line_proof_ack_\nv2"))
        reject(literals[1].raw.replace("sms_line_proof_ack_v2", "sms_line_proof_ack_\u0001v2"))
    }

    @Test fun bomMalformedUtf8AndNonJsonWhitespaceAreRejected() {
        val raw = bytes(literals[1].raw)
        rejectBytes(byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + raw)
        rejectBytes(byteArrayOf(0xc0.toByte(), 0xaf.toByte()) + raw)
        rejectBytes(raw + byteArrayOf(0xc3.toByte()))
        reject("\u00a0" + literals[1].raw)
    }

    @Test fun rawByteBudgetIncludesWhitespaceAndAcceptsExactly4096() {
        val raw = bytes(literals[1].raw)
        val boundary = raw + ByteArray(4096 - raw.size) { ' '.code.toByte() }
        assertEquals(4096, boundary.size)
        assertTrue(LineActivationV2IncomingFrames.parse(boundary, LineActivationV2Purpose.SMS)
            is LineActivationV2IncomingFrames.SmsProofAck)
        rejectBytes(boundary + byteArrayOf(' '.code.toByte()))
    }

    @Test fun inputAndAllOutputByteArraysAreDefensivelyCopied() {
        val raw = bytes(literals[0].raw)
        val challenge = LineActivationV2IncomingFrames.parse(raw, LineActivationV2Purpose.SMS)
            as LineActivationV2IncomingFrames.SmsChallenge
        raw.fill(0)
        challenge.nonce().fill(0)
        assertArrayEquals(ByteArray(32) { it.toByte() }, challenge.nonce())
        for (index in listOf(2, 5, 6)) {
            val receipt = decode(index) as LineActivationV2IncomingFrames.Receipt
            val statement = receipt.deviceStatementSha256()
            val signature = receipt.deviceSignatureSha256()
            receipt.deviceStatementSha256().fill(0)
            receipt.deviceSignatureSha256().fill(0)
            assertArrayEquals(statement, receipt.deviceStatementSha256())
            assertArrayEquals(signature, receipt.deviceSignatureSha256())
        }
    }

    @Test fun diagnosticsAreRedactedAndNoBooleanReceiptBecomesAProofMatch() {
        literals.indices.forEach { index -> assertEquals("LineActivationV2IncomingFrame(redacted)", decode(index).toString()) }
        val error = assertThrows(IllegalArgumentException::class.java) {
            LineActivationV2IncomingFrames.parse(bytes(literals[1].raw + " extra"), LineActivationV2Purpose.SMS)
        }
        assertEquals("Invalid v2 line frame", error.message)
        assertNull(error.cause)
        assertTrue(decode(1) is LineActivationV2IncomingFrames.ProofAck)
        assertTrue(decode(7) is LineActivationV2IncomingFrames.SealedInstallAck)
    }
}
