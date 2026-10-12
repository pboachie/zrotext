// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Public wire/signature controls only. No enrollment, session, fetch transaction or receiver. */
abstract class Draft03DispatchWireCorpus {
    // Android's public JSONArray writer handles exact scalar and nested-object JSON.
    private fun jsonValue(value: Any): String = org.json.JSONArray().put(value).toString().let {
        it.substring(1, it.length - 1)
    }

    @Test fun publicGrantReadyAndFetchVectorReconstructExactly() {
        val fixture = fixture()
        val grant = SealedDispatch03Frames.grant(grantJson())
        val expected = hex(fixture.getJSONObject("grant").getString("transcriptHex"))
        assertEquals(362, expected.size)
        assertArrayEquals(expected, SealedEnvelopeFetch03.transcript(grant))
        val ready = SealedDispatch03Frames.ready(readyJson())
        assertEquals(grant.lineId, ready.lineId)
        assertEquals(grant.manifestVersion, ready.manifestVersion)
        assertArrayEquals(grant.electionDigest, ready.electionDigest)
        val fetch = SealedEnvelopeFetch03.parse(fetchJson())
        assertTrue(SealedEnvelopeFetch03.verify(fetch, point()))
        assertArrayEquals(expected, SealedEnvelopeFetch03.transcript(SealedDispatch03Frames.grant(grant.json())))
        assertEquals(ready.json(), SealedDispatch03Frames.ready(ready.json()).json())
        assertEquals(fetch.json(), SealedEnvelopeFetch03.parse(fetch.json()).json())
        // Property order and insignificant JSON whitespace never affect signature bytes.
        val values = JSONObject(grantJson())
        val reversed = values.keys().asSequence().toList().reversed().joinToString(",\n", "{\n", "\n}") {
            "\"$it\":${jsonValue(values.get(it))}"
        }
        assertArrayEquals(expected, SealedEnvelopeFetch03.transcript(SealedDispatch03Frames.grant(reversed)))
    }

    @Test fun everyFieldIsRequiredAndUnknownOrWrongTypedFieldsRefuse() {
        for ((raw, parse) in listOf(grantJson() to { s: String -> SealedDispatch03Frames.grant(s) },
            readyJson() to { s: String -> SealedDispatch03Frames.ready(s) },
            fetchJson() to { s: String -> SealedEnvelopeFetch03.parse(s) })) {
            val source = JSONObject(raw)
            for (name in source.keys().asSequence().toList()) {
                denied { parse(JSONObject(raw).apply { remove(name) }.toString()) }
                for (bad in listOf(JSONObject.NULL, true, JSONObject(), org.json.JSONArray())) {
                    denied { parse(JSONObject(raw).put(name, bad).toString()) }
                }
            }
            denied { parse(JSONObject(raw).put("extension", 1).toString()) }
        }
        denied { SealedEnvelopeFetch03.parse(JSONObject(fetchJson()).put("grant", grantJson()).toString()) }
    }

    @Test fun rawDuplicateDecodedNamesAndNestedDuplicatesRefuseBeforeProjection() {
        for ((raw, parse) in listOf(grantJson() to { s: String -> SealedDispatch03Frames.grant(s) },
            readyJson() to { s: String -> SealedDispatch03Frames.ready(s) },
            fetchJson() to { s: String -> SealedEnvelopeFetch03.parse(s) })) {
            val obj = JSONObject(raw)
            val name = obj.keys().next()
            val first = "\"$name\":${jsonValue(obj.get(name))},"
            denied { parse("{" + first + raw.drop(1)) }
        }
        val raw = grantJson()
        denied { SealedDispatch03Frames.grant("{" + escapedName("u0076") + ":1," + raw.drop(1)) }
        denied { SealedEnvelopeFetch03.parse("{\"grant\":{\"v\":1," + raw.drop(1) +
            ",\"signature_der\":\"${signatureText()}\"}") }
        denied { SealedEnvelopeFetch03.parse("{\"signature_der\":\"${signatureText()}\",\"signature_der\":\"${signatureText()}\",\"grant\":$raw}") }
    }

    @Test fun rawJsonBoundsDelimitersEscapesAndExactEofRefuseMalformedInput() {
        val raw = grantJson()
        for (bad in listOf("", "{}", "[]", "null", "\ufeff$raw", "$raw{}", "$raw true", "$raw\u0000",
            raw.dropLast(1), raw.dropLast(1) + ",}", raw.replaceFirst("\"v\"", "v"),
            raw.replaceFirst("\"v\"", "'v'"), raw.replaceFirst("\"v\"", escapedName("x76")),
            raw.replaceFirst("\"v\"", escapedName("uD800")), " ".repeat(16_385) + raw,
            raw.replaceFirst("\"type\":", "\"type\":/*comment*/"))) {
            denied { SealedDispatch03Frames.grant(bad) }
        }
        assertEquals(SealedDispatch03Frames.grant(raw).json(), SealedDispatch03Frames.grant(" \t\r\n$raw \t\r\n").json())
        // A valid escaped ASCII field spelling is decoded once; aliases cannot hide duplicates.
        assertEquals(SealedDispatch03Frames.grant(raw).json(), SealedDispatch03Frames.grant(raw.replaceFirst("\"v\"", escapedName("u0076"))).json())
        denied { SealedEnvelopeFetch03.parse("{\"grant\":{\"nested\":{}},\"signature_der\":\"${signatureText()}\"}") }
    }

    @Test fun signed64IntegersRemainExactBeyondFloatingPointPrecision() {
        val fields = listOf("connection_epoch", "deployment_epoch", "binding_generation", "attempt_generation",
            "expires_at_ms", "trust_generation", "manifest_version")
        for ((index, name) in fields.withIndex()) {
            for (exact in listOf(9_007_199_254_740_993L, Long.MAX_VALUE)) {
                val raw = replaceValue(grantJson(), name, exact.toString())
                val grant = SealedDispatch03Frames.grant(raw)
                assertEquals(exact, grant.integer(name))
                assertEquals(exact, ByteBuffer.wrap(SealedEnvelopeFetch03.transcript(grant), 114 + index * 8, 8).long)
            }
            for (bad in listOf("0", "-1", "9223372036854775808", "1.0", "1e0", "01", "+1", "\"1\"")) {
                denied { SealedDispatch03Frames.grant(replaceValue(grantJson(), name, bad)) }
            }
        }
        for (name in fields.filter { it != "attempt_generation" && it != "expires_at_ms" }) {
            assertEquals(Long.MAX_VALUE.toString(), JSONObject(SealedDispatch03Frames.ready(
                replaceValue(readyJson(), name, Long.MAX_VALUE.toString())).json()).get(name).toString())
            for (bad in listOf("0", "9223372036854775808", "2.5", "1e2", "\"2\"")) {
                denied { SealedDispatch03Frames.ready(replaceValue(readyJson(), name, bad)) }
            }
        }
    }

    @Test fun canonicalUuidAndDigestEncodingAreRequiredForEveryIdentity() {
        val source = JSONObject(grantJson())
        for (name in listOf("account_id", "device_id", "line_id", "message_id", "attempt_id")) {
            val original = source.getString(name)
            for (bad in listOf(original.uppercase(), original.replace("-", ""), "{$original}",
                "00000000-0000-0000-0000-000000000000", "1-1-1-1-1")) {
                denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put(name, bad).toString()) }
            }
        }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for (name in listOf("reader_key_id", "envelope_sha256", "unsigned_sha256", "manifest_digest", "root_fingerprint", "election_digest")) {
            val original = source.getString(name)
            val noncanonical = original.dropLast(1) + alphabet[alphabet.indexOf(original.last()) xor 1]
            for (bad in listOf(original + "=", original.dropLast(1), original + "A", noncanonical, "+" + original.drop(1), "")) {
                denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put(name, bad).toString()) }
            }
        }
        denied { SealedDispatch03Frames.ready(JSONObject(readyJson()).put("line_id", source.getString("line_id").uppercase()).toString()) }
        denied { SealedDispatch03Frames.ready(JSONObject(readyJson()).put("reader_key_id", source.getString("reader_key_id") + "=").toString()) }
    }

    @Test fun oldProfilesWrongRolesAndOutOfRangeSegmentsCannotBeReinterpreted() {
        for (name in listOf("v", "grant_version", "envelope_profile", "manifest_profile", "reader_role")) {
            val expected = JSONObject(grantJson()).getInt(name)
            for (bad in listOf(0, expected + 1, -1)) {
                denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put(name, bad).toString()) }
            }
            denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put(name, expected.toString()).toString()) }
        }
        for (bad in listOf(0, 7, -1)) denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put("segment_count", bad).toString()) }
        for (valid in 1..6) assertEquals(valid, SealedDispatch03Frames.grant(JSONObject(grantJson()).put("segment_count", valid).toString()).segmentCount)
        denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put("type", "sealed_ready").toString()) }
        for (name in listOf("grant_version", "envelope_profile", "manifest_profile")) {
            denied { SealedDispatch03Frames.grant(JSONObject(grantJson()).put(name, 2).toString()) }
            denied { SealedDispatch03Frames.ready(JSONObject(readyJson()).put(name, 2).toString()) }
        }
    }

    @Test fun publicSignatureBindsEveryTranscriptFieldAndIndependentPoint() {
        val pair = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        val original = SealedDispatch03Frames.grant(grantJson())
        val bytes = SealedEnvelopeFetch03.transcript(original)
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(bytes); sign() }
        val (r, s) = scalars(der)
        val low = encodeDer(r, if (s > order.shiftRight(1)) order - s else s)
        val fetch = SealedEnvelopeFetch03.parse(fetchJson(original.json(), low))
        val public = DevicePayloadKeyStore.encodePoint(pair.public as ECPublicKey)
        assertTrue(SealedEnvelopeFetch03.verify(fetch, public))
        assertFalse(SealedEnvelopeFetch03.verify(fetch, point()))
        denied { SealedEnvelopeFetch03.verify(fetch, ByteArray(65)) }
        denied { SealedEnvelopeFetch03.verify(fetch, public.copyOf(64)) }
        for (name in listOf("account_id", "device_id", "line_id", "message_id", "attempt_id")) {
            val changed = JSONObject(grantJson()).put(name, "11111111-2222-3333-4444-555555555555").toString()
            assertFalse(SealedEnvelopeFetch03.verify(SealedEnvelopeFetch03.parse(fetchJson(changed, low)), public))
        }
        for (name in listOf("connection_epoch", "deployment_epoch", "binding_generation", "attempt_generation", "expires_at_ms", "trust_generation", "manifest_version", "segment_count")) {
            val source = JSONObject(grantJson())
            val changed = source.put(name, source.getLong(name) + 1).toString()
            assertFalse(SealedEnvelopeFetch03.verify(SealedEnvelopeFetch03.parse(fetchJson(changed, low)), public))
        }
        for (name in listOf("reader_key_id", "envelope_sha256", "unsigned_sha256", "manifest_digest", "root_fingerprint", "election_digest")) {
            val changed = JSONObject(grantJson()).put(name, b64(ByteArray(32) { 9 })).toString()
            assertFalse(SealedEnvelopeFetch03.verify(SealedEnvelopeFetch03.parse(fetchJson(changed, low)), public))
        }
        val wrongDomain = bytes.copyOf().also { it[26] = '1'.code.toByte() }
        val wrongDer = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(wrongDomain); sign() }
        val (wr, ws) = scalars(wrongDer)
        assertFalse(SealedEnvelopeFetch03.verify(SealedEnvelopeFetch03.parse(fetchJson(original.json(),
            encodeDer(wr, if (ws > order.shiftRight(1)) order - ws else ws))), public))
    }

    @Test fun receivedDerIsMinimalInRangeLowSAndNeverNormalized() {
        val minimum = encodeDer(BigInteger.ONE, BigInteger.ONE)
        assertEquals(8, minimum.size)
        val maximum = encodeDer(order - BigInteger.ONE, order.shiftRight(1))
        assertEquals(71, maximum.size)
        for (validShape in listOf(minimum, maximum)) {
            val fetch = SealedEnvelopeFetch03.parse(fetchJson(grantJson(), validShape))
            assertFalse(SealedEnvelopeFetch03.verify(fetch, point())) // Shape does not imply a valid proof.
        }
        val actual = Base64.getUrlDecoder().decode(signatureText())
        val (r, s) = scalars(actual)
        assertTrue(s <= order.shiftRight(1))
        val high = encodeDer(r, order - s)
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(DevicePayloadKeyStore.decodePoint(point())); update(SealedEnvelopeFetch03.transcript(SealedDispatch03Frames.grant(grantJson()))); verify(high)
        })
        val badDer = listOf(high, encodeDer(BigInteger.ZERO, BigInteger.ONE), encodeDer(order, BigInteger.ONE),
            encodeDer(BigInteger.ONE, BigInteger.ZERO), encodeDer(BigInteger.ONE, order),
            byteArrayOf(0x30, 6, 2, 1, 0x80.toByte(), 2, 1, 1),
            byteArrayOf(0x30, 7, 2, 2, 0, 1, 2, 1, 1),
            byteArrayOf(0x30, 7, 2, 0x81.toByte(), 1, 1, 2, 1, 1),
            byteArrayOf(0x30, 0x81.toByte(), 6, 2, 1, 1, 2, 1, 1),
            actual + byteArrayOf(0), actual.copyOf(actual.size - 1), byteArrayOf())
        for (bad in badDer) denied { SealedEnvelopeFetch03.parse(fetchJson(grantJson(), bad)) }
        denied { SealedEnvelopeFetch03.parse(fetchJson().replace(signatureText(), signatureText() + "=")) }
        denied { SealedEnvelopeFetch03.parse(fetchJson().replace(signatureText(), "A")) }
    }

    @Test fun byteOutputsAndSuppliedSignatureAreOwnedAndSyntaxDoesNotRequireFreshness() {
        val grant = SealedDispatch03Frames.grant(grantJson())
        val original = SealedEnvelopeFetch03.transcript(grant)
        grant.readerKeyId.fill(0); grant.manifestDigest.fill(0); grant.electionDigest.fill(0)
        SealedEnvelopeFetch03.transcript(grant).fill(0)
        assertArrayEquals(original, SealedEnvelopeFetch03.transcript(grant))
        val signature = Base64.getUrlDecoder().decode(signatureText())
        val fetch = SealedEnvelopeFetch03.Fetch(grant, signature)
        signature.fill(0); fetch.signatureDer.fill(0)
        assertTrue(SealedEnvelopeFetch03.verify(fetch, point()))
        // No clock/current adapter exists here: an expired frame can prove syntax, never permission.
        val historical = SealedDispatch03Frames.grant(replaceValue(grantJson(), "expires_at_ms", "1"))
        assertEquals(1L, historical.expiresAtMs)
        assertFalse(SealedEnvelopeFetch03.verify(SealedEnvelopeFetch03.parse(fetchJson(historical.json(), fetch.signatureDer)), point()))
    }

    private fun fixture(): JSONObject = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-contract-01.json")!!.use {
        JSONObject(it.bufferedReader(Charsets.UTF_8).readText())
    }
    private fun grantJson() = fixture().getJSONObject("grant").getJSONObject("frame").toString()
    private fun readyJson() = fixture().getJSONObject("readyFrame").toString()
    private fun signatureText() = fixture().getJSONObject("grant").getString("signatureDerBase64url")
    private fun point() = hex(fixture().getJSONObject("publicPointsHex").getString("deviceEnrollment"))
    private fun fetchJson(grant: String = grantJson(), signature: ByteArray = Base64.getUrlDecoder().decode(signatureText())) =
        "{\"grant\":$grant,\"signature_der\":\"${b64(signature)}\"}"
    private fun replaceValue(raw: String, name: String, literal: String): String {
        val pattern = Regex("\\\"$name\\\"\\s*:\\s*[^,}]+")
        require(pattern.findAll(raw).count() == 1)
        return pattern.replace(raw, "\"$name\":$literal")
    }
    private fun escapedName(value: String) = "\"" + '\\' + value + "\""
    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun scalars(der: ByteArray): Pair<BigInteger, BigInteger> {
        val rSize = der[3].toInt() and 255
        val sAt = 4 + rSize
        val sSize = der[sAt + 1].toInt() and 255
        return BigInteger(1, der.copyOfRange(4, sAt)) to BigInteger(1, der.copyOfRange(sAt + 2, sAt + 2 + sSize))
    }
    private fun encodeDer(r: BigInteger, s: BigInteger): ByteArray {
        fun field(value: BigInteger): ByteArray = value.toByteArray().let { byteArrayOf(2, it.size.toByte()) + it }
        val fields = field(r) + field(s)
        return byteArrayOf(0x30, fields.size.toByte()) + fields
    }
    private fun denied(block: () -> Any?) {
        try { block() } catch (_: IllegalArgumentException) { return }
        fail("Expected strict wire refusal")
    }
    companion object {
        private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    }
}
