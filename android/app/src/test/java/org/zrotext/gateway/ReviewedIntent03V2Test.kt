// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Genuine synthetic signatures and body GCM. Public proofs do not supply installed113,
 * transport provenance, maintained HPKE custody, an effect journal or radio permission. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ReviewedIntent03V2Test {
    private fun verify(f: Profile03ExecutionFixture, intent: ReviewedIntent03V2 = f.intentV2,
        signature: ByteArray = f.intentV2Signature, admitted: Long = f.admittedAt, now: Long = f.now,
        epoch: Long = 1, origin: ByteArray = f.origins.protocolDigest()) =
        intent.verifyReceipt(signature, f.authority, f.election.requireCurrent(f.authority, f.currentSelection, now),
            admitted, now, epoch, origin, 1, 200_000)

    @Test fun distinctV2SignatureBindsExactCiphertextReadersAndCeilingWithoutAPlaintextDigest(): Unit = Profile03ExecutionFixture().use { f ->
        val request = verify(f)
        val proof = Draft03OutboundEnvelope.verify(f.envelope, f.authority, request) { f.now }
        assertArrayEquals(proof.envelopeDigest, f.intentV2.envelopeSha256)
        assertArrayEquals(proof.unsignedDigest, f.intentV2.unsignedSha256)
        f.intentV2.requireGrant(f.grant)
        assertEquals(592, f.intentV2Bytes.size)
        assertFalse(f.intentV2Bytes.asList().windowed(32).any { it.toByteArray().contentEquals(Profile03ExecutionFixture.sha(f.body)) })
        assertEquals(3, f.intentV2Bytes[520].toInt())
        val clear = Draft03Body.open(proof, f.authority, request, f.now, f.key.copyOf())
        try { assertArrayEquals(f.body, String(clear).toByteArray(Charsets.UTF_8)) }
        finally { clear.fill('\u0000') }
    }

    @Test fun historicalV1RemainsExactButCannotEnterTheV2CodecOrSignatureDomain(): Unit = Profile03ExecutionFixture().use { f ->
        assertEquals(624, f.intentBytes.size)
        f.intent.verifyReceipt(f.intentSignature, f.authority, f.election.requireCurrent(f.authority, f.currentSelection, f.now),
            f.admittedAt, f.now, 3, f.origins.protocolDigest(), 1, 200_000)
        denied { ReviewedIntent03V2.decode(f.intentBytes) }
        denied { ReviewedIntent03.decode(f.intentV2Bytes) }
        denied { ReviewedIntent03V2.decode(f.intentBytes.copyOf().apply { this[4] = 2 }) }
        denied { verify(f, signature = f.signIntent(f.intentV2Bytes)) }
        denied { verify(f, signature = Profile03ExecutionFixture.rawSign(f.signer,
            ReviewedIntent03.framed("ZTSE/sign/v3", f.intentV2Bytes))) }
        assertArrayEquals(Profile03ExecutionFixture.sha(f.body), f.intent.bodySha256)
        assertArrayEquals(f.intentBytes, f.intent.bytes())
    }

    @Test fun originalAdmissionTimeDoesNotRenewReviewAndWholeMessageBounds(): Unit = Profile03ExecutionFixture().use { f ->
        verify(f, now = f.intentV2.reviewExpiresMs + 1)
        for (admitted in listOf(f.intentV2.reviewIssuedMs - 1, f.intentV2.reviewExpiresMs)) denied { verify(f, admitted = admitted) }
        denied { verify(f, now = f.intentV2.expiresMs) }
        denied { verify(f, epoch = 3) }
        denied { verify(f, origin = ByteArray(32) { 8 }) }
        val edits: List<(ByteArray) -> Unit> = listOf(
            { it[360] = (it[360].toInt() xor 1).toByte() },
            { it[392] = (it[392].toInt() xor 1).toByte() },
            { ByteBuffer.wrap(it).putLong(176, 100_010) },
            { ByteBuffer.wrap(it).putLong(184, 100_030) },
            { ByteBuffer.wrap(it).putLong(192, 130_011) })
        for (edit in edits) {
            val raw = f.intentV2Bytes.copyOf().apply(edit)
            denied { verify(f, ReviewedIntent03V2.decode(raw), f.signIntentV2(raw)) }
        }
    }

    @Test fun everyFixedFieldAndCorrectlyResignedScopeSubstitutionRefuses(): Unit = Profile03ExecutionFixture().use { f ->
        for (at in (8 until 136 step 16) + (136 until 200 step 8) + (200 until 520 step 32)) {
            val raw = f.intentV2Bytes.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            denied { verify(f, ReviewedIntent03V2.decode(raw)) }
        }
        // Fresh VALID role5 signatures isolate the independent selected context checks.
        for (at in listOf(8, 24, 40, 56, 200, 232, 264, 296, 328)) {
            val raw = f.intentV2Bytes.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            denied { verify(f, ReviewedIntent03V2.decode(raw), f.signIntentV2(raw)) }
        }
        for (offset in listOf(144, 160)) for (value in listOf(0L, 2L, Long.MIN_VALUE)) denied {
            ReviewedIntent03V2.decode(f.intentV2Bytes.copyOf().apply { ByteBuffer.wrap(this).putLong(offset, value) })
        }
    }

    @Test fun highSWrongKeyCiphertextAndCeilingCannotAcquireOriginalGrant(): Unit = Profile03ExecutionFixture().use { f ->
        val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        val high = order.subtract(BigInteger(1, f.intentV2Signature.copyOfRange(32, 64))).toByteArray().takeLast(32).toByteArray()
        val signature = f.intentV2Signature.copyOf().apply { fill(0, 32, 64); high.copyInto(this, 64 - high.size) }
        denied { verify(f, signature = signature) }
        denied { verify(f, signature = Profile03ExecutionFixture.rawSign(f.enrollment, f.intentV2.transcript())) }
        val raw = f.intentV2Bytes.copyOf().apply { this[lastIndex] = 6 }
        val changed = ReviewedIntent03V2.decode(raw)
        verify(f, changed, f.signIntentV2(raw))
        denied { changed.requireGrant(f.grant) }
        val wrong = f.grant.json().let { JSONObject(it).put("envelope_sha256", Profile03ExecutionFixture.b64(ByteArray(32) { 9 })) }
        denied { f.intentV2.requireGrant(SealedDispatch03Frames.grant(wrong.toString())) }
    }

    @Test fun everyTruncationHeaderRecipientTailAndOverflowRefusesWithoutConversion(): Unit = Profile03ExecutionFixture().use { f ->
        for (length in 0 until f.intentV2Bytes.size) denied { ReviewedIntent03V2.decode(f.intentV2Bytes.copyOf(length)) }
        for (at in 0 until 8) denied {
            ReviewedIntent03V2.decode(f.intentV2Bytes.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() })
        }
        for (raw in listOf(f.intentV2Bytes + byteArrayOf(0), f.intentV2Bytes + ByteArray(32),
            f.intentV2Bytes.copyOf().apply { this[520] = 0 }, f.intentV2Bytes.copyOf().apply { this[524] = 1 },
            f.intentV2Bytes.copyOf().apply { this[lastIndex - 33] = 1 },
            f.intentV2Bytes.copyOf().apply { this[lastIndex] = 0 }, f.intentV2Bytes.copyOf().apply { this[lastIndex] = 7 }))
            denied { ReviewedIntent03V2.decode(raw) }
    }

    @Test fun snapshotsDoNotExposeMutableWireOrPeer(): Unit = Profile03ExecutionFixture().use { f ->
        val original = f.intentV2Bytes.copyOf(); val raw = original.copyOf()
        val intent = ReviewedIntent03V2.decode(raw)
        raw.fill(0); intent.bytes().fill(0); intent.peer().fill(0); intent.readerKeyId.fill(0)
        assertArrayEquals(original, intent.bytes()); verify(f, intent)
        assertEquals("ReviewedIntent03V2(public-evidence-only)", intent.toString())
    }

    @Test fun byteIdenticalIndependentProducerVectorsVerifyExactExtremaAndDistinctDomain() {
        val vector = javaClass.classLoader!!.getResourceAsStream("reviewed-intent03-v2.json")!!.use { JSONObject(it.bufferedReader().readText()) }
        val cases = vector.getJSONArray("cases")
        val lengths = mutableListOf<Int>()
        for (index in 0 until cases.length()) {
            val v = cases.getJSONObject(index)
            fun raw(name: String) = Profile03ExecutionFixture.unhex(v.getString(name))
            val intent = ReviewedIntent03V2.decode(raw("intent_hex")); lengths.add(intent.bytes().size)
            assertArrayEquals(raw("intent_sha256"), Profile03ExecutionFixture.sha(intent.bytes()))
            assertArrayEquals(raw("transcript_sha256"), Profile03ExecutionFixture.sha(intent.transcript()))
            assertTrue(ConversationContentCrypto.verifyRaw(raw("signature_hex"), raw("signer_point_hex"), intent.transcript()))
            assertFalse(ConversationContentCrypto.verifyRaw(raw("signature_hex"), raw("signer_point_hex"),
                ReviewedIntent03.framed("zrotext/conversation/reviewed-send03/v1", intent.bytes())))
            val fields = v.getJSONObject("fields")
            assertEquals(fields.getLong("bindingGeneration"), intent.bindingGeneration)
            assertEquals(fields.getInt("smsCeiling"), intent.segmentCeiling)
            assertFalse(fields.has("bodyDigest"))
        }
        assertEquals(listOf(592, 803, 592), lengths)
    }
    private fun denied(block: () -> Unit) { assertTrue(runCatching(block).isFailure) }
}
