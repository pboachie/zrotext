// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ReviewedIntent03Test {
    private fun verify(f: Profile03ExecutionFixture, intent: ReviewedIntent03 = f.intent,
        signature: ByteArray = f.intentSignature, admitted: Long = f.admittedAt, now: Long = f.now,
        epoch: Long = 3, origin: ByteArray = Profile03ExecutionFixture.unhex(f.session.originHash)) =
        intent.verifyReceipt(signature, f.authority, f.election.requireCurrent(f.authority, f.currentSelection, now),
            admitted, now, epoch, origin, 1, 200_000)

    @Test fun authenticIntentBindsTheEnvelopeReadersBodyAndMandatoryCeiling() = Profile03ExecutionFixture().use { f ->
        val request = verify(f)
        val proof = Draft03OutboundEnvelope.verify(f.envelope, f.authority, request) { f.now }
        assertArrayEquals(f.intent.envelopeSha256, proof.envelopeDigest)
        assertArrayEquals(f.intent.unsignedSha256, proof.unsignedDigest)
        f.intent.requireGrant(f.grant)
        assertEquals(1, f.intent.segmentCeiling)
        val key = f.key.copyOf()
        val clear = Draft03Body.open(proof, f.authority, request, f.now, key)
        try { assertArrayEquals(f.body, String(clear).toByteArray(Charsets.UTF_8)) }
        finally { clear.fill('\u0000') }
        assertTrue(key.all { it == 0.toByte() })
    }
    @Test fun delayedDeliveryUsesOriginalAcceptanceWithoutRenewingReviewOrMessageDeadline() = Profile03ExecutionFixture().use { f ->
        assertTrue(f.now < f.intent.reviewExpiresMs)
        verify(f, now = f.intent.reviewExpiresMs + 1)
        assertThrows(IllegalArgumentException::class.java) { verify(f, admitted = f.intent.reviewExpiresMs) }
        assertThrows(IllegalArgumentException::class.java) { verify(f, admitted = f.intent.reviewIssuedMs - 1) }
        assertThrows(IllegalArgumentException::class.java) { verify(f, now = f.intent.expiresMs) }
        Unit
    }
    @Test fun everySignedIdentityIntegerAndCommitmentIsCoveredByTheSignature() = Profile03ExecutionFixture().use { f ->
        for (at in (8 until 136 step 16) + (136 until 200 step 8) + (200 until 552 step 32)) {
            val changed = f.intentBytes.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) { verify(f, ReviewedIntent03.decode(changed)) }
        }
    }
    @Test fun correctlyResignedWrongSelectionEpochOriginOwnerDigestAndDeadlinesStillRefuse() = Profile03ExecutionFixture().use { f ->
        val edits: List<(ByteArray) -> Unit> = listOf(
            { ByteBuffer.wrap(it, 160, 8).putLong(4) },
            { it[392] = (it[392].toInt() xor 1).toByte() },
            { it[360] = (it[360].toInt() xor 1).toByte() },
            { ByteBuffer.wrap(it, 176, 8).putLong(100_010) },
            { ByteBuffer.wrap(it, 184, 8).putLong(100_030) },
            { ByteBuffer.wrap(it, 192, 8).putLong(130_011) },
        )
        for (edit in edits) {
            val bytes = f.intentBytes.copyOf().apply(edit)
            assertThrows(IllegalArgumentException::class.java) { verify(f, ReviewedIntent03.decode(bytes), f.signIntent(bytes)) }
        }
        assertThrows(IllegalArgumentException::class.java) { verify(f, epoch = 4) }
        assertThrows(IllegalArgumentException::class.java) { verify(f, origin = ByteArray(32) { 6 }) }
        Unit
    }
    @Test fun malformedProfileReservedByteWidthsUnsignedOverflowAndRecipientOrderRefuse() = Profile03ExecutionFixture().use { f ->
        for (bytes in listOf(f.intentBytes.copyOf(623), f.intentBytes + byteArrayOf(0),
            f.intentBytes.copyOf().apply { this[4] = 2 }, f.intentBytes.copyOf().apply { this[5] = 2 },
            f.intentBytes.copyOf().apply { this[7] = 1 }, f.intentBytes.copyOf().apply { fill(0, 8, 24) },
            f.intentBytes.copyOf().apply { ByteBuffer.wrap(this, 136, 8).putLong(Long.MIN_VALUE) },
            f.intentBytes.copyOf().apply { this[lastIndex - 33] = 1 },
            f.intentBytes.copyOf().apply { this[lastIndex] = 0 },
            f.intentBytes.copyOf().apply { this[lastIndex] = 7 })) {
            assertThrows(IllegalArgumentException::class.java) { ReviewedIntent03.decode(bytes) }
        }
    }
    @Test fun changedCeilingNeverFitsTheOriginalGrantEvenWithAValidNewIntentSignature() = Profile03ExecutionFixture().use { f ->
        val bytes = f.intentBytes.copyOf().apply { this[lastIndex] = 6 }
        val changed = ReviewedIntent03.decode(bytes)
        verify(f, changed, f.signIntent(bytes))
        assertThrows(IllegalArgumentException::class.java) { changed.requireGrant(f.grant) }
        Unit
    }
    @Test fun snapshotsOwnAllInputAndOutputBytesAndNeverRenderThePeer() = Profile03ExecutionFixture().use { f ->
        val input = f.intentBytes.copyOf()
        val intent = ReviewedIntent03.decode(input)
        input.fill(0)
        intent.bytes().fill(0); intent.peer().fill(0); intent.readerKeyId.fill(0)
        verify(f, intent)
        assertEquals("ReviewedIntent03(public-evidence-only)", intent.toString())
        assertArrayEquals(f.intentBytes, intent.bytes())
    }
}
