// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.math.BigInteger
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Genuine software TEST signatures/ciphertext. This does not install an interval,
 * create hardware custody or prove a first-receipt/journal/current-server permission. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class CaptureIntent03Test {
    private class Fixture {
        val f = Profile03InboundFixture()
        val proof = Profile03InboundSealer(Profile03InboundFixture.softwareWrap).seal("synthetic".toCharArray(),
            f.authority, f.request(), f.observed, 1, f.deadline, { f.now }, {})
        val envelope = f.signed(proof)
        val ids = CaptureIntent03.Identities(uuid(f.account), uuid(f.event), UUID(0, 10), UUID(0, 11),
            UUID(0, 12), uuid(f.device), uuid(f.line), UUID(0, 13), UUID(0, 14), UUID(0, 15),
            UUID(0, 16), UUID(0, 17), UUID(0, 0))
        val times = CaptureIntent03.Times(1, 1, f.authority.version, 1, 1, 1, 1, f.observed,
            f.observed + 5, f.now, f.deadline, 1_000, 1_002, f.observed - 10)
        val commitments = CaptureIntent03.Commitments(Profile03InboundFixture.id(f.reader),
            Profile03InboundFixture.id(f.archive), Profile03InboundFixture.id(f.phone, true),
            Profile03InboundFixture.sha("ZTSE/root-pin/v2\u0000".toByteArray() + f.pin), f.authority.digest,
            digest(6), digest(7), digest(8), digest(9), digest(10), digest(11), digest(12), digest(13),
            digest(14), digest(15), digest(16), Profile03InboundFixture.sha(envelope), proof.sha256())
        fun intent() = CaptureIntent03.encode(ids, times, commitments, "+12", f.request().readers())
        companion object {
            private fun uuid(b: ByteArray): UUID = ByteBuffer.wrap(b).let { UUID(it.long, it.long) }
            private fun digest(n: Int) = ByteArray(32) { n.toByte() }
        }
    }
    @Test fun twoDistinctRealRole04SignaturesBindTheExactUnsignedAndFinalCiphertext() {
        val f = Fixture(); val intent = f.intent()
        assertEquals(942, intent.bytes().size)
        assertArrayEquals(f.proof.bytes(), intent.requireEnvelope(f.envelope, f.f.authority, f.f.request(), f.f.now).bytes())
        val signature = Profile03ExecutionFixture.rawSign(f.f.phone, intent.transcript())
        intent.requireSignature(signature, Profile03InboundFixture.point(f.f.phone))
        val n = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        val high = n.subtract(BigInteger(1, signature.copyOfRange(32, 64))).toByteArray().takeLast(32).toByteArray()
        val highS = signature.copyOf().apply { fill(0, 32, 64); high.copyInto(this, 64 - high.size) }
        denied { intent.requireSignature(highS, Profile03InboundFixture.point(f.f.phone)) }
        denied { intent.requireSignature(f.envelope.takeLast(64).toByteArray(), Profile03InboundFixture.point(f.f.phone)) }
        denied { intent.requireSignature(signature, Profile03InboundFixture.point(f.f.browser)) }
        denied { intent.requireEnvelope(f.envelope.copyOf().apply { this[200] = (this[200].toInt() xor 1).toByte() },
            f.f.authority, f.f.request(), f.f.now) }
    }
    @Test fun exactMaximumGrammarAndOwnedCopiesDoNotBecomePermission() {
        val f = Fixture(); val readers = listOf(Draft03ManifestAuthority.Reader(2, f.commitments.archive())) +
            (1..6).map { Draft03ManifestAuthority.Reader(3, ByteArray(32) { _ -> it.toByte() }) }
        val max = CaptureIntent03.encode(f.ids, f.times, f.commitments, "+" + "1".repeat(15), readers)
        assertEquals(1153, max.bytes().size)
        val original = max.bytes(); max.bytes().fill(0); max.commitments.reader().fill(0)
        max.recipients().first().keyId.fill(0)
        assertArrayEquals(original, max.bytes())
        assertArrayEquals(f.commitments.reader(), max.commitments.reader())
        assertEquals(f.ids, max.identities)
        assertEquals(f.times, max.times)
        assertEquals(7, max.recipients().size)
    }
    @Test fun nilIdentitiesNegativeCountersAndZeroCommitmentsRefuseAtEveryFixedOffset() {
        val valid = Fixture().intent().bytes()
        for (i in 0 until 12) denied {
            CaptureIntent03.decode(valid.copyOf().apply { fill(0, 8 + i * 16, 8 + (i + 1) * 16) })
        }
        for (i in 0 until 14) denied {
            CaptureIntent03.decode(valid.copyOf().apply { ByteBuffer.wrap(this).putLong(216 + i * 8, -1) })
        }
        for (i in (0 until 14).filter { it !in 11..12 }) denied {
            CaptureIntent03.decode(valid.copyOf().apply { ByteBuffer.wrap(this).putLong(216 + i * 8, 0) })
        }
        for (i in 0 until 18) denied {
            CaptureIntent03.decode(valid.copyOf().apply { fill(0, 328 + i * 32, 328 + (i + 1) * 32) })
        }
        denied { CaptureIntent03.decode(valid.copyOf().apply { copyInto(this, 40, 24, 40) }) }
        assertEquals(UUID(0, 0), CaptureIntent03.decode(valid).identities.physicalRefresh)
    }
    @Test fun upperDeadlineNeverUsesEarlierObservedLowerOrRestoresAgeAndElapsed() {
        val f = Fixture(); val intent = f.intent()
        intent.requireCurrent(f.f.now, 1_002)
        denied { intent.requireCurrent(f.times.permissionComparedMs - 1, 1_002) }
        denied { intent.requireCurrent(f.times.permissionExpiresMs, 1_002) }
        denied { intent.requireCurrent(f.f.now, 1_001) }
        denied { intent.requireCurrent(f.f.now, 61_001) }
        val raw = intent.bytes()
        for ((index, value) in listOf(8 to f.times.observedMs - 1, 8 to f.times.observedMs + 2_001,
            9 to f.times.observedMs - 1, 10 to f.times.permissionComparedMs + 30_001,
            12 to f.times.observedElapsedMs - 1, 13 to f.times.observedMs + 1)) {
            denied { CaptureIntent03.decode(raw.copyOf().apply { ByteBuffer.wrap(this).putLong(216 + index * 8, value) }) }
        }
    }
    @Test fun elapsedZeroIsAllowedButUnsupportedEpochOrVaultNeverBecomesValidRuntimeScope() {
        val f = Fixture()
        val zero = CaptureIntent03.encode(f.ids, f.times.copy(observedElapsedMs = 0, preparedElapsedMs = 0),
            f.commitments, "+12", f.f.request().readers())
        assertEquals(0L, zero.times.observedElapsedMs)
        denied { CaptureIntent03.encode(f.ids, f.times.copy(selectionEpoch = 7), f.commitments, "+12", f.f.request().readers()) }
        denied { CaptureIntent03.encode(f.ids, f.times.copy(vaultGeneration = 2), f.commitments, "+12", f.f.request().readers()) }
    }
    @Test fun oldHeaderTrailingBytesAndWrongInboundRecipientSetNeverDecodeAsCapture() {
        val f = Fixture(); val raw = f.intent().bytes()
        for (at in 0 until 8) denied {
            CaptureIntent03.decode(raw.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() })
        }
        denied { CaptureIntent03.decode(raw + byteArrayOf(0)) }
        denied { CaptureIntent03.decode(raw.copyOfRange(0, raw.size - 1)) }
        denied { CaptureIntent03.encode(f.ids, f.times, f.commitments, "+12", listOf(Draft03ManifestAuthority.Reader(1, f.commitments.reader()))) }
        denied { CaptureIntent03.encode(f.ids, f.times, f.commitments, "+12", listOf(Draft03ManifestAuthority.Reader(3, f.commitments.archive()))) }
        denied { CaptureIntent03.encode(f.ids, f.times, f.commitments, "+12", listOf(Draft03ManifestAuthority.Reader(2, ByteArray(32) { 1 }))) }
    }
    private fun denied(run: () -> Unit) { assertTrue(runCatching(run).isFailure) }
}
