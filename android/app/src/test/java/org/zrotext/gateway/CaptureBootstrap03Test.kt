// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Actual software TEST signatures, never hardware custody/zero-history/current actor evidence. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class CaptureBootstrap03Test {
    private class Fixture {
        val enrolled = pair(); val root = pair(); val approval = pair(); val phone = pair(); val browser = pair(); val canary = pair()
        val known = listOf(root, approval, phone, browser).map(::point)
        val originalNonce = ByteArray(32) { 21 }; val attemptNonce = ByteArray(32) { 22 }
        val attempt = UUID(0, 10)
        fun association(key: KeyPair = canary) = CaptureBootstrap03.Association.encode(
            CaptureBootstrap03.Identities(UUID(0, 1), UUID(0, 2), UUID(0, 3), UUID(0, 4), UUID(0, 5),
                UUID(0, 6), UUID(0, 7), UUID(0, 8), UUID(0, 9)), CaptureBootstrap03.Generations(1, 3),
            CaptureBootstrap03.Commitments(sha(originalNonce), id(enrolled), id(key), sha(point(root)),
                digest(31), digest(32), digest(33)), point(key))
        fun core() = CaptureBootstrap03.Core.encode(association(), attempt, attemptNonce)
        fun bundle(core: CaptureBootstrap03.Core = core(), key: KeyPair = canary): ByteArray {
            val device = sign(enrolled, core.deviceTranscript())
            return core.bytes() + device + sign(key, core.canaryTranscript(device))
        }
    }
    @Test fun genuineDistinctSignaturesBindBothNonceCommitmentsAndTheSameAssociation() {
        val f = Fixture(); val a = f.association(); val c = f.core(); val b = CaptureBootstrap03.Bundle.decode(f.bundle(c))
        assertEquals(473, a.bytes().size); assertEquals(521, c.bytes().size); assertEquals(649, b.bytes().size)
        a.requireOriginalNonce(f.originalNonce)
        c.requireAttempt(f.attempt, f.attemptNonce, a)
        b.requireSignatures(point(f.enrolled), f.known)
        assertArrayEquals(a.bytes(), c.association.bytes())
        assertArrayEquals(c.bytes(), b.core.bytes())
        assertArrayEquals(sha(f.originalNonce), a.bytes().copyOfRange(184, 216))
        assertArrayEquals(sha(f.attemptNonce), c.bytes().copyOfRange(424, 456))
        assertFalse(a.bytes().copyOfRange(184, 216).contentEquals(f.originalNonce))
        denied { a.requireOriginalNonce(f.attemptNonce) }
        denied { c.requireAttempt(UUID(0, 11), f.attemptNonce, a) }
        denied { c.requireAttempt(f.attempt, f.originalNonce, a) }
    }
    @Test fun explicitNewAttemptRetainsOriginalAssociationAndCannotValidateAnOldProofAsNew() {
        val f = Fixture(); val original = CaptureBootstrap03.Bundle.decode(f.bundle())
        val nextNonce = ByteArray(32) { 23 }
        val next = CaptureBootstrap03.Core.encode(f.association(), UUID(0, 11), nextNonce)
        assertArrayEquals(original.core.association.bytes(), next.association.bytes())
        assertFalse(original.core.bytes().contentEquals(next.bytes()))
        denied { original.core.requireAttempt(next.attempt, nextNonce, next.association) }
        val forged = CaptureBootstrap03.Bundle.decode(next.bytes() + original.deviceSignature() + original.canarySignature())
        denied { forged.requireSignatures(point(f.enrolled), f.known) }
        CaptureBootstrap03.Bundle.decode(f.bundle(next)).requireSignatures(point(f.enrolled), f.known)
        // No closure/foreground/server receipt or usable counter is issued by either proof.
    }
    @Test fun validSignaturesFromKnownRootApprovalAndContentKeysCannotSubstituteForTheCanary() {
        val f = Fixture()
        for (known in listOf(f.root, f.approval, f.phone, f.browser)) {
            val core = CaptureBootstrap03.Core.encode(f.association(known), f.attempt, f.attemptNonce)
            val bundle = CaptureBootstrap03.Bundle.decode(f.bundle(core, known))
            denied { bundle.requireSignatures(point(f.enrolled), f.known) }
        }
        denied { f.association(f.enrolled) }
        denied { CaptureBootstrap03.Bundle.decode(f.bundle()).requireSignatures(point(f.approval), f.known) }
    }
    @Test fun bareAssociationTentativeDomainsAndSwappedSignatureRolesNeverVerify() {
        val f = Fixture(); val c = f.core(); val valid = CaptureBootstrap03.Bundle.decode(f.bundle(c))
        val tentative = sign(f.enrolled, ReviewedIntent03.framed("ZTSE/conversation/capture-bootstrap/device/v1", c.bytes()))
        val oldBare = sign(f.enrolled, ReviewedIntent03.framed("ZTSE/conversation/capture-bootstrap/device-attempt/v1", c.association.bytes()))
        for (wrong in listOf(tentative, oldBare, valid.canarySignature())) {
            denied { CaptureBootstrap03.Bundle.decode(c.bytes() + wrong + valid.canarySignature()).requireSignatures(point(f.enrolled), f.known) }
        }
        val wrongCanary = sign(f.canary, c.deviceTranscript())
        denied { CaptureBootstrap03.Bundle.decode(c.bytes() + valid.deviceSignature() + wrongCanary).requireSignatures(point(f.enrolled), f.known) }
        denied { CaptureBootstrap03.Bundle.decode(c.association.bytes() + valid.deviceSignature() + valid.canarySignature()) }
    }
    @Test fun allFixedIdentitiesGenerationsCommitmentsAndCurveEncodingRefuseInvalidValues() {
        val f = Fixture(); val c = f.core().bytes()
        for (i in 0 until 10) denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { fill(0, 8 + i * 16, 24 + i * 16) }) }
        for (i in 0 until 4) for (bad in listOf(0L, -1L)) denied {
            CaptureBootstrap03.Core.decode(c.copyOf().apply { ByteBuffer.wrap(this).putLong(168 + i * 8, bad) })
        }
        for (i in 0 until 8) denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { fill(0, 200 + i * 32, 232 + i * 32) }) }
        for (i in listOf(2, 3)) denied {
            CaptureBootstrap03.Core.decode(c.copyOf().apply { ByteBuffer.wrap(this).putLong(168 + i * 8, 2) })
        }
        denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { ByteBuffer.wrap(this).putLong(176, 1) }) }
        denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { fill(0, 456, 521) }) }
        denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { this[456] = 2 }) }
        denied { CaptureBootstrap03.Core.decode(c.copyOf().apply { this[264] = (this[264].toInt() xor 1).toByte() }) }
    }
    @Test fun zeroOrderHighSAndNoncanonicalLengthsCannotEnterBundleGrammar() {
        val raw = Fixture().bundle()
        val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        for (offset in listOf(521, 585)) {
            denied { CaptureBootstrap03.Bundle.decode(raw.copyOf().apply { fill(0, offset, offset + 32) }) }
            denied { CaptureBootstrap03.Bundle.decode(raw.copyOf().apply { fill(0, offset + 32, offset + 64) }) }
            denied { CaptureBootstrap03.Bundle.decode(raw.copyOf().apply { scalar(order).copyInto(this, offset) }) }
            val high = order.subtract(BigInteger(1, raw.copyOfRange(offset + 32, offset + 64)))
            denied { CaptureBootstrap03.Bundle.decode(raw.copyOf().apply { scalar(high).copyInto(this, offset + 32) }) }
        }
        for (length in 0 until 649) denied { CaptureBootstrap03.Bundle.decode(raw.copyOf(length)) }
        denied { CaptureBootstrap03.Bundle.decode(raw + byteArrayOf(0)) }
        for (at in 0 until 8) denied {
            CaptureBootstrap03.Bundle.decode(raw.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() })
        }
    }
    @Test fun decodedCandidatesAndEveryReturnedArrayOwnTheirBytes() {
        val f = Fixture(); val raw = f.bundle(); val saved = raw.copyOf(); val b = CaptureBootstrap03.Bundle.decode(raw)
        raw.fill(0); b.bytes().fill(0); b.deviceSignature().fill(0); b.canarySignature().fill(0)
        b.core.bytes().fill(0); b.core.attemptNonceCommitment().fill(0); b.core.association.bytes().fill(0)
        b.core.association.canaryPoint().fill(0); b.core.association.commitments.enrolledKey().fill(0)
        assertArrayEquals(saved, b.bytes())
        b.requireSignatures(point(f.enrolled), f.known)
        b.core.requireAttempt(f.attempt, f.attemptNonce, f.association())
    }
    @Test fun independentlyProducedVectorMatchesEveryByteAndBothStrictSignatureDomains() {
        val v = javaClass.classLoader!!.getResourceAsStream("sealed-capture-bootstrap03-01.json")!!.use {
            JSONObject(it.bufferedReader().readText())
        }
        fun bytes(name: String) = Profile03ExecutionFixture.unhex(v.getString(name))
        val b = CaptureBootstrap03.Bundle.decode(bytes("bundle649"))
        assertArrayEquals(bytes("core521"), b.core.bytes())
        assertArrayEquals(bytes("association473"), b.core.association.bytes())
        assertArrayEquals(bytes("association_sha256"), b.core.association.sha256())
        assertArrayEquals(bytes("core_sha256"), b.core.sha256())
        assertArrayEquals(bytes("bundle_sha256"), b.sha256())
        assertArrayEquals(bytes("device_transcript"), b.core.deviceTranscript())
        assertArrayEquals(bytes("canary_transcript"), b.core.canaryTranscript(b.deviceSignature()))
        b.core.association.requireOriginalNonce(bytes("bootstrap_nonce"))
        b.core.requireAttempt(UUID.fromString(v.getString("attempt_id")), bytes("attempt_nonce"), b.core.association)
        val known = listOf("root_point", "approval_point", "role04_point", "role05_point").map(::bytes)
        b.requireSignatures(bytes("enrolled_point"), known)
    }
    private fun denied(run: () -> Unit) { assertTrue(runCatching(run).isFailure) }
    companion object {
        private fun pair() = Profile03ExecutionFixture.pair()
        private fun point(key: KeyPair) = Profile03ExecutionFixture.point(key)
        private fun id(key: KeyPair) = CaptureBootstrap03.signingKeyId(point(key))
        private fun sign(key: KeyPair, transcript: ByteArray) = Profile03ExecutionFixture.rawSign(key, transcript)
        private fun sha(bytes: ByteArray) = Profile03ExecutionFixture.sha(bytes)
        private fun digest(n: Int) = ByteArray(32) { n.toByte() }
        private fun scalar(value: BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
    }
}
