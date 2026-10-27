// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03InboundEnvelopeTest {
    private fun seal(f: Profile03InboundFixture, integration: Boolean = false) = Profile03InboundSealer(Profile03InboundFixture.softwareWrap)
        .seal("synthetic inbound".toCharArray(), f.authority, f.request(integration), f.observed, 1, f.deadline, { f.now }, {})
    @Test fun exact03InboundUsesDistinctPhoneSignerAndExpectedArchiveReaders() {
        val f = Profile03InboundFixture(); val p = seal(f, true); val bytes = f.signed(p)
        val checked = Draft03InboundEnvelope.verify(bytes, f.authority, f.request(true), f.observed, 1, f.now, f.deadline)
        assertArrayEquals(p.bytes(), checked.bytes())
        assertArrayEquals(Profile03InboundFixture.point(f.phone), checked.signerPoint())
        assertFalse(checked.signerPoint().contentEquals(Profile03InboundFixture.point(f.browser)))
        assertEquals(2, bytes[5].toInt())
        assertTrue(runCatching { f.signed(p, f.browser) }.isFailure)
        assertTrue(runCatching { Draft03InboundEnvelope.verify(bytes, f.authority, f.request(), f.observed, 1, f.now, f.deadline) }.isFailure)
    }
    @Test fun validNewSignaturesCannotRewriteIndependentPeerSequenceTimeOrProfile() {
        val f = Profile03InboundFixture(); val p = seal(f)
        // Each mutation is re-signed by the real selected role04 key. Routing and capture
        // expectations remain independent; a valid public signature cannot override them.
        for (at in listOf(4, 5, 10, 26, 42, 58, 74, 82, 114, 146, 170, 178, 180)) {
            val changed = p.bytes().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            val sig = Profile03ExecutionFixture.rawSign(f.phone, ReviewedIntent03.framed("ZTSE/sign/v3", changed))
            assertTrue("offset $at", runCatching { Draft03InboundEnvelope.verify(changed + sig, f.authority, f.request(), f.observed, 1, f.now, f.deadline) }.isFailure)
        }
        val signed = f.signed(p)
        assertTrue(runCatching { Draft03InboundEnvelope.verify(signed, f.authority, f.request(targetPeer = "+13".toByteArray()), f.observed, 1, f.now, f.deadline) }.isFailure)
        assertTrue(runCatching { Draft03InboundEnvelope.verify(signed, f.authority, f.request(), f.observed, 2, f.now, f.deadline) }.isFailure)
        assertTrue(runCatching { Draft03InboundEnvelope.verify(signed, f.authority, f.request(), f.observed + 1, 1, f.now, f.deadline) }.isFailure)
    }
    @Test fun truncatedOversizedReorderedExtraAndNoncanonicalSignaturesRefuse() {
        val f = Profile03InboundFixture(); val p = seal(f, true); val signed = f.signed(p)
        for (bytes in listOf(signed.copyOf(425), signed + byteArrayOf(0), signed.copyOf(signed.size - 1), signed.copyOf(34_083)))
            assertTrue(runCatching { Draft03InboundEnvelope.verify(bytes, f.authority, f.request(true), f.observed, 1, f.now, f.deadline) }.isFailure)
        val unsigned = p.bytes(); val end = 10 + (ByteBuffer.wrap(unsigned, 8, 2).short.toInt() and 65535)
        val wraps = end + 16 + ByteBuffer.wrap(unsigned, end + 12, 4).int + 1
        val reordered = unsigned.copyOf().apply {
            unsigned.copyOfRange(wraps + 146, wraps + 292).copyInto(this, wraps)
            unsigned.copyOfRange(wraps, wraps + 146).copyInto(this, wraps + 146)
        }
        assertTrue(runCatching { Draft03InboundEnvelope.unsigned(reordered, f.authority, f.request(true), f.observed, 1, f.now, f.deadline) }.isFailure)
        val bad = signed.copyOf().apply { fill(0, size - 64, size) }
        assertTrue(runCatching { Draft03InboundEnvelope.verify(bad, f.authority, f.request(true), f.observed, 1, f.now, f.deadline) }.isFailure)
    }
    @Test fun onlyCurrentObservedRole04AndBothDirectionIntegrationKeysAreEligible() {
        for (f in listOf(Profile03InboundFixture(phoneState = 2), Profile03InboundFixture(phoneFrom = 100_015)))
            assertTrue(runCatching { seal(f) }.isFailure)
        for (f in listOf(Profile03InboundFixture(integrationScope = 4), Profile03InboundFixture(integrationScope = 8), Profile03InboundFixture(integrationState = 2)))
            assertTrue(runCatching { seal(f, true) }.isFailure)
        val f = Profile03InboundFixture(); val p = seal(f)
        assertTrue(runCatching { p.requirePublicCurrent(f.deadline) }.isFailure)
        assertTrue(runCatching { p.requirePublicCurrent(f.now - 1) }.isFailure)
        assertTrue(runCatching { f.authority.inboundContext(f.request(signer = f.browser), f.observed, f.now, f.deadline) }.isFailure)
        assertTrue(runCatching { f.authority.inboundContext(f.request(readers = listOf(
            Draft03ManifestAuthority.Reader(1, Profile03InboundFixture.id(f.reader)),
            Draft03ManifestAuthority.Reader(2, Profile03InboundFixture.id(f.archive)))), f.observed, f.now, f.deadline) }.isFailure)
        assertTrue(runCatching { f.authority.inboundContext(f.request(), f.observed, f.now, 900_001) }.isFailure)
    }
    @Test fun ownedPublicInputsCannotMutatePreparedCiphertextOrSelectedRouting() {
        val f = Profile03InboundFixture(); val p = seal(f); val bytes = p.bytes(); bytes.fill(0)
        val point = p.signerPoint(); point.fill(0)
        assertArrayEquals(Profile03InboundFixture.point(f.phone), p.signerPoint())
        val signed = f.signed(p)
        assertArrayEquals(p.bytes(), Draft03InboundEnvelope.verify(signed, f.authority, f.request(), f.observed, 1, f.now, f.deadline).bytes())
    }
}
