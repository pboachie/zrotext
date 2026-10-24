// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Real JCA software TEST keys authenticate exact03 encryption. This does not exercise
 * production wolfSSL JNI, Keystore custody, a journal reservation or capture permission. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03InboundSealerTest {
    private fun seal(f: Profile03InboundFixture, text: CharArray, integration: Boolean = true,
        port: Profile03InboundWrapSealer = Profile03InboundFixture.softwareWrap,
        now: () -> Long = { f.now }, current: () -> Unit = {}) = Profile03InboundSealer(port)
        .seal(text, f.authority, f.request(integration), f.observed, 1, f.deadline, now, current)
    @Test fun archiveAndExactAdditionalReaderOpenIdenticalStrictTextWithDifferentFreshWraps() {
        val f = Profile03InboundFixture()
        val text = "synthetic\r\n e\u0301 \u00e9 \ud83d\ude42".toCharArray(); val expected = String(text).toByteArray(Charsets.UTF_8)
        val proof = seal(f, text); val bytes = f.signed(proof)
        assertArrayEquals(expected, f.open(bytes, f.archive, 2))
        assertArrayEquals(expected, f.open(bytes, f.integration, 3))
        assertArrayEquals("synthetic\r\n e\u0301 \u00e9 \ud83d\ude42".toCharArray(), text)
        val second = seal(f, text)
        assertFalse(proof.bytes().contentEquals(second.bytes()))
        assertTrue(runCatching { f.open(bytes, f.archive, 2, aadLabel = "ZTSE/wrap-aad/v2\u0000") }.isFailure)
        assertTrue(runCatching { f.open(bytes, f.archive, 2, infoLabel = "ZTSE/wrap/v2\u0000") }.isFailure)
        assertTrue(runCatching { f.open(bytes, f.reader, 1) }.isFailure)
    }
    @Test fun wrapAndBodyAuthenticationRejectTamperingBeyondPublicSignatureGrammar() {
        val f = Profile03InboundFixture(); val proof = seal(f, "synthetic".toCharArray())
        val bytes = proof.bytes(); val end = 10 + (ByteBuffer.wrap(bytes, 8, 2).short.toInt() and 65535)
        val wrap = end + 16 + ByteBuffer.wrap(bytes, end + 12, 4).int + 1
        for (at in listOf(end, end + 16, wrap + 98)) {
            val changed = bytes.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            // The real role04 key may sign a ciphertext with a corrupt tag. Public proof
            // verifies, but the selected recipient must still fail authenticated decryption.
            val signed = changed + Profile03ExecutionFixture.rawSign(f.phone, ReviewedIntent03.framed("ZTSE/sign/v3", changed))
            Draft03InboundEnvelope.verify(signed, f.authority, f.request(true), f.observed, 1, f.now, f.deadline)
            assertTrue("authenticated offset $at", runCatching { f.open(signed, f.archive, 2) }.isFailure)
        }
    }
    @Test fun sourceCharactersAreCapturedBeforeAnAdmissionWaitCanMutateTheCallerBuffer() {
        val f = Profile03InboundFixture(); val source = "synthetic original".toCharArray(); var first = true
        val proof = seal(f, source, integration = false, current = {
            if (first) { first = false; source.fill('x') }
        })
        assertArrayEquals("synthetic original".toByteArray(), f.open(f.signed(proof), f.archive, 2))
        assertTrue(source.all { it == 'x' })
    }
    @Test fun strictTextRefusesEmptyNulBomMalformedSurrogateAndOversizeBeforeWrapping() {
        val f = Profile03InboundFixture(); var calls = 0
        val port = Profile03InboundWrapSealer { _, _, _, _, _ -> calls++; error("must not wrap invalid text") }
        for (text in listOf(charArrayOf(), "bad\u0000text".toCharArray(), "\ufeffbad".toCharArray(), charArrayOf('\ud800'), CharArray(32_769) { 'a' }))
            assertTrue(runCatching { seal(f, text, port = port) }.isFailure)
        assertEquals(0, calls)
        val exact = seal(f, CharArray(32_768) { 'a' }, integration = false)
        assertEquals(32_768, f.open(f.signed(exact), f.archive, 2).size)
    }
    @Test fun withdrawalInsideBlockedWrapBurnsNoSignatureOrOutputAndClearsPassedKey() {
        val f = Profile03InboundFixture(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val alive = AtomicBoolean(true); val failure = AtomicReference<Throwable?>(); val output = AtomicReference<ByteArray?>()
        val retained = AtomicReference<ByteArray?>()
        val port = Profile03InboundWrapSealer { point, key, info, aad, current ->
            retained.set(key); entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
            Profile03InboundFixture.softwareWrap.seal(point, key, info, aad, current)
        }
        val worker = Thread {
            try { output.set(seal(f, "synthetic".toCharArray(), port = port, current = { check(alive.get()) }).bytes()) }
            catch (thrown: Throwable) { failure.set(thrown) }
        }
        try {
            worker.start(); assertTrue(entered.await(5, TimeUnit.SECONDS)); alive.set(false); release.countDown(); worker.join(5_000)
            assertFalse(worker.isAlive); assertNotNull(failure.get()); assertNull(output.get())
            assertTrue(checkNotNull(retained.get()).all { it == 0.toByte() })
        } finally { release.countDown(); worker.join(5_000) }
    }
    @Test fun postWrapClockRegressionDeadlineAndMalformedProviderOutputRefuseAndClearKeyCopies() {
        val f = Profile03InboundFixture()
        for (badNow in listOf(f.now - 1, f.deadline)) {
            var now = f.now; var retained: ByteArray? = null
            val port = Profile03InboundWrapSealer { point, key, info, aad, current ->
                retained = key
                Profile03InboundFixture.softwareWrap.seal(point, key, info, aad, current).also { now = badNow }
            }
            assertTrue(runCatching { seal(f, "synthetic".toCharArray(), port = port, now = { now }) }.isFailure)
            assertTrue(checkNotNull(retained).all { it == 0.toByte() })
        }
        for (bad in listOf(ByteArray(112), ByteArray(113))) {
            var retained: ByteArray? = null
            val port = Profile03InboundWrapSealer { _, key, _, _, _ -> retained = key; bad }
            assertTrue(runCatching { seal(f, "synthetic".toCharArray(), port = port) }.isFailure)
            assertTrue(checkNotNull(retained).all { it == 0.toByte() })
        }
    }
    @Test @Config(sdk = [28, 29, 30]) fun oldAndroidRefusesBeforeCallingAnySender() {
        val f = Profile03InboundFixture(); var called = false
        val port = Profile03InboundWrapSealer { _, _, _, _, _ -> called = true; error("unsupported API") }
        assertTrue(runCatching { seal(f, "synthetic".toCharArray(), port = port) }.isFailure)
        assertFalse(called)
    }
}
