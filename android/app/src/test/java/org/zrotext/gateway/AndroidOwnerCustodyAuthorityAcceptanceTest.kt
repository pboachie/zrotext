// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Managed authority/lifecycle acceptance only. Fake public framing proves no cryptography;
 * native time, replay and AEAD properties have independent Rust and Android JNI coverage.
 */
class AndroidOwnerCustodyAuthorityAcceptanceTest {
    private val fixture = AndroidOwnerCustodyFixture
    private var authority: AndroidOwnerCustodyAuthority? = fixture.authority()
    private var elapsed = 100L
    private var commits = 0
    private val native = ControlledNative()
    private val store = object : AndroidOwnerCustodyKitStore {
        override fun put(kit: AndroidOwnerCustodyKit, permitted: () -> Boolean) {
            check(permitted()); commits++; check(permitted())
        }
    }
    private fun controller() = AndroidOwnerCustodyController(native, store, { elapsed }, { authority })
    private fun recover(controller: AndroidOwnerCustodyController) = controller.recover(
        fixture.kit.backup(), fixture.kit.card(), fixture.token, fixture.kit.identity, true)
    private fun reviewed(): AndroidOwnerCustodyController = controller().also {
        recover(it); it.review(fixture.challenge(), fixture.kit.identity)
    }

    private inner class ControlledNative : AndroidOwnerCustodyNativePort {
        override val available = true
        var afterOpen: () -> Unit = {}
        var beforeSignReturn: () -> Unit = {}
        var recoveryEntered: CountDownLatch? = null
        var recoveryContinue: CountDownLatch? = null
        var signingCalls = 0
        var signingElapsed: Long? = null
        var closedHandles = 0
        var closedAll = 0
        override fun create(account: ByteArray, origin: String): Array<ByteArray> = error("Creation not used")
        override fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity): Boolean {
            recoveryEntered?.countDown()
            check(recoveryContinue?.await(5, TimeUnit.SECONDS) != false)
            return true
        }
        override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
            authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long = 7L.also { afterOpen() }
        override fun review(handle: Long) = fixture.challenge()
        override fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> {
            signingCalls++; signingElapsed = elapsed
            check(authority.utcMs + elapsed - authority.anchoredElapsedMs < 61000)
            beforeSignReturn()
            return arrayOf(ByteArray(64) { 1 }, ByteArray(64) { 2 })
        }
        override fun close(handle: Long) { closedHandles++ }
        override fun closeAll() { closedAll++ }
    }

    @Test fun ownerWithdrawalBeforeSigningConsumesReviewWithoutNativeSignature() {
        val controller = reviewed(); authority = null
        val token = fixture.token
        assertThrows(IllegalStateException::class.java) { controller.sign(token, true) }
        assertEquals(0, native.signingCalls)
        assertTrue(token.all { it == 0.toByte() })
        assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
        assertFalse(controller.snapshot().recoveryVerified); assertTrue(native.closedHandles > 0)
    }

    @Test fun withdrawalDuringOpeningClosesHandleAndNeverPublishesReview() {
        val controller = controller(); recover(controller)
        native.afterOpen = { authority = null }
        assertThrows(IllegalStateException::class.java) { controller.review(fixture.challenge(), fixture.kit.identity) }
        assertEquals(1, native.closedHandles)
        assertNull(controller.snapshot().review); assertFalse(controller.snapshot().recoveryVerified)
    }

    @Test fun withdrawalDuringNativeOutputSuppressesPublicSignaturePublication() {
        val controller = reviewed(); native.beforeSignReturn = { authority = null }
        val token = fixture.token
        assertThrows(IllegalStateException::class.java) { controller.sign(token, true) }
        assertEquals(1, native.signingCalls)
        assertTrue(token.all { it == 0.toByte() })
        assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
        assertFalse(controller.snapshot().recoveryVerified)
    }

    @Test fun changedOwnerUserCannotReuseSameAccountBrowserProposal() {
        val controller = controller(); recover(controller)
        authority = fixture.authority().copy(user = UUID.randomUUID())
        assertThrows(IllegalArgumentException::class.java) { controller.review(fixture.challenge(), fixture.kit.identity) }
        assertEquals(1, native.closedHandles)
        assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
    }

    @Test fun malformedFreshProposalRevokesPreviouslyReviewedApproval() {
        val controller = reviewed()
        assertNotNull(controller.snapshot().review)
        assertThrows(IllegalArgumentException::class.java) { controller.review(byteArrayOf(), fixture.kit.identity) }
        assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
        assertFalse(controller.snapshot().recoveryVerified)
        assertTrue(native.closedHandles > 0 || native.closedAll > 0)
        val token = fixture.token
        assertThrows(IllegalStateException::class.java) { controller.sign(token, true) }
        assertTrue(token.all { it == 0.toByte() }); assertEquals(0, native.signingCalls)
    }

    @Test fun elapsedRealtimeAfterSuspendIsForwardedFreshAndExpiryProducesNoOutput() {
        val controller = reviewed(); elapsed += 120000
        val token = fixture.token
        assertThrows(IllegalStateException::class.java) { controller.sign(token, true) }
        assertEquals(elapsed, native.signingElapsed)
        assertTrue(token.all { it == 0.toByte() })
        assertNull(controller.snapshot().publicSignatures); assertFalse(controller.snapshot().recoveryVerified)
    }

    @Test fun cancellationDuringRecoveryPreventsDelayedStoreAndReadyPublication() {
        val controller = controller()
        native.recoveryEntered = CountDownLatch(1); native.recoveryContinue = CountDownLatch(1)
        val failure = AtomicReference<Throwable>()
        val token = fixture.token
        val thread = Thread {
            try { controller.recover(fixture.kit.backup(), fixture.kit.card(), token, fixture.kit.identity, true) }
            catch (problem: Throwable) { failure.set(problem) }
        }
        try {
            thread.start(); assertTrue(native.recoveryEntered!!.await(5, TimeUnit.SECONDS))
            controller.cancel(); native.recoveryContinue!!.countDown(); thread.join(5000)
            assertFalse(thread.isAlive); assertNotNull(failure.get())
            assertEquals(0, commits); assertTrue(native.closedAll > 0)
            assertTrue(token.all { it == 0.toByte() }); assertFalse(controller.snapshot().recoveryVerified)
            assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
        } finally { native.recoveryContinue!!.countDown(); thread.join(5000); controller.close() }
    }
}
