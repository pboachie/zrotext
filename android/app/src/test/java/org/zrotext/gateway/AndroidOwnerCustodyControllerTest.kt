// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class AndroidOwnerCustodyControllerTest {
    private val fixture = AndroidOwnerCustodyFixture
    private var elapsed = 100L
    private var authority: AndroidOwnerCustodyAuthority? = fixture.authority()
    private var failStorage = false
    private var stored: ByteArray? = null
    private val native = FakeNative()
    private val store = object : AndroidOwnerCustodyKitStore {
        override fun put(kit: AndroidOwnerCustodyKit, permitted: () -> Boolean) {
            check(permitted()); check(!failStorage); stored = kit.encode(); check(permitted())
        }
    }
    private fun controller() = AndroidOwnerCustodyController(native, store, { elapsed }, { authority })
    private fun recover(controller: AndroidOwnerCustodyController) = controller.recover(fixture.kit.backup(), fixture.kit.card(), fixture.token, fixture.kit.identity, true)
    private inner class FakeNative : AndroidOwnerCustodyNativePort {
        override var available = true
        var recoveryCalls = 0; var openCalls = 0; var signCalls = 0; var closeAllCalls = 0
        var failRecovery = false; var failCreate = false; var closed = false
        var signingEntered: CountDownLatch? = null; var signingContinue: CountDownLatch? = null
        var creatingEntered: CountDownLatch? = null; var creatingContinue: CountDownLatch? = null
        override fun create(account: ByteArray, origin: String): Array<ByteArray> {
            creatingEntered?.countDown(); creatingContinue?.await(5, TimeUnit.SECONDS)
            check(!failCreate)
            return arrayOf(fixture.kit.backup(), fixture.kit.card(), fixture.token, fixture.kit.identity.fingerprintBytes(), fixture.kit.pin)
        }
        override fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity): Boolean {
            recoveryCalls++; return !failRecovery && token.contentEquals(fixture.token) && kit.identity == expected
        }
        override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
            authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long { openCalls++; closed = false; return 1 }
        override fun review(handle: Long) = fixture.challenge()
        override fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> {
            signingEntered?.countDown(); signingContinue?.await(5, TimeUnit.SECONDS)
            check(!closed); signCalls++
            return arrayOf(ByteArray(64) { 1 }, ByteArray(64) { 2 })
        }
        override fun close(handle: Long) { closed = true }
        override fun closeAll() { closeAllCalls++; closed = true }
    }
    @Test fun creationAndExportNeverEstablishRecoveryOrEnrollment() {
        val controller = controller(); controller.create(fixture.account, fixture.origin)
        assertTrue(controller.snapshot().canReveal); assertFalse(controller.snapshot().recoveryVerified)
        controller.reveal(); controller.confirmTokenRecorded()
        controller.exportReadback(fixture.kit.backup())
        assertTrue(controller.snapshot().exported); assertFalse(controller.snapshot().recoveryVerified)
        assertEquals(0, native.recoveryCalls); assertNull(controller.snapshot().review)
    }
    @Test fun freshRecoveryWorksWithNoLocalKitOrCachedTokenAndPersistsOnlyEncryptedKit() {
        val controller = controller(); assertNull(stored)
        val token = fixture.token; controller.recover(fixture.kit.backup(), fixture.kit.card(), token, fixture.kit.identity, true)
        assertTrue(controller.snapshot().recoveryVerified); assertTrue(token.all { it == 0.toByte() })
        assertTrue(AndroidOwnerCustodyKit.decode(checkNotNull(stored)).matches(fixture.kit))
        assertFalse(String(checkNotNull(stored), Charsets.US_ASCII).contains("ZTRK1-"))
        assertNull(controller.snapshot().review); assertNull(controller.snapshot().publicSignatures)
    }
    @Test fun wrongIndependentIdentityNeverCallsNativeAndAlwaysClearsToken() {
        for (expected in listOf(fixture.kit.identity.copy(account = UUID.randomUUID()),
            fixture.kit.identity.copy(origin = "https://other.invalid"), fixture.kit.identity.copy(fingerprint = "22".repeat(32)))) {
            val controller = controller(); val token = fixture.token
            assertThrows(IllegalArgumentException::class.java) { controller.recover(fixture.kit.backup(), fixture.kit.card(), token, expected, true) }
            assertTrue(token.all { it == 0.toByte() }); assertFalse(controller.snapshot().recoveryVerified)
        }
        assertEquals(0, native.recoveryCalls)
    }
    @Test fun wrongTokenFailedAEADOrStorageNeverEstablishReady() {
        val controller = controller(); native.failRecovery = true
        assertThrows(IllegalArgumentException::class.java) { recover(controller) }; assertFalse(controller.snapshot().recoveryVerified)
        native.failRecovery = false; failStorage = true
        assertThrows(IllegalStateException::class.java) { recover(controller) }; assertFalse(controller.snapshot().recoveryVerified)
    }
    @Test fun randomnessAndCreationStorageFailuresHaveNoRevealOrReady() {
        val controller = controller(); native.failCreate = true
        assertThrows(IllegalStateException::class.java) { controller.create(fixture.account, fixture.origin) }
        assertFalse(controller.snapshot().canReveal); assertFalse(controller.snapshot().recoveryVerified)
        native.failCreate = false; failStorage = true
        assertThrows(IllegalStateException::class.java) { controller.create(fixture.account, fixture.origin) }
        assertFalse(controller.snapshot().canReveal); assertFalse(controller.snapshot().recoveryVerified)
    }
    @Test fun retentionDeclarationIsSeparateAndRequired() {
        val controller = controller(); val token = fixture.token
        assertThrows(IllegalArgumentException::class.java) { controller.recover(fixture.kit.backup(), fixture.kit.card(), token, fixture.kit.identity, false) }
        assertTrue(token.all { it == 0.toByte() }); assertEquals(0, native.recoveryCalls)
    }
    @Test fun rejectedRecoveryAndRejectedConsentRevokePreviouslyReviewedAuthority() {
        val controller = controller(); recover(controller); controller.review(fixture.challenge(), fixture.kit.identity)
        assertThrows(IllegalArgumentException::class.java) { controller.sign(fixture.token, false) }
        assertNull(controller.snapshot().review); assertFalse(controller.snapshot().recoveryVerified)
        recover(controller)
        val expected = fixture.kit.identity.copy(fingerprint = "22".repeat(32))
        assertThrows(IllegalArgumentException::class.java) { controller.recover(fixture.kit.backup(), fixture.kit.card(), fixture.token, expected, true) }
        assertFalse(controller.snapshot().recoveryVerified)
    }
    @Test fun cancelledOrAmbiguousExportCannotBecomeRecoveryReady() {
        val controller = controller(); controller.create(fixture.account, fixture.origin)
        controller.reveal(); controller.confirmTokenRecorded()
        controller.exportReadback(fixture.kit.backup()); controller.exportUnconfirmed()
        assertFalse(controller.snapshot().exported); assertFalse(controller.snapshot().recoveryVerified)
        assertThrows(IllegalArgumentException::class.java) { controller.exportReadback(ByteArray(1)) }
    }
    @Test fun absentNativeLibraryProvidesNoFakeReadyOrCreate() {
        native.available = false; val controller = controller()
        assertFalse(controller.snapshot().available)
        assertThrows(IllegalStateException::class.java) { controller.create(fixture.account, fixture.origin) }
        assertFalse(controller.snapshot().recoveryVerified); assertNull(stored)
    }
    @Test fun deliberateRevealIsOneUseBoundedAndCancelledOnLifecycleLoss() {
        val controller = controller(); controller.create(fixture.account, fixture.origin)
        assertEquals(String(fixture.token, Charsets.US_ASCII), controller.reveal())
        assertThrows(IllegalStateException::class.java) { controller.reveal() }
        controller.create(fixture.account, fixture.origin); elapsed += 120000; controller.expireReveal()
        assertFalse(controller.snapshot().canReveal)
        controller.create(fixture.account, fixture.origin); controller.cancel()
        assertFalse(controller.snapshot().canReveal); assertFalse(controller.snapshot().recoveryVerified)
    }
    @Test fun importedChallengeCannotCreateCurrentOwnerAuthority() {
        val controller = controller(); recover(controller); authority = null
        assertThrows(IllegalStateException::class.java) { controller.review(fixture.challenge(), fixture.kit.identity) }
        assertEquals(0, native.openCalls); assertNull(controller.snapshot().review)
    }
    @Test fun exportRequiresExplicitRecordedRevealAndNeverInferredFromCancelOrTimeout() {
        val controller = controller(); controller.create(fixture.account, fixture.origin)
        assertThrows(IllegalStateException::class.java) { controller.encryptedBackup() }
        assertThrows(IllegalStateException::class.java) { controller.publicCard() }
        controller.reveal(); controller.cancel()
        assertThrows(IllegalStateException::class.java) { controller.confirmTokenRecorded() }
        assertFalse(controller.snapshot().canExportKit)
        controller.create(fixture.account, fixture.origin); controller.reveal(); elapsed += 120000
        assertThrows(IllegalArgumentException::class.java) { controller.confirmTokenRecorded() }
        assertFalse(controller.snapshot().canExportKit)
        controller.create(fixture.account, fixture.origin); controller.reveal(); controller.confirmTokenRecorded()
        controller.cancel() // SAF lifecycle loss revokes signing, while explicit recorded retention remains.
        assertArrayEquals(fixture.kit.backup(), controller.encryptedBackup())
        assertArrayEquals(fixture.kit.card(), controller.publicCard())
    }
    @Test fun independentlyRecoveredKitCanExportWithoutCreationTokenReveal() {
        val controller = controller(); recover(controller)
        assertTrue(controller.snapshot().canExportKit); assertFalse(controller.snapshot().canReveal)
        controller.cancel(); assertArrayEquals(fixture.kit.backup(), controller.encryptedBackup())
        assertEquals(UUID.fromString("44444444-4444-4444-8444-444444444444"), controller.snapshot().backupId)
        val receipt = String(controller.publicRootReceipt(), Charsets.UTF_8)
        assertTrue(receipt.contains("Encrypted backup UUID: 44444444-4444-4444-8444-444444444444"))
        assertFalse(receipt.contains("ZTRK1-")); assertTrue(receipt.contains("not server enrollment"))
    }
    @Test fun exactReviewRequiresFreshTokenSeparateApprovalAndConsumesOneAttempt() {
        val controller = controller(); recover(controller); controller.review(fixture.challenge(), fixture.kit.identity)
        assertEquals(fixture.session, controller.snapshot().review?.session)
        val token = fixture.token; controller.sign(token, true)
        assertEquals(1, native.signCalls); assertTrue(token.all { it == 0.toByte() })
        assertNotNull(controller.snapshot().publicSignatures); assertNull(controller.snapshot().review)
        assertThrows(IllegalStateException::class.java) { controller.sign(fixture.token, true) }
        assertEquals(1, native.signCalls)
    }
    @Test fun sessionSwitchBetweenReviewAndSignConsumesWithoutSigning() {
        val controller = controller(); recover(controller); controller.review(fixture.challenge(), fixture.kit.identity)
        authority = fixture.authority().copy(session = UUID.randomUUID()); val token = fixture.token
        assertThrows(IllegalArgumentException::class.java) { controller.sign(token, true) }
        assertEquals(0, native.signCalls); assertTrue(token.all { it == 0.toByte() }); assertNull(controller.snapshot().publicSignatures)
    }
    @Test fun cancellationDuringNativeSigningRevokesInFlightHandleAndPublishesNothing() {
        val controller = controller(); recover(controller); controller.review(fixture.challenge(), fixture.kit.identity)
        native.signingEntered = CountDownLatch(1); native.signingContinue = CountDownLatch(1)
        val failure = AtomicReference<Throwable>(); val token = fixture.token
        val thread = Thread { try { controller.sign(token, true) } catch (problem: Throwable) { failure.set(problem) } }; thread.start()
        assertTrue(native.signingEntered!!.await(5, TimeUnit.SECONDS)); controller.cancel(); native.signingContinue!!.countDown(); thread.join(5000)
        assertFalse(thread.isAlive); assertNotNull(failure.get()); assertEquals(0, native.signCalls)
        assertTrue(native.closeAllCalls > 0); assertTrue(token.all { it == 0.toByte() }); assertNull(controller.snapshot().publicSignatures)
    }
    @Test fun cancellationDuringCreateRejectsDelayedSecretAndReadyPublication() {
        val controller = controller(); native.creatingEntered = CountDownLatch(1); native.creatingContinue = CountDownLatch(1)
        val thread = Thread { runCatching { controller.create(fixture.account, fixture.origin) } }; thread.start()
        assertTrue(native.creatingEntered!!.await(5, TimeUnit.SECONDS)); controller.cancel(); native.creatingContinue!!.countDown(); thread.join(5000)
        assertFalse(thread.isAlive); assertFalse(controller.snapshot().canReveal); assertFalse(controller.snapshot().recoveryVerified); assertNull(stored)
    }
}
