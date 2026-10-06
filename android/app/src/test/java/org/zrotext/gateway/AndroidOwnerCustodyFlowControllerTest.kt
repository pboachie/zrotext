// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Synthetic ciphertext/native port exercises lifecycle and framing, not cryptography. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AndroidOwnerCustodyFlowControllerTest {
    private val f = AndroidOwnerCustodyFixture
    private var elapsed = 100L
    private var live: AndroidOwnerCustodyAuthority? = f.authority()
    private var after: AndroidOwnerCustodyAuthority? = live
    private var postCheck: () -> Unit = {}
    private var persisted = 0
    private val point = byteArrayOf(4) + ByteArray(64) { 8 }
    private val archiveId = AndroidOwnerCustodyKit.hash("ZTSE/key/v1\u0000".toByteArray() + byteArrayOf(0, 16) + point)
    private val archiveIdentity = AndroidOwnerCustodyArchiveIdentity(f.kit.identity, AndroidOwnerCustodyKit.hex(archiveId), AndroidOwnerCustodyKit.hex(point))
    private fun archive(): AndroidOwnerCustodyArchiveKit {
        val origin = f.origin.toByteArray()
        val bytes = ByteBuffer.allocate(333 + origin.size).put(byteArrayOf(90, 84, 65, 66, 1, 1))
            .put(ByteArray(16) { 9 }).put(f.uuid(f.account)).putLong(1).put(f.kit.identity.fingerprintBytes())
            .put(archiveId).put(point).putShort(origin.size.toShort()).put(origin).array()
        ByteBuffer.wrap(bytes, 281 + origin.size, 4).putInt(48)
        return AndroidOwnerCustodyArchiveKit(bytes, archiveIdentity)
    }
    private val native = object : AndroidOwnerCustodyNativePort {
        override val available = true
        var opened = 0; var signed = 0; var recoveredArchive = 0; var closed = 0
        var scope = byteArrayOf(); var proposal = byteArrayOf(); var kind = 0
        var createdRecovery: ByteArray? = null
        var createdPublic: ByteArray? = null
        var duringSign: () -> Unit = {}
        override fun create(account: ByteArray, origin: String): Array<ByteArray> = error("Unused")
        override fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity) = true
        override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long = error("Unused")
        override fun review(handle: Long): ByteArray = error("Unused")
        override fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> = error("Unused")
        override fun close(handle: Long) { closed++ }
        override fun closeAll() { closed++ }
        override fun openTyped(kind: Int, proposal: ByteArray, expectedJson: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long {
            this.kind = kind; this.proposal = proposal.copyOf(); scope = expectedJson.copyOf(); opened++; return opened.toLong()
        }
        override fun reviewTyped(handle: Long) = arrayOf(proposal.copyOf(), scope.copyOf())
        override fun signTyped(handle: Long, token: ByteArray, archiveBackup: ByteArray, archiveRecovery: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> {
            signed++; duringSign()
            return if (kind == 2) {
                val kit = archive(); val private = ByteArray(32) { 6 }; createdRecovery = private
                arrayOf(kit.backup(), kit.receipt(), private, archiveId.copyOf(), point.copyOf())
            } else arrayOf(ByteArray(64) { 5 }.also { createdPublic = it })
        }
        override fun archiveRecoveryCheck(backup: ByteArray, recovery: ByteArray, expected: AndroidOwnerCustodyIdentity, archiveId: ByteArray, archivePoint: ByteArray): Boolean {
            recoveredArchive++; return recovery.contentEquals(ByteArray(32) { 6 }) && archiveId.contentEquals(this@AndroidOwnerCustodyFlowControllerTest.archiveId) && archivePoint.contentEquals(point)
        }
    }
    private val store = object : AndroidOwnerCustodyKitStore {
        override fun put(kit: AndroidOwnerCustodyKit, permitted: () -> Boolean) { check(permitted()) }
        override fun putArchive(kit: AndroidOwnerCustodyArchiveKit, permitted: () -> Boolean) { check(permitted()); persisted++ }
    }
    private fun controller() = AndroidOwnerCustodyController(native, store, { elapsed }, { live }, {
        postCheck(); after
    })
    private fun restore(c: AndroidOwnerCustodyController) = c.recover(f.kit.backup(), f.kit.card(), f.token, f.kit.identity, true)
    private fun archiveExpected() = createAndroidOwnerArchiveContext(f.kit.pin, f.kit.identity, f.authority())
    private fun reviewArchive(c: AndroidOwnerCustodyController) { restore(c); c.reviewTyped(AndroidOwnerCustodyFlowKind.ARCHIVE, byteArrayOf(), archiveExpected(), f.kit.identity) }
    @Test fun archiveCreationUsesSeparatePrivateSinkAndIsNeverRecoveryReady() {
        val c = controller(); reviewArchive(c); val root = f.token
        var privateCopy: ByteArray? = null
        c.signTyped(root, byteArrayOf(), true) { kit, secret, permitted ->
            assertTrue(permitted()); assertEquals(archiveIdentity, kit.identity); privateCopy = secret.copyOf(); true
        }
        assertEquals(1, native.signed); assertEquals(1, persisted)
        assertArrayEquals(ByteArray(32) { 6 }, privateCopy)
        assertTrue(root.all { it == 0.toByte() }); assertTrue(checkNotNull(native.createdRecovery).all { it == 0.toByte() })
        assertTrue(c.snapshot().archiveCanExport); assertFalse(c.snapshot().archiveRecoveryVerified)
        assertNull(c.snapshot().publicArtifact)
    }
    @Test fun absentSeparateDestinationNeverCallsNativeAndClearsFreshToken() {
        val c = controller(); reviewArchive(c); val root = f.token
        assertThrows(IllegalArgumentException::class.java) { c.signTyped(root, byteArrayOf(), true) }
        assertEquals(0, native.signed); assertTrue(root.all { it == 0.toByte() }); assertNull(c.snapshot().flowReview)
    }
    @Test fun failedPrivateDestinationAndCancellationCannotPublishOrPersistArchiveReady() {
        for (cancel in listOf(false, true)) {
            val c = controller(); reviewArchive(c)
            assertThrows(Exception::class.java) { c.signTyped(f.token, byteArrayOf(), true) { _, _, permitted ->
                if (cancel) { c.cancel(); assertFalse(permitted()); true } else false
            } }
            assertTrue(checkNotNull(native.createdRecovery).all { it == 0.toByte() })
            assertFalse(c.snapshot().archiveRecoveryVerified); assertFalse(c.snapshot().archiveCanExport)
        }
        assertEquals(0, persisted)
    }
    @Test fun changedPostSignSessionClearsBothSecretsAndSuppressesPrivateExport() {
        val c = controller(); reviewArchive(c); after = f.authority().copy(session = UUID.randomUUID())
        val root = f.token; var exports = 0
        postCheck = { assertTrue(root.all { it == 0.toByte() }) }
        assertThrows(IllegalArgumentException::class.java) { c.signTyped(root, byteArrayOf(), true) { _, _, _ -> exports++; true } }
        assertEquals(0, exports); assertEquals(0, persisted); assertNull(c.snapshot().archiveIdentity)
        assertTrue(checkNotNull(native.createdRecovery).all { it == 0.toByte() })
    }
    @Test fun managedDeadlineOverflowStillClearsNewArchiveSecret() {
        val c = controller(); reviewArchive(c); native.duringSign = { elapsed = Long.MAX_VALUE }
        assertThrows(ArithmeticException::class.java) { c.signTyped(f.token, byteArrayOf(), true) { _, _, _ -> true } }
        assertTrue(checkNotNull(native.createdRecovery).all { it == 0.toByte() }); assertEquals(0, persisted)
    }
    @Test fun freshArchiveRecoveryWorksWithoutCachedArchiveOrRecoveryAndRequiresIndependentIdentity() {
        val c = controller(); restore(c); val recovery = ByteArray(32) { 6 }
        c.recoverArchive(archive().backup(), recovery, archiveIdentity, true)
        assertEquals(1, native.recoveredArchive); assertTrue(recovery.all { it == 0.toByte() }); assertTrue(c.snapshot().archiveRecoveryVerified)
        c.cancel(); assertFalse(c.snapshot().archiveRecoveryVerified)
        assertArrayEquals(archive().backup(), c.encryptedArchive())
    }
    @Test fun archiveRecoveryWrongRetentionOrRootNeverMakesReadyAndAlwaysClearsMaterial() {
        val c = controller(); restore(c)
        val secret = ByteArray(32) { 6 }
        assertThrows(IllegalArgumentException::class.java) { c.recoverArchive(archive().backup(), secret, archiveIdentity, false) }
        assertTrue(secret.all { it == 0.toByte() }); assertEquals(0, native.recoveredArchive)
        assertFalse(c.snapshot().archiveRecoveryVerified)
    }
    @Test fun changedAuthenticatedExpectedContextRevokesNativeReview() {
        val c = controller(); reviewArchive(c)
        val changed = AndroidOwnerCustodyFlowExpected.fromAuthenticatedComposition("{}".toByteArray())
        assertThrows(IllegalArgumentException::class.java) { c.requireCurrentTypedContext(changed) }
        assertNull(c.snapshot().flowReview); assertFalse(c.snapshot().recoveryVerified); assertTrue(native.closed > 0)
    }
    @Test fun typedMalformedFreshReviewConsumesPreviousApprovalHandle() {
        val c = controller(); reviewArchive(c)
        assertThrows(IllegalArgumentException::class.java) { c.reviewTyped(AndroidOwnerCustodyFlowKind.ARCHIVE, byteArrayOf(1), archiveExpected(), f.kit.identity) }
        assertNull(c.snapshot().flowReview); assertTrue(native.closed > 0); assertFalse(c.snapshot().recoveryVerified)
    }
    @Test fun archiveMaterialTypesAreIndependentAndPublicFramingCannotGrantRecovery() {
        assertThrows(IllegalArgumentException::class.java) { decodeAndroidOwnerArchiveRecovery(String(f.token)) }
        assertThrows(IllegalArgumentException::class.java) { decodeAndroidOwnerPublicProposal(java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 6 }), 20480) }
        assertThrows(IllegalArgumentException::class.java) { decodeAndroidOwnerPublicProposal(java.util.Base64.getEncoder().encodeToString(f.token), 20480) }
        val c = controller(); assertFalse(c.snapshot().archiveRecoveryVerified)
        assertEquals(archiveIdentity, AndroidOwnerCustodyArchiveKit(archive().backup(), archiveIdentity).identity)
    }
    @Test fun browserPrivateGrantRequiresFreshSelectedFileAEADAndClearsWrongOrCancelledMaterial() {
        val c = controller(); restore(c); c.recoverArchive(archive().backup(), ByteArray(32) { 6 }, archiveIdentity, true)
        c.cancel() // SAF pause closes review/readiness, but does not replace a fresh proof.
        val selected = c.approvedBrowserArchive(f.kit.identity); val correct = ByteArray(32) { 6 }
        assertTrue(c.verifyBrowserArchiveRecovery(selected, correct)); assertTrue(correct.all { it == 0.toByte() })
        assertFalse(c.snapshot().archiveRecoveryVerified) // Browser grant never invents native ceremony readiness.
        val wrong = ByteArray(32) { 7 }
        assertThrows(IllegalArgumentException::class.java) { c.verifyBrowserArchiveRecovery(selected, wrong) }
        assertTrue(wrong.all { it == 0.toByte() })
        assertThrows(IllegalArgumentException::class.java) { c.approvedBrowserArchive(f.kit.identity.copy(origin = "https://other.invalid")) }
    }
    @Test fun typedLineRequiresFreshPostContextEvenWhenOwnerSessionIsUnchanged() {
        val flow = AndroidOwnerCustodyFlowFixture
        val c = controller(); restore(c); c.reviewTyped(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), flow.expected(), f.kit.identity)
        val root = f.token
        assertThrows(IllegalArgumentException::class.java) { c.signTyped(root, byteArrayOf(), true) }
        assertEquals(0, native.signed); assertTrue(root.all { it == 0.toByte() }); assertTrue(native.closed > 0)
        assertNull(c.snapshot().flowReview); assertNull(c.snapshot().publicArtifact)
    }
    @Test fun typedLinePublishesOnlyAfterFreshExactContextAndClearsNativeOutput() {
        val flow = AndroidOwnerCustodyFlowFixture
        val c = controller(); restore(c); c.reviewTyped(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), flow.expected(), f.kit.identity)
        val root = f.token; var postChecks = 0
        c.signTyped(root, byteArrayOf(), true, postContextCheck = {
            postChecks++; assertTrue(root.all { it == 0.toByte() }); assertNull(c.snapshot().publicArtifact); flow.expected()
        })
        assertEquals(1, postChecks); assertArrayEquals(ByteArray(64) { 5 }, c.snapshot().publicArtifact)
        assertTrue(checkNotNull(native.createdPublic).all { it == 0.toByte() }); assertNull(c.snapshot().flowReview)
    }
    @Test fun withdrawnProposalOrChangedCheckpointDuringNativeSignSuppressesAndClearsOutput() {
        val flow = AndroidOwnerCustodyFlowFixture
        for (withdrawn in listOf(true, false)) {
            val c = controller(); restore(c); c.reviewTyped(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), flow.expected(), f.kit.identity)
            var changed = false; native.duringSign = { changed = true }; val root = f.token
            assertThrows(Exception::class.java) { c.signTyped(root, byteArrayOf(), true, postContextCheck = {
                assertTrue(changed); assertTrue(root.all { it == 0.toByte() }); assertEquals(f.session, checkNotNull(live).session)
                if (withdrawn) error("Synthetic proposal consumed during native operation")
                val expected = flow.scope(); expected.getJSONObject("scope").put("connection_epoch", 9)
                AndroidOwnerCustodyFlowExpected.fromAuthenticatedComposition(expected.toString().toByteArray())
            }) }
            assertNull(c.snapshot().publicArtifact); assertNull(c.snapshot().flowReview)
            assertTrue(checkNotNull(native.createdPublic).all { it == 0.toByte() }); assertTrue(native.closed > 0)
        }
    }
}
