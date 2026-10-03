// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.ContextWrapper
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SealedLineReviewControllerTest {
    private val line = UUID(0, 3).toString()
    private class Fixture {
        var current = true
        var sim: Int? = 7
        var point = ByteArray(65) { 1 }.also { it[0] = 4 }
        var installs = 0
        var closes = 0
        var duringInstall: () -> Unit = {}
        var installedGuard: (() -> Boolean)? = null
        val scope = ConversationSocketComposition.AuthenticatedIdentitySnapshot(
            EvidenceIdentity(UUID(0, 1).toString(), UUID(0, 2).toString(), "a".repeat(64))) {
            check(current)
        }
        val controller = SealedLineReviewController({ if (current) scope else null }, { sim },
            { point.copyOf() }, { _, guard -> installedGuard = guard; installs++; duringInstall(); AutoCloseable { closes++ } })
    }
    @Test fun prepareAndCancelNeverInstall() {
        val f = Fixture()
        assertNotNull(f.controller.prepare(line, "1"))
        f.controller.cancel()
        assertEquals(0, f.installs)
    }
    @Test fun exactConfirmIsSingleUseAndWithdrawalClosesOwner() {
        val f = Fixture(); val review = checkNotNull(f.controller.prepare(line, "1"))
        assertTrue(f.controller.confirm(review)); assertFalse(f.controller.confirm(review))
        assertEquals(1, f.installs)
        f.controller.cancel(); f.controller.close()
        assertEquals(1, f.closes)
    }
    @Test fun staleReviewCannotConfirmReplacement() {
        val f = Fixture(); val old = checkNotNull(f.controller.prepare(line, "1"))
        val fresh = checkNotNull(f.controller.prepare(line, "2"))
        assertFalse(f.controller.confirm(old)); assertTrue(f.controller.confirm(fresh))
    }
    @Test fun lostSessionChangedSimAndRotatedKeyRejectBeforeInstall() {
        for (change in 0..2) {
            val f = Fixture(); val review = checkNotNull(f.controller.prepare(line, "1"))
            when(change) { 0 -> f.current = false; 1 -> f.sim = 8; else -> f.point[1] = 9 }
            assertFalse(f.controller.confirm(review)); assertEquals(0, f.installs)
        }
    }
    @Test fun lostSessionDuringInstallClosesCandidateAndDoesNotClaimAcceptance() {
        val f = Fixture(); val review = checkNotNull(f.controller.prepare(line, "1"))
        f.duringInstall = { f.current = false }
        assertFalse(f.controller.confirm(review)); assertEquals(1, f.closes)
        assertFalse(checkNotNull(f.installedGuard).invoke())
    }
    @Test fun approvalCannotOutliveOriginalHostEvenWhenAccountAndDeviceAreUnchanged() {
        val f = Fixture(); val review = checkNotNull(f.controller.prepare(line, "1"))
        assertTrue(f.controller.confirm(review)); assertTrue(checkNotNull(f.installedGuard).invoke())
        f.current = false
        val successor = ConversationSocketComposition.AuthenticatedIdentitySnapshot(f.scope.identity) {}
        successor.requireCurrent()
        assertFalse(checkNotNull(f.installedGuard).invoke())
    }
    @Test fun invalidInputAndClosedControllerCannotCreateReview() {
        val f = Fixture()
        assertNull(f.controller.prepare(line, "01")); assertNull(f.controller.prepare(line, "0"))
        assertNull(f.controller.prepare("invalid", "1"))
        f.controller.close(); assertNull(f.controller.prepare(line, "1"))
        assertEquals(0, f.installs)
    }
    @Test fun successorHostCannotOpenMountAfterOriginalHostLossOrCreateAndroidState() {
        val selection = SealedLineAcceptance(UUID(0, 1), UUID(0, 2), UUID(0, 3), 1, 7, ByteArray(32) { 1 })
        var originalCurrent = true
        val owner = checkNotNull(SealedLineActivationMount.enableOwned(selection, true) { originalCurrent })
        val context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = error("Android state must remain untouched")
        }
        try {
            originalCurrent = false
            assertNull(SealedLineActivationMount.open(context, DeviceSigningKeyStore(context),
                selection.accountId, selection.deviceId, 2) { true })
        } finally { owner.close(); SealedLineActivationMount.disable() }
    }
    @Test fun obsoleteOwnerCloseDoesNotClearLaterExplicitHostApproval() {
        val selection = SealedLineAcceptance(UUID(0, 1), UUID(0, 2), UUID(0, 3), 1, 7, ByteArray(32) { 1 })
        val old = checkNotNull(SealedLineActivationMount.enableOwned(selection, true) { true })
        val fresh = checkNotNull(SealedLineActivationMount.enableOwned(selection, true) { true })
        var visited = false
        val context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context { visited = true; error("Fixture admission boundary") }
        }
        try {
            old.close()
            assertThrows(IllegalStateException::class.java) {
                SealedLineActivationMount.open(context, DeviceSigningKeyStore(context),
                    selection.accountId, selection.deviceId, 2) { true }
            }
            assertTrue(visited)
        } finally { fresh.close(); SealedLineActivationMount.disable() }
    }
    @Test fun explicitFlagWithoutOriginalHostCannotEnableApproval() {
        val selection = SealedLineAcceptance(UUID(0, 1), UUID(0, 2), UUID(0, 3), 1, 7, ByteArray(32) { 1 })
        assertFalse(SealedLineActivationMount.enable(selection, true))
    }
}
