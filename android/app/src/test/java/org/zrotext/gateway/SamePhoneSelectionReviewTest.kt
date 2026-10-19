// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Genuine synthetic signatures, actual callback-driven complete-selection issuer and Room
 * history. These tests create local PENDING decisions only, never owner or hardware permission.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SamePhoneSelectionReviewTest {
    private class Inputs(val f: Profile03ExecutionFixture) : SamePhoneSelectionReview.Inputs {
        var now = f.now
        var active = true
        var readHook: () -> Unit = {}
        override fun withdrawInstalled() { f.line.owner.retireInstalled() }
        override fun requireSession() { check(active) }
        override fun nowMs() = now
        override fun captureFresh() = f.line.owner.capture()
        override fun retained(): SamePhoneSelectionReview.Retained {
            readHook()
            return SamePhoneSelectionReview.Retained(f.binding,
                checkNotNull(f.line.db.lineActivationsV2().find("sealed", f.line.challengeId.toString())),
                checkNotNull(f.line.db.profile03Elections().find(f.record.challengeId)), f.line.point)
        }
    }
    @Test fun freshExplicitReviewRetainsOriginalHistoryAndNeverReconstructsAnInstalledPermit() = Profile03ExecutionFixture().use { f ->
        f.install()
        val original = f.line.db.lineActivationsV2().find("sealed", f.line.challengeId.toString())!!
        val election = f.line.db.profile03Elections().find(f.record.challengeId)
        f.line.callback() // The original selected-SIM permit is genuinely withdrawn.
        assertNull(f.binding.installedSelectionV2())
        val inputs = Inputs(f)
        SamePhoneSelectionReview(inputs).use { controller ->
            assertNull(controller.takePending())
            val review = checkNotNull(controller.prepare())
            assertEquals(f.line.selected, review.selectedSubscription)
            assertEquals(LineActivationV2Kind.EMBEDDED, review.newObservationKind)
            assertEquals(2, review.completeSimCount)
            assertTrue(controller.confirm(review)); assertFalse(controller.confirm(review))
            val pending = checkNotNull(controller.takePending())
            assertNull(controller.takePending())
            assertArrayEquals(inputs.captureFresh()!!.observation().bytes(), pending.observation())
            assertFalse(Profile03ElectionEncoding.decode(original.observationB64url, 121).contentEquals(pending.observation()))
            assertNull(f.binding.installedSelectionV2()) // A phone decision is not owner approval/ACK.
            assertEquals(original, f.line.db.lineActivationsV2().find("sealed", original.challengeId))
            assertEquals(election, f.line.db.profile03Elections().find(f.record.challengeId))
            assertEquals(f.binding, f.line.db.attempts().currentLineBinding())
            controller.cancel()
            assertThrows(IllegalStateException::class.java) { pending.requireCurrent() }
        }
    }
    @Test fun completeSetCallbackChangedSubscriptionAndSessionLossConsumeTheDisplayedDecision() {
        for (change in 0..2) Profile03ExecutionFixture().use { f ->
            f.install(); f.line.callback()
            val inputs = Inputs(f)
            SamePhoneSelectionReview(inputs).use { controller ->
                val displayed = checkNotNull(controller.prepare())
                when (change) {
                    0 -> { f.line.rows = f.line.rows.drop(1); f.line.callback() }
                    1 -> { f.line.selected = 7; f.line.callback() }
                    2 -> inputs.active = false
                }
                assertFalse(controller.confirm(displayed))
                assertFalse(controller.confirm(displayed))
                assertNull(controller.takePending())
                assertNull(f.binding.installedSelectionV2())
            }
        }
    }
    @Test fun clockRegressionExpiryAndBlockedIdentityReadsCannotCarryConsentPastItsWindow() {
        for (change in 0..2) Profile03ExecutionFixture().use { f ->
            f.install(); f.line.callback()
            val inputs = Inputs(f)
            SamePhoneSelectionReview(inputs).use { controller ->
                val displayed = checkNotNull(controller.prepare())
                when (change) {
                    0 -> inputs.now--
                    1 -> inputs.now += 30_000
                    2 -> inputs.readHook = { inputs.now += 30_000; inputs.readHook = {} }
                }
                assertFalse(controller.confirm(displayed)); assertNull(controller.takePending())
            }
        }
    }
    @Test fun newReviewCloseAndPendingExpiryWithdrawEvenAPreviouslyTakenDecision() {
        for (change in 0..2) Profile03ExecutionFixture().use { f ->
            f.install(); f.line.callback()
            val inputs = Inputs(f)
            val controller = SamePhoneSelectionReview(inputs)
            try {
                val displayed = checkNotNull(controller.prepare())
                assertTrue(controller.confirm(displayed))
                val pending = checkNotNull(controller.takePending())
                when (change) {
                    0 -> assertNotNull(controller.prepare())
                    1 -> controller.close()
                    2 -> inputs.now += 300_000
                }
                assertThrows(IllegalStateException::class.java) { pending.requireCurrent() }
                assertNull(f.binding.installedSelectionV2())
            } finally { controller.close() }
        }
    }
    @Test fun cancellationAtAnIdentityWaitCannotPublishALateReviewOrConsent() = Profile03ExecutionFixture().use { f ->
        f.install(); f.line.callback()
        val inputs = Inputs(f)
        SamePhoneSelectionReview(inputs).use { controller ->
            inputs.readHook = { inputs.readHook = {}; controller.cancel() }
            assertNull(controller.prepare())
            val displayed = checkNotNull(controller.prepare())
            inputs.readHook = { inputs.readHook = {}; controller.cancel() }
            assertFalse(controller.confirm(displayed)); assertNull(controller.takePending())
            assertNull(f.binding.installedSelectionV2())
        }
    }
}
