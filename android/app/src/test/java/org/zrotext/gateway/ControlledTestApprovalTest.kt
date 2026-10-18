// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import androidx.room.Room
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ControlledTestApprovalTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var prefs: SharedPreferences
    private lateinit var approval: ControlledTestApproval
    private val device = UUID.randomUUID()
    private val identity = EvidenceIdentity.fromStream(UUID.randomUUID(), device, ENDPOINT)
    private val scope = ControlledTestScope.capture(ENDPOINT, device.toString(), 7, "+15555550101")
    private val prior = UUID.randomUUID().toString()
    private val next = UUID.randomUUID().toString()

    @Before fun setup() {
        val context = RuntimeEnvironment.getApplication()
        db = Room.inMemoryDatabaseBuilder(context, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        prefs = context.getSharedPreferences("controlled-test-fixture", Context.MODE_PRIVATE)
        assertTrue(prefs.edit().clear().putBoolean("attempt_used", true).putString("unrelated", "retained").commit())
        approval = ControlledTestApproval(db, prefs)
    }
    @After fun cleanup() { db.close() }

    private fun failed(acknowledge: Boolean = true) {
        val dao = db.attempts()
        val message = UUID.randomUUID().toString()
        val intent = UUID.randomUUID().toString()
        dao.reserveAlpha(prior, message, 2, 1, intent, 10, identity = identity)
        assertTrue(dao.acknowledgeAlphaIntent(intent, true, 20))
        assertEquals(1, dao.consumeRadioStart(prior, message, 2, 1, 21))
        dao.recordCallback(prior, 0, false, 1, null, 30)
        val event = checkNotNull(dao.nextAlphaEvent(identity.accountId, identity.deviceId, identity.originHash))
        if (acknowledge) assertEquals(1, dao.acknowledgeAlphaEvent(event.eventId, 40))
    }
    private fun authorize(): String { failed();return approval.approve(scope, approval.prepare(scope), 100) }
    private fun refused(body: () -> Unit) { assertThrows(RuntimeException::class.java) { body() } }

    @Test fun freshExplicitApprovalSpendsOnceAndRetainsPreviousAttemptAndMarker() {
        val nonce = authorize()
        val original = db.attempts().getAttempt(prior)
        assertEquals(nonce, approval.available(scope, 101))
        approval.consume(scope, nonce, identity, next, 102)
        assertNull(approval.available(scope, 103))
        refused { approval.consume(scope, nonce, identity, UUID.randomUUID().toString(), 104) }
        refused { approval.approve(scope, approval.prepare(scope), 105) }
        assertEquals(original, db.attempts().getAttempt(prior))
        assertTrue(prefs.getBoolean("attempt_used", false))
        assertEquals("retained", prefs.getString("unrelated", null))
        assertTrue(ControlledTestApproval(db, prefs).radioStillApproved(nonce, identity, next))
    }

    @Test fun unacknowledgedFailureCannotBeApproved() {
        failed(false);refused { approval.prepare(scope) }
    }
    @Test fun missingAndUnknownResultsCannotAuthorizeAnotherMessage() {
        refused { approval.prepare(scope) };failed()
        db.attempts().setState(prior, AttemptState.UNKNOWN, 50)
        refused { approval.prepare(scope) }
    }
    @Test fun unrelatedUnresolvedAttemptBlocksApproval() {
        failed();db.attempts().reserve(UUID.randomUUID().toString(), 8, 1, 50)
        refused { approval.prepare(scope) }
    }
    @Test fun successfulOrPartialEvidenceDoesNotBecomeFailurePermission() {
        failed();db.attempts().recordCallback(prior, 0, false, Activity.RESULT_OK, null, 50)
        assertTrue(checkNotNull(db.attempts().getAttempt(prior)).evidenceConflict)
        refused { approval.prepare(scope) }
    }
    @Test fun reviewedRecipientAndSimCannotChangeBeforeApproval() {
        failed();val review = approval.prepare(scope)
        refused { approval.approve(scope.copy(subscriptionId = 8), review, 100) }
        refused { approval.approve(scope.copy(recipientDigest = "a".repeat(64)), review, 100) }
        assertNull(approval.available(scope, 101))
    }
    @Test fun changedRecipientSimOriginDeviceOrAccountCannotConsumeThePermit() {
        val nonce = authorize()
        for (changed in listOf(scope.copy(subscriptionId = 8), scope.copy(recipientDigest = "a".repeat(64)),
                scope.copy(originHash = "b".repeat(64)), scope.copy(deviceId = UUID.randomUUID().toString()))) {
            refused { approval.consume(changed, nonce, identity, next, 101) }
        }
        refused { approval.consume(scope, nonce, identity.copy(accountId = UUID.randomUUID().toString()), next, 101) }
        assertEquals(nonce, approval.available(scope, 102))
    }
    @Test fun expiryAndClockRollbackCannotSpendApproval() {
        val nonce = authorize()
        refused { approval.consume(scope, nonce, identity, next, 99) }
        refused { approval.consume(scope, nonce, identity, next, 300100) }
        assertNull(approval.available(scope, 300100))
    }
    @Test fun replacingUnusedApprovalRetainsItAndInvalidatesItsNonce() {
        val first = authorize()
        val second = approval.approve(scope, approval.prepare(scope), 110)
        assertNotEquals(first, second)
        refused { approval.consume(scope, first, identity, next, 111) }
        approval.consume(scope, second, identity, next, 112)
        assertTrue(prefs.getString("controlled_test_approvals_v1", "")!!.contains(first))
    }
    @Test fun lateContradictionBeforeConsumptionBlocksTheNewGrant() {
        val nonce = authorize()
        db.attempts().recordCallback(prior, 0, false, Activity.RESULT_OK, null, 101)
        refused { approval.consume(scope, nonce, identity, next, 102) }
    }
    @Test fun lateContradictionAfterConsumptionFencesTheRadioBoundary() {
        val nonce = authorize();approval.consume(scope, nonce, identity, next, 101)
        assertTrue(approval.radioStillApproved(nonce, identity, next))
        db.attempts().recordCallback(prior, 0, false, Activity.RESULT_OK, null, 102)
        assertFalse(approval.radioStillApproved(nonce, identity, next))
    }
    @Test fun anotherAttemptCannotBorrowASpentApproval() {
        val nonce = authorize();approval.consume(scope, nonce, identity, next, 101)
        assertFalse(approval.radioStillApproved(nonce, identity, UUID.randomUUID().toString()))
        assertFalse(approval.radioStillApproved(nonce, identity.copy(accountId = UUID.randomUUID().toString()), next))
    }
    @Test fun failedPersistenceCannotCreateAnApprovalOrModifyTheOldEvidence() {
        failed();val original = db.attempts().getAttempt(prior)
        val unavailable = object : SharedPreferences by prefs {
            override fun edit(): SharedPreferences.Editor {
                val editor = prefs.edit()
                return object : SharedPreferences.Editor by editor {
                    override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                        editor.putString(key, value);return this
                    }
                    override fun commit() = false
                }
            }
        }
        val blocked = ControlledTestApproval(db, unavailable)
        refused { blocked.approve(scope, blocked.prepare(scope), 100) }
        assertNull(approval.available(scope, 101))
        assertEquals(original, db.attempts().getAttempt(prior))
        assertTrue(prefs.getBoolean("attempt_used", false))
    }
    @Test fun corruptLedgerRefusesWithoutResettingItsEvidence() {
        failed();assertTrue(prefs.edit().putString("controlled_test_approvals_v1", "corrupt").commit())
        refused { approval.prepare(scope) }
        assertEquals("corrupt", prefs.getString("controlled_test_approvals_v1", null))
    }
    companion object { private const val ENDPOINT = "wss://gateway.invalid/v1/device-stream" }
}
