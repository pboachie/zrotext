// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class LocalLineBindingTest {
    private val account = "11111111-1111-4111-8111-111111111111"
    private val device = "22222222-2222-4222-8222-222222222222"
    private val line = "33333333-3333-4333-8333-333333333333"
    private val sender = "a".repeat(64)
    private val firstPdu = "b".repeat(64)

    @Test fun verifiedBindingRequiresOneSelectedSubscriptionAndIncreasingGeneration() {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            val first = LocalLineBinding(accountId = account, deviceId = device,
                lineId = line, generation = 1, subscriptionId = 7, installedAtMs = 1000)
            assertFalse(dao.installVerifiedLineBinding(first, emptyList()))
            assertFalse(dao.installVerifiedLineBinding(first, listOf(7, 8)))
            assertFalse(dao.installVerifiedLineBinding(first, listOf(8)))
            assertNull(dao.currentLineBinding())
            assertTrue(dao.installVerifiedLineBinding(first, listOf(7)))
            assertFalse(dao.installVerifiedLineBinding(first.copy(generation = 1), listOf(7)))
            assertFalse(dao.installVerifiedLineBinding(first.copy(generation = 2,
                lineId = "44444444-4444-4444-8444-444444444444"), listOf(7)))
            assertFalse(dao.installVerifiedLineBinding(first.copy(generation = 2,
                deviceId = "44444444-4444-4444-8444-444444444444"), listOf(7)))
            assertTrue(dao.installVerifiedLineBinding(first.copy(generation = 2,
                subscriptionId = 9, installedAtMs = 2000), listOf(9)))
            assertEquals(2L, dao.currentLineBinding()?.generation)
        } finally { db.close() }
    }

    @Test fun unsolicitedStopIsDurableAndUnknownLineCannotLiftOrAttributeIt() {
        val context = RuntimeEnvironment.getApplication()
        val name = "local-line-withdrawal-test.db"
        context.deleteDatabase(name)
        val first = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val dao = first.attempts()
            assertTrue(dao.installVerifiedLineBinding(LocalLineBinding(accountId = account,
                deviceId = device, lineId = line, generation = 3, subscriptionId = 7,
                installedAtMs = 1000), listOf(7)))
            assertTrue(dao.recordLocalWithdrawal(firstPdu, sender,
                InboundClassification.OPT_OUT, 7, listOf(7), 2000))
            assertFalse(dao.recordLocalWithdrawal(firstPdu, sender,
                InboundClassification.OPT_OUT, 7, listOf(7), 2001))
            assertEquals(line, dao.localWithdrawal(firstPdu)?.lineId)
            assertEquals(3L, dao.localWithdrawal(firstPdu)?.bindingGeneration)
            // A second SIM or missing subscription evidence can only make a global local block.
            val ambiguous = "c".repeat(64)
            assertTrue(dao.recordLocalWithdrawal(ambiguous, sender,
                InboundClassification.OPT_OUT_REVIEW, 7, listOf(7, 8), 2002))
            assertNull(dao.localWithdrawal(ambiguous)?.lineId)
            assertNull(dao.localWithdrawal(ambiguous)?.bindingGeneration)
            assertTrue(dao.isRecipientSuppressed(sender))
        } finally { first.close() }
        val reopened = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val dao = reopened.attempts()
            assertEquals(line, dao.currentLineBinding()?.lineId)
            assertEquals(3L, dao.currentLineBinding()?.generation)
            assertEquals(2, listOf(firstPdu, "c".repeat(64)).count {
                dao.localWithdrawal(it) != null
            })
            assertTrue(dao.isRecipientSuppressed(sender))
        } finally {
            reopened.close()
            context.deleteDatabase(name)
        }
    }
}
