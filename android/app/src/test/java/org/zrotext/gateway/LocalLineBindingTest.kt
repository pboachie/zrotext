// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class LocalLineBindingTest {
    private val account = "11111111-1111-4111-8111-111111111111"
    private val device = "22222222-2222-4222-8222-222222222222"
    private val line = "33333333-3333-4333-8333-333333333333"
    private val sender = "a".repeat(64)
    private val firstPdu = "b".repeat(64)
    private val testSender = "+12025550199"
    private val testKey = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")

    @Test fun senderVaultBindsCiphertextToTheExactDedupeToken() {
        val sealed = InboundVault.sealSenderWithKey(testKey, testSender, firstPdu)
        assertFalse(sealed.ciphertext.contentEquals(testSender.toByteArray(Charsets.US_ASCII)))
        assertEquals(testSender, InboundVault.openSenderWithKey(testKey, sealed, firstPdu))
        assertThrows(Exception::class.java) {
            InboundVault.openSenderWithKey(testKey, sealed, "c".repeat(64))
        }
        val changed = sealed.ciphertext.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) {
            InboundVault.openSenderWithKey(testKey, InboundVault.Sealed(changed, sealed.nonce),
                firstPdu)
        }
    }

    @Test fun keystoreFailureLeavesNoRecoverableSenderButDoesNotPreventLocalBlock() {
        val sealed = InboundVault.sealSenderOrNull(testSender, firstPdu) { _, _ ->
            throw IllegalStateException("keystore unavailable")
        }
        assertNull(sealed)
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            assertTrue(dao.recordLocalWithdrawal(firstPdu, sender, InboundClassification.OPT_OUT,
                null, emptyList(), 2000, sealed?.ciphertext, sealed?.nonce))
            assertTrue(dao.isRecipientSuppressed(sender))
            assertNull(dao.localWithdrawal(firstPdu)?.encryptedSender)
            assertNull(dao.localWithdrawal(firstPdu)?.senderNonce)
            assertEquals(1L, dao.localWithdrawal(firstPdu)?.deviceSequence)
        } finally { db.close() }
    }

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
            val sealed = InboundVault.sealSenderWithKey(testKey, testSender, firstPdu)
            assertTrue(dao.recordLocalWithdrawal(firstPdu, sender,
                InboundClassification.OPT_OUT, 7, listOf(7), 2000,
                sealed.ciphertext, sealed.nonce))
            assertFalse(dao.recordLocalWithdrawal(firstPdu, sender,
                InboundClassification.OPT_OUT, 7, listOf(7), 2001))
            val stored = dao.localWithdrawal(firstPdu)!!
            assertEquals(line, stored.lineId)
            assertEquals(3L, stored.bindingGeneration)
            assertEquals(1L, stored.deviceSequence)
            assertEquals(UUID.fromString(stored.eventId).toString(), stored.eventId)
            assertArrayEquals(sealed.ciphertext, stored.encryptedSender)
            assertArrayEquals(sealed.nonce, stored.senderNonce)
            assertEquals(testSender, InboundVault.openSenderWithKey(testKey,
                InboundVault.Sealed(stored.encryptedSender!!, stored.senderNonce!!), firstPdu))
            // A second SIM or missing subscription evidence can only make a global local block.
            val ambiguous = "c".repeat(64)
            assertTrue(dao.recordLocalWithdrawal(ambiguous, sender,
                InboundClassification.OPT_OUT_REVIEW, 7, listOf(7, 8), 2002))
            assertNull(dao.localWithdrawal(ambiguous)?.lineId)
            assertNull(dao.localWithdrawal(ambiguous)?.bindingGeneration)
            assertNull(dao.localWithdrawal(ambiguous)?.encryptedSender)
            assertNull(dao.localWithdrawal(ambiguous)?.senderNonce)
            assertEquals(2L, dao.localWithdrawal(ambiguous)?.deviceSequence)
            assertTrue(dao.isRecipientSuppressed(sender))
        } finally { first.close() }
        val reopened = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val dao = reopened.attempts()
            assertEquals(line, dao.currentLineBinding()?.lineId)
            assertEquals(3L, dao.currentLineBinding()?.generation)
            val persisted = dao.localWithdrawal(firstPdu)!!
            assertEquals(1L, persisted.deviceSequence)
            assertEquals(testSender, InboundVault.openSenderWithKey(testKey,
                InboundVault.Sealed(persisted.encryptedSender!!, persisted.senderNonce!!), firstPdu))
            assertEquals(2, listOf(firstPdu, "c".repeat(64)).count {
                dao.localWithdrawal(it) != null
            })
            assertTrue(dao.isRecipientSuppressed(sender))
            assertTrue(dao.recordLocalWithdrawal("d".repeat(64), sender,
                InboundClassification.OPT_OUT, null, emptyList(), 3000))
            assertEquals(3L, dao.localWithdrawal("d".repeat(64))?.deviceSequence)
        } finally {
            reopened.close()
            context.deleteDatabase(name)
        }
    }

    @Test fun versionEightWithdrawalMigratesWithoutInventingSenderOrSequence() {
        val context: Context = RuntimeEnvironment.getApplication()
        val name = "local-withdrawal-v8-upgrade.db"
        context.deleteDatabase(name)
        val current = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            assertTrue(current.attempts().recordLocalWithdrawal(firstPdu, sender,
                InboundClassification.OPT_OUT, null, emptyList(), 2000))
        } finally { current.close() }
        val old = context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null)
        old.execSQL("CREATE TABLE local_inbound_withdrawals_v8 (dedupeToken TEXT NOT NULL PRIMARY KEY, senderToken TEXT NOT NULL, classification TEXT NOT NULL, observedSubscriptionId INTEGER, lineId TEXT, bindingGeneration INTEGER, receivedAtMs INTEGER NOT NULL)")
        old.execSQL("INSERT INTO local_inbound_withdrawals_v8 SELECT dedupeToken,senderToken,classification,observedSubscriptionId,lineId,bindingGeneration,receivedAtMs FROM local_inbound_withdrawals")
        old.execSQL("DROP TABLE local_inbound_withdrawals")
        old.execSQL("ALTER TABLE local_inbound_withdrawals_v8 RENAME TO local_inbound_withdrawals")
        old.execSQL("CREATE INDEX index_local_inbound_withdrawals_senderToken ON local_inbound_withdrawals(senderToken)")
        old.execSQL("DROP TABLE local_withdrawal_sequences")
        old.version = 8
        old.close()
        val upgraded = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_8_9).build()
        try {
            val dao = upgraded.attempts()
            assertEquals(9, upgraded.openHelper.readableDatabase.version)
            assertTrue(dao.isRecipientSuppressed(sender))
            val oldWithdrawal = dao.localWithdrawal(firstPdu)!!
            assertNull(oldWithdrawal.eventId)
            assertNull(oldWithdrawal.deviceSequence)
            assertNull(oldWithdrawal.encryptedSender)
            assertNull(oldWithdrawal.senderNonce)
            assertTrue(dao.recordLocalWithdrawal("c".repeat(64), sender,
                InboundClassification.OPT_OUT, null, emptyList(), 3000))
            assertEquals(1L, dao.localWithdrawal("c".repeat(64))?.deviceSequence)
        } finally {
            upgraded.close()
            context.deleteDatabase(name)
        }
    }
}
