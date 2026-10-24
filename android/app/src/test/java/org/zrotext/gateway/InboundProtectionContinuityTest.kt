// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Test-only SQL seeds a historical identity, never a production provisioning factory. Actual
 * Room and JCA HMAC are exercised; the fixture keys have no hardware or enrolled authority. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class InboundProtectionContinuityTest {
    private class Fixture : AutoCloseable {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        val dao = db.captures03()
        val epochs = InboundProtectionEpochs()
        val original = SecretKeySpec(ByteArray(32) { 9 }, "HmacSHA256")
        var present: SecretKey? = original
        var reads = 0
        fun read(): SecretKey = InboundProtection.verifiedKey(dao, {
            reads++; checkNotNull(present)
        }, current = epochs::requireNotRevoked, withdraw = epochs::revoke)
        fun pinned() {
            val tag = Mac.getInstance("HmacSHA256").run {
                init(original); doFinal("zrotext-inbound-protection-continuity-v1\u0000".toByteArray(Charsets.US_ASCII))
            }.joinToString("") { "%02x".format(it.toInt() and 255) }
            db.openHelper.writableDatabase.execSQL("INSERT INTO inbound_protection_state VALUES(1,?,?,0,NULL,0,1000)",
                arrayOf(tag, UUID(0, 19).toString()))
        }
        fun retained(token: String) = Capture03IngressGate.reserve {
            dao.claim(Capture03Route(token, "blocked", null, null, 1000), null, false) {}
        }
        override fun close() = db.close()
    }
    @Test fun absentPinAndEmptyTablesNeverBlessEvenAnExistingLegacyAlias() = Fixture().use { f ->
        assertEquals("continuity_missing", assertThrows(InboundProtection.Unavailable::class.java) { f.read() }.reason)
        assertEquals(0, f.reads); assertNull(f.dao.protection()); assertSame(f.original, f.present)
        assertFalse(f.dao.hasCapture03History())
    }
    @Test fun missingPinnedKeyCreatesNeitherProtectionPinNorReplacementKey() = Fixture().use { f ->
        f.pinned(); assertSame(f.original, f.read()); val before = f.dao.protection(); f.present = null
        assertEquals("key_unavailable", assertThrows(InboundProtection.Unavailable::class.java) { f.read() }.reason)
        assertNull(f.present); assertFalse(f.epochs.available()); assertEquals(before, f.dao.protection())
    }
    @Test fun retainedCaptureHistoryWithoutItsOriginalPinRefusesBeforeReadingAnyCurrentAlias() = Fixture().use { f ->
        f.retained("a".repeat(64))
        assertEquals("continuity_missing", assertThrows(InboundProtection.Unavailable::class.java) { f.read() }.reason)
        assertEquals(0, f.reads); assertFalse(f.epochs.available()); assertNull(f.dao.protection())
        assertEquals("blocked", f.dao.route("a".repeat(64))!!.route)
    }
    @Test fun recreatedAliasAcrossCallersCannotChangeTheSamePduOrItsPermanentRoute() = Fixture().use { f ->
        f.pinned()
        val first = ConversationExistingSuppressionTokens(f::read)
        val sender = first.sender("+12025550199")
        val pdu = first.pdu(sender, byteArrayOf(1, 2, 3))
        f.retained(pdu)
        val prior = f.dao.protection()
        val second = ConversationExistingSuppressionTokens(f::read)
        assertEquals(pdu, second.pdu(second.sender("+12025550199"), byteArrayOf(1, 2, 3)))
        f.present = SecretKeySpec(ByteArray(32) { 8 }, "HmacSHA256")
        val coldCaller = ConversationExistingSuppressionTokens(f::read)
        assertEquals("identity_changed", assertThrows(InboundProtection.Unavailable::class.java) {
            coldCaller.sender("+12025550199")
        }.reason)
        assertEquals(prior, f.dao.protection()); assertEquals("blocked", f.dao.route(pdu)!!.route)
        assertFalse(f.epochs.available())
    }
    @Test fun missingOriginalKeyCannotBeReplacedByAnotherObjectOrSuccessfulRead() = Fixture().use { f ->
        f.pinned(); f.present = null
        assertThrows(InboundProtection.Unavailable::class.java) { f.read() }
        val reads = f.reads; f.present = f.original
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { ConversationExistingSuppressionTokens(f::read).requireAvailable() }
        assertEquals(reads, f.reads)
    }
    @Test fun coldDurableQuarantineRefusesEvenWithTheExactOriginalKey() = Fixture().use { f ->
        f.pinned(); f.dao.quarantineProtection("key_unavailable", 1, 1001)
        val cold = InboundProtectionEpochs(); var provider = 0
        assertThrows(InboundProtection.Unavailable::class.java) {
            InboundProtection.verifiedKey(f.dao, { provider++; f.original }, cold::requireNotRevoked, cold::revoke)
        }
        assertEquals(0, provider); assertFalse(cold.available())
        assertNotNull(f.dao.protection()!!.expectedTag)
    }
    @Test fun negativeLedgerRetainsAllOptDebtAndNeverClearsPinOrBecomesReady() = Fixture().use { f ->
        f.pinned(); val pin = f.dao.protection()!!.expectedTag
        f.dao.quarantineProtection("key_unavailable", 1, 1001)
        f.dao.quarantineProtection("identity_changed", 2, 1002)
        f.dao.quarantineProtection("storage_unavailable", 4, 1003)
        val row = f.dao.protection()!!
        assertTrue(row.blocked); assertEquals(7, row.debtMask); assertEquals(pin, row.expectedTag)
        assertEquals(1000L, row.firstObservedMs); assertEquals("storage_unavailable", row.reason)
        assertThrows(IllegalArgumentException::class.java) { f.dao.quarantineProtection("ready", 0, 1004) }
        assertThrows(IllegalArgumentException::class.java) { f.dao.quarantineProtection("key_unavailable", 8, 1004) }
        assertEquals(row, f.dao.protection())
    }
    @Test fun freshNegativeLedgerContainsNoRecipientTokenKeyOrCounter() = Fixture().use { f ->
        f.dao.quarantineProtection("key_unavailable", 3, 2000)
        val row = f.dao.protection()!!
        assertTrue(row.blocked); assertNull(row.expectedTag); assertNull(row.originId); assertEquals(3, row.debtMask)
        assertTrue(f.dao.modes().isEmpty()); assertNull(f.dao.counter(UUID(0, 1).toString(), UUID(0, 2).toString()))
        assertFalse(f.dao.hasCapture03History())
    }
    @Test fun providerWaitAcrossStopAndKnownWithdrawalCompletionCannotPublishTheOldEpoch() = Fixture().use { f ->
        f.pinned(); val epoch = f.epochs.snapshot()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val published = AtomicBoolean(); val refused = AtomicBoolean()
        val worker = thread {
            try {
                InboundProtection.verifiedKey(f.dao, {
                    entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.original
                }, current = { f.epochs.checked(epoch) }, withdraw = f.epochs::revoke)
                published.set(true)
            } catch (_: InboundProtectionEpochs.Withdrawn) { refused.set(true) }
        }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            checkNotNull(f.epochs.beforeProtectionWait(OptOutParser.OPT_OUT)).completeKnownWithdrawal()
            assertTrue(f.epochs.available())
        } finally { release.countDown() }
        worker.join(5_000); assertFalse(worker.isAlive); assertFalse(published.get()); assertTrue(refused.get())
    }
    @Test fun noKeyOrProtectionProviderMayRunUnderTheIngressReservationGate() = Fixture().use { f ->
        Capture03IngressGate.reserve {
            assertThrows(IllegalStateException::class.java) { f.read() }
        }
        assertEquals(0, f.reads); assertTrue(f.epochs.available())
    }
}
