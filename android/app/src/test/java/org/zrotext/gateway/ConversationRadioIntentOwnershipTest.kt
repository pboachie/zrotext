// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Synthetic metadata only: no preparation crypto, writer permission or platform radio call. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28], application=android.app.Application::class)
class ConversationRadioIntentOwnershipTest {
    private fun id()=UUID.randomUUID().toString()
    private fun session()=ConversationPhoneSession(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,"ab".repeat(32))
    private fun identity(session:ConversationPhoneSession)=EvidenceIdentity(session.account.toString(),session.device.toString(),session.originHash)
    private fun event(session:ConversationPhoneSession,event:String=id(),message:String=id(),attempt:String=id())=
        AlphaRadioEvent(event,message,attempt,"durable_submit_intent",10,
            accountId=session.account.toString(),deviceId=session.device.toString(),originHash=session.originHash)
    private fun memory()=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build()
    private fun reserve(db:SmsJournalDatabase,event:AlphaRadioEvent) {
        db.attempts().reserveAlpha(event.attemptId,event.messageId,3,1,event.eventId,10,
            identity=EvidenceIdentity(event.accountId!!,event.deviceId!!,event.originHash!!))
    }
    private fun sealed(db:SmsJournalDatabase,event:AlphaRadioEvent) {
        db.sealedPreparations().reserve(SealedPreparationRecord(event.accountId!!,event.messageId,event.attemptId,
            "01".repeat(32),"02".repeat(32))) {}
    }
    @Test fun ownershipRequiresExactTupleAndNeverClaimsCallbackEvidence() {
        val phone=session();val intent=event(phone)
        val lease=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
        try {
            assertTrue(ConversationRadioIntentOwnership.owns(intent))
            listOf(intent.copy(accountId=id()),intent.copy(deviceId=id()),intent.copy(originHash="cd".repeat(32)),
                intent.copy(messageId=id()),intent.copy(attemptId=id()),intent.copy(eventId=id()),
                intent.copy(evidence="sent_ok")).forEach { assertFalse(ConversationRadioIntentOwnership.owns(it)) }
            assertEquals(listOf(intent.eventId),ConversationRadioIntentOwnership.excluded(identity(phone)))
            assertTrue(ConversationRadioIntentOwnership.excluded(identity(phone).copy(originHash="cd".repeat(32))).isEmpty())
        } finally {lease.close()}
        assertFalse(ConversationRadioIntentOwnership.owns(intent))
    }
    @Test fun canonicalDuplicateAndClosedLeaseCannotEraseReplacementOwnership() {
        val phone=session();val intent=event(phone)
        listOf("bad",UUID(0,0).toString(),"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").forEach { bad ->
            assertThrows(IllegalArgumentException::class.java) {
                ConversationRadioIntentOwnership.register(phone,bad,intent.messageId,intent.attemptId)
            }
        }
        val first=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
        try {
            assertThrows(IllegalStateException::class.java) {ConversationRadioIntentOwnership.register(phone,intent.eventId,id(),id())}
            assertThrows(IllegalStateException::class.java) {ConversationRadioIntentOwnership.register(phone,id(),intent.messageId,id())}
            assertThrows(IllegalStateException::class.java) {ConversationRadioIntentOwnership.register(phone,id(),id(),intent.attemptId)}
        } finally {first.close()}
        val second=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
        try {first.close();assertTrue(ConversationRadioIntentOwnership.owns(intent))} finally {second.close();second.close()}
    }
    @Test fun boundedRegistryAndFullExclusionListWorkOnActualOlderSqlite() {
        val phone=session();val leases=mutableListOf<AutoCloseable>();val db=memory()
        try {
            repeat(1024) {leases+=ConversationRadioIntentOwnership.register(phone,id(),id(),id())}
            assertThrows(IllegalStateException::class.java) {ConversationRadioIntentOwnership.register(phone,id(),id(),id())}
            val ordinary=event(phone);reserve(db,ordinary)
            val excluded=ConversationRadioIntentOwnership.excluded(identity(phone))
            assertEquals(1024,excluded.size)
            assertEquals(ordinary.eventId,db.attempts().nextAlphaEvent(ordinary.accountId!!,ordinary.deviceId!!,
                ordinary.originHash!!,excluded)?.eventId)
        } finally {leases.forEach{it.close()};db.close()}
    }
    @Test fun liveOwnershipRecheckedAfterBlockedRoomTransactionAndStaleSnapshot() {
        val phone=session();val intent=event(phone);val db=memory();val pool=Executors.newSingleThreadExecutor()
        val started=CountDownLatch(1);val stale=ConversationRadioIntentOwnership.excluded(identity(phone))
        var lease:AutoCloseable?=null
        db.beginTransaction()
        try {
            val task=pool.submit {
                started.countDown()
                db.attempts().retireOrphanedAlphaIntents(20,stale) {
                    assertTrue(db.inTransaction());ConversationRadioIntentOwnership.owns(it)
                }
            }
            assertTrue(started.await(2,TimeUnit.SECONDS))
            lease=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
            sealed(db,intent);reserve(db,intent)
            db.setTransactionSuccessful();db.endTransaction()
            task.get(5,TimeUnit.SECONDS)
            assertEquals(AttemptState.RESERVED,db.attempts().getAttempt(intent.attemptId)?.state)
            assertNull(db.attempts().getAlphaEvent(intent.eventId)?.acknowledgedAtMs)
            assertNull(db.attempts().nextAlphaEvent(intent.accountId!!,intent.deviceId!!,intent.originHash!!,stale))
        } finally {
            if(db.inTransaction())db.endTransaction()
            lease?.close();pool.shutdown();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));db.close()
        }
    }
    @Test fun ownedOldestIntentDoesNotStarveOrdinaryAlphaOrCallbackEvidence() {
        val phone=session();val intent=event(phone);val ordinary=event(phone);val db=memory()
        val lease=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
        try {
            sealed(db,intent);reserve(db,intent);reserve(db,ordinary)
            val dao=db.attempts();val owner=identity(phone)
            assertEquals(ordinary.eventId,dao.nextAlphaEvent(owner.accountId,owner.deviceId,owner.originHash,
                ConversationRadioIntentOwnership.excluded(owner))?.eventId)
            dao.acknowledgeAlphaEvent(ordinary.eventId,20)
            val callback=intent.copy(eventId=id(),evidence="sent_ok")
            dao.insertAlphaEvent(callback)
            assertEquals(callback.eventId,dao.nextAlphaEvent(owner.accountId,owner.deviceId,owner.originHash)?.eventId)
            assertFalse(ConversationRadioIntentOwnership.owns(callback))
        } finally {lease.close();db.close()}
    }
    @Test fun durableSealedIntentNeverAutomaticallyResendsAfterRegistryLossAndRestart() {
        val phone=session();val intent=event(phone);val db=memory()
        val lease=ConversationRadioIntentOwnership.register(phone,intent.eventId,intent.messageId,intent.attemptId)
        try {
            sealed(db,intent);reserve(db,intent);lease.close()
            val dao=db.attempts();val owner=identity(phone)
            assertNull(dao.nextAlphaEvent(owner.accountId,owner.deviceId,owner.originHash))
            recoverJournalState(dao,30)
            assertEquals(AttemptState.NOT_SUBMITTED,dao.getAttempt(intent.attemptId)?.state)
            assertNotNull(dao.getAlphaEvent(intent.eventId)?.acknowledgedAtMs)
            assertEquals("proven_no_submit",dao.nextAlphaEvent(owner.accountId,owner.deviceId,owner.originHash)?.evidence)
            assertFalse(dao.acknowledgeAlphaIntent(intent.eventId,true,40))
            assertEquals(0,dao.consumeRadioStart(intent.attemptId,intent.messageId,3,1,40))
            assertNotNull(db.sealedPreparations().find(owner.accountId,intent.messageId))
        } finally {lease.close();db.close()}
    }
    @Test fun closedOwnerRetiresOnlyNoRadioStatesAndPreservesUncertainAttempt() {
        val phone=session();val pending=event(phone);val uncertain=event(phone);val db=memory()
        try {
            sealed(db,pending);reserve(db,pending);sealed(db,uncertain);reserve(db,uncertain)
            assertTrue(db.attempts().acknowledgeAlphaIntent(uncertain.eventId,true,20))
            assertEquals(1,db.attempts().consumeRadioStart(uncertain.attemptId,uncertain.messageId,3,1,21))
            db.attempts().retireOrphanedAlphaIntents(30,emptyList(),ConversationRadioIntentOwnership::owns)
            assertEquals(AttemptState.NOT_SUBMITTED,db.attempts().getAttempt(pending.attemptId)?.state)
            assertEquals(AttemptState.RADIO_STARTED,db.attempts().getAttempt(uncertain.attemptId)?.state)
        } finally {db.close()}
    }
}
