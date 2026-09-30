// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.UUID
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationAuthenticatedRuntimeTest {
    private fun id() = UUID.randomUUID().toString()
    private val disclosure = Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray())
    private val scope = ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),disclosure,"11".repeat(32),1,2,"22".repeat(32),"33".repeat(32))
    private val phone = ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),1,1,"44".repeat(32))
    private var session: ConversationPhoneSession? = phone
    private var elapsed = 0L
    private var permission = true
    private var consent = true
    private var closeAck = true
    private var tamperTime = false
    private var decisions = 0
    private var exchanges = 0
    private var duringInstall: () -> Unit = {}
    private class Queue : Executor {
        private val commands = java.util.ArrayDeque<Runnable>()
        var beforeSubmit: () -> Unit = {}
        override fun execute(command: Runnable) { beforeSubmit();commands.add(command) }
        fun drain() { while(commands.isNotEmpty()) commands.removeFirst().run() }
    }
    private val worker = Queue()
    private val delivery = Queue()
    private lateinit var db: ConversationCaptureDatabase
    private lateinit var sendDb: ConversationSendDatabase
    private lateinit var assembly: ConversationAuthenticatedRuntime
    private val snapshots = mutableListOf<ConversationPresentationSnapshot>()
    private val review = ConversationPhoneReview(id(),scope.intervalId,scope.lineId,1,scope.peer,
        ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",disclosure,10000)
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val protection = object : ConversationJournalProtection {
        override fun seal(value:String,aad:String):InboundVault.Sealed {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key)
            cipher.updateAAD(aad.toByteArray());return InboundVault.Sealed(cipher.doFinal(value.toByteArray()),cipher.iv)
        }
        override fun open(value:InboundVault.Sealed,aad:String):String {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,value.nonce))
            cipher.updateAAD(aad.toByteArray());return cipher.doFinal(value.ciphertext).toString(Charsets.UTF_8)
        }
    }
    @Before fun setup() {
        val context=RuntimeEnvironment.getApplication()
        db=Room.inMemoryDatabaseBuilder(context,ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        sendDb=Room.inMemoryDatabaseBuilder(context,ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        val verifier=object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray):ConversationCaptureScope {check(evidence.contentEquals(byteArrayOf(1)));return scope}
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray):Long {
                check(scope==this@ConversationAuthenticatedRuntimeTest.scope && UUID.fromString(challenge)!=UUID(0,0) && evidence.contentEquals(byteArrayOf(2)));return 10000
            }
        }
        val wire=object:ConversationAuthenticatedWire {
            override fun currentSession()=session
            override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
                val current=checkNotNull(session)
                val bytes=if(request[5].toInt()==1) {
                    val time=ConversationChannelCodec.parseTimeRequest(request,current)
                    ConversationChannelCodec.timeReply(ConversationTimeReply(current,if(tamperTime) UUID.randomUUID() else time.challenge,100000))
                } else {
                    val close=ConversationChannelCodec.parseCloseRequest(request,current)
                    ConversationChannelCodec.closeReply(ConversationClosureReply(current,close.challenge,close.scope,closeAck))
                }
                return ConversationAuthenticatedWire.Reply(current,bytes)
            }
        }
        assembly=ConversationAuthenticatedRuntime(db.journal(),sendDb.sends(),verifier,protection,wire,{elapsed},
            { selected,utc -> check(selected==scope && utc in 100000..109999 && permission && consent) },
            {check(it==scope);decisions++}, {exchanges++;duringInstall();byteArrayOf(2)},worker,delivery)
        assembly.presentation.observe {snapshots.add(it)}
        delivery.drain()
    }
    @After fun cleanup() {db.close();sendDb.close()}
    private fun drain() {worker.drain();delivery.drain()}
    private fun propose() {assembly.propose(review,byteArrayOf(1));drain()}
    private fun activate() {propose();val value=snapshots.last();assembly.presentation.approvePhoneReview(review.requestId,value.version);drain();assertTrue(assembly.captureEligible())}
    @Test fun proposalAndSeparatePhoneDecisionRequiredBeforeEncryptedReceipt() {
        propose();assertFalse(assembly.captureEligible());assertEquals(0,decisions)
        val value=snapshots.last();assertEquals(ConversationPresentationPhase.AWAITING_PHONE_REVIEW,value.phase)
        assembly.presentation.approvePhoneReview(review.requestId,value.version);drain()
        assertEquals(1,decisions);assertEquals(1,exchanges);assertTrue(assembly.captureEligible())
        assertEquals(ConversationObservation.CAPTURED,assembly.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic incoming"))
        assertEquals(ConversationObservation.DUPLICATE,assembly.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic incoming"))
        assertEquals(1,db.journal().contentCount())
    }
    @Test fun denialNeverInstallsOrCaptures() {propose();val value=snapshots.last();assembly.presentation.declinePhoneReview(review.requestId,value.version);drain();assertFalse(assembly.captureEligible());assertEquals(0,decisions);assertEquals(0,exchanges)}
    @Test fun wrongAuthenticatedTimeNonceCannotPrepare() {tamperTime=true;propose();assertFalse(assembly.captureEligible());assertEquals(0,decisions);assertNull(db.journal().installation())}
    @Test fun permissionLossBeforeApprovalCannotInstall() {propose();permission=false;val value=snapshots.last();assembly.presentation.approvePhoneReview(review.requestId,value.version);drain();assertFalse(assembly.captureEligible());assertEquals(0,exchanges)}
    @Test fun permissionLossDuringInstallCannotActivate() {duringInstall={permission=false;assembly.lifecycleLost(ConversationStopReason.PERMISSION_LOST)};propose();val value=snapshots.last();assembly.presentation.approvePhoneReview(review.requestId,value.version);drain();assertFalse(assembly.captureEligible());assertEquals(ConversationStopReason.PERMISSION_LOST,snapshots.last().stopReason)}
    @Test fun sessionRotationClosesEligibilityWithoutCachedAuthority() {activate();session=phone.copy(connectionEpoch=2);assertFalse(assembly.captureEligible())}
    @Test fun withdrawalClosesSynchronouslyAndPublishesVerifiedDurableOutcome() {activate();consent=false;assembly.lifecycleLost(ConversationStopReason.WITHDRAWAL);assertFalse(assembly.captureEligible());drain();assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,snapshots.last().phase);assertEquals(ConversationStopReason.WITHDRAWAL,snapshots.last().stopReason);assertEquals("closed",db.journal().installation()!!.state);assertEquals(1,sendDb.sends().closed(scope.intervalId))}
    @Test fun missingDurableAckCannotClaimClosed() {activate();closeAck=false;assembly.lifecycleLost(ConversationStopReason.OWNER_SESSION_LOST);assertFalse(assembly.captureEligible());drain();assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,snapshots.last().close)}
    @Test fun expiredAuthenticatedTimeCannotKeepCaptureActive() {activate();elapsed=30000;assertFalse(assembly.captureEligible())}
    @Test fun lifecycleBeforeQueuedProposalCannotReopenAdmission() {assembly.propose(review,byteArrayOf(1));assembly.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST);drain();assertFalse(assembly.captureEligible());assertNull(db.journal().installation());assertEquals(0,decisions)}
    @Test fun concurrentRejectedSchedulingNeverSilentlyAcceptsLifecycleClosure() {
        val entered=java.util.concurrent.CountDownLatch(1)
        val release=java.util.concurrent.CountDownLatch(1)
        worker.beforeSubmit={entered.countDown();check(release.await(2,java.util.concurrent.TimeUnit.SECONDS));throw java.util.concurrent.RejectedExecutionException()}
        val closureThread=java.util.concurrent.atomic.AtomicReference<Thread>()
        val closureStarted=java.util.concurrent.CountDownLatch(1)
        val pool=java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val proposal=pool.submit {assembly.propose(review,byteArrayOf(1))}
            assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            val closure=pool.submit {closureThread.set(Thread.currentThread());closureStarted.countDown();assembly.lifecycleLost(ConversationStopReason.OWNER_SESSION_LOST)}
            assertTrue(closureStarted.await(2,java.util.concurrent.TimeUnit.SECONDS))
            val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(1)
            while(closureThread.get().state!=Thread.State.BLOCKED && !closure.isDone && System.nanoTime()<deadline) Thread.yield()
            assertEquals(Thread.State.BLOCKED,closureThread.get().state)
            assertFalse(closure.isDone) // Concurrent submission waits for definitive delegate admission.
            release.countDown()
            proposal.get(2,java.util.concurrent.TimeUnit.SECONDS);closure.get(2,java.util.concurrent.TimeUnit.SECONDS)
            delivery.drain()
            assertFalse(assembly.captureEligible())
            assertEquals(ConversationPresentationPhase.FAILURE,snapshots.last().phase)
            assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,snapshots.last().close)
        } finally {release.countDown();pool.shutdownNow()}
    }
}
