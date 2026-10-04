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
    private var duringContent: () -> Unit = {}
    private var duringTime: () -> Unit = {}
    private var duringAuthority: () -> Unit = {}
    private var duringElapsed: () -> Unit = {}
    private var leaseDuration = 10000L
    private var authorityUntil = 110000L
    private var timeReplies = 0
    private var captureReplies = 0
    private var captureCreated = true
    private var alterCaptureReply: (ByteArray) -> ByteArray = { it }
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
                check(scope==this@ConversationAuthenticatedRuntimeTest.scope && UUID.fromString(challenge)!=UUID(0,0) && evidence.contentEquals(byteArrayOf(2)));return leaseDuration
            }
        }
        val wire=object:ConversationAuthenticatedWire {
            override fun currentSession()=session
            override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
                val current=checkNotNull(session)
                val bytes=if(request[5].toInt()==1) {
                    val time=ConversationChannelCodec.parseTimeRequest(request,current)
                    val utc=100000+elapsed
                    timeReplies++;duringTime()
                    ConversationChannelCodec.timeReply(ConversationTimeReply(current,if(tamperTime) UUID.randomUUID() else time.challenge,utc))
                } else if(request[5].toInt()==12) {
                    val (nonce,selected,envelope)=ConversationChannelCodec.parseCaptureRequest(request,current)
                    captureReplies++
                    duringContent()
                    alterCaptureReply(ConversationChannelCodec.captureReply(current,nonce,UUID.fromString(db.journal().receipt("55".repeat(32))!!.captureId),
                        Draft02OutboundPreparation.hash(envelope),captureCreated)).also {assertEquals(scope,selected)}
                } else if(request[5].toInt()==14) {
                    val (nonce,selected,_)=ConversationChannelCodec.parseDeliveryRequest(request,current)
                    duringContent()
                    ConversationChannelCodec.deliveryReply(current,nonce,byteArrayOf(1)).also {assertEquals(scope,selected)}
                } else {
                    val close=ConversationChannelCodec.parseCloseRequest(request,current)
                    ConversationChannelCodec.closeReply(ConversationClosureReply(current,close.challenge,close.scope,closeAck))
                }
                return ConversationAuthenticatedWire.Reply(current,bytes)
            }
        }
        assembly=ConversationAuthenticatedRuntime(db.journal(),sendDb.sends(),verifier,protection,wire,{duringElapsed();elapsed},
            { selected,utc -> duringAuthority();check(selected==scope && utc in 100000 until authorityUntil && permission && consent) },
            {check(it==scope);decisions++}, {exchanges++;duringInstall();byteArrayOf(2)},worker,delivery)
        assembly.presentation.observe {snapshots.add(it)}
        delivery.drain()
    }
    @After fun cleanup() {db.close();sendDb.close()}
    private fun drain() {worker.drain();delivery.drain()}
    private fun propose() {assembly.propose(review,byteArrayOf(1));drain()}
    private fun activate() {propose();val value=snapshots.last();assembly.presentation.approvePhoneReview(review.requestId,value.version);drain();assertTrue(assembly.captureEligible())}
    private fun activateLongLease() {leaseDuration=60000;authorityUntil=200000;activate()}
    private fun maintain():Boolean? {var result:Boolean?=null;assembly.maintainAuthenticatedTime(scope){result=it};drain();return result}
    @Test fun genuineMaintenanceBeforeOldBoundaryPreservesOriginalAdmissionDeadline() {
        activateLongLease();val deadline=assembly.executionDeadline(scope)
        elapsed=20000;assertEquals(true,maintain())
        assertEquals(deadline,assembly.executionDeadline(scope));assertEquals(1,decisions);assertEquals(1,exchanges)
        elapsed=40000;assertEquals(true,maintain());assertTrue(assembly.captureEligible())
        elapsed=60000;assertFalse(assembly.captureEligible());assertEquals(false,maintain())
        assertEquals(1,decisions);assertEquals(1,exchanges);assertEquals(0,captureReplies)
    }
    @Test fun oldAnchorExpiryDuringGenuineRefreshCannotBeRevivedByFreshInstalledTime() {
        activateLongLease();elapsed=29900;duringTime={elapsed=30100}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
        assertEquals(ConversationStopReason.LEASE_EXPIRED,snapshots.last().stopReason)
        assertEquals(0,db.journal().contentCount());assertEquals(0,captureReplies)
    }
    @Test fun originalAnchorDeadlineEqualityRefusesEvenWithValidReply() {
        activateLongLease();elapsed=29900;duringTime={elapsed=30000}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
    }
    @Test fun finalAuthorityWaitCannotSpendOldDeadlineOrPromoteFirstReceiptFromNewClock() {
        activateLongLease();elapsed=29900;var sampled=false;var refreshed=false
        duringTime={refreshed=true}
        duringAuthority={
            if(refreshed && !sampled) {
                elapsed=30000
                sampled=true
                val boundary=assembly.firstReceiptBoundary()
                assertEquals(ConversationObservation.DISCARDED,assembly.observeAtBoundary(boundary,
                    "55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
            }
        }
        assertEquals(false,maintain());assertTrue(sampled);assertFalse(assembly.captureEligible())
        assertEquals(0,db.journal().contentCount())
    }
    @Test fun queuedMaintenanceAfterOldAgeExpiresNeverStartsTimeExchange() {
        activateLongLease();var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it};elapsed=30000;drain()
        assertEquals(false,result);assertEquals(1,timeReplies);assertFalse(assembly.captureEligible())
    }
    @Test fun maintenanceWrongAuthenticatedNonceClosesExistingAdmission() {
        activateLongLease();elapsed=10000;tamperTime=true
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
        assertEquals(1,decisions);assertEquals(1,exchanges)
    }
    @Test fun lifecycleDuringMaintenanceCannotPublishLateSuccess() {
        activateLongLease();elapsed=10000;duringTime={assembly.lifecycleLost(ConversationStopReason.USER_STOP)}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
    }
    @Test fun sessionRotationDuringMaintenanceCannotPublishLateSuccess() {
        activateLongLease();elapsed=10000;duringTime={session=phone.copy(connectionEpoch=2)}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
    }
    @Test fun lostAuthorityDuringMaintenanceCannotReopenExistingScope() {
        activateLongLease();elapsed=10000;duringTime={consent=false}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible());assertEquals(0,captureReplies)
    }
    @Test fun overlappingMaintenanceHasOnlyOneExchangeAndNoReplacementRequest() {
        activateLongLease();elapsed=10000;var first:Boolean?=null;var second:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){first=it};assembly.maintainAuthenticatedTime(scope){second=it}
        drain();assertEquals(true,first);assertEquals(false,second);assertEquals(2,timeReplies)
    }
    @Test fun serialDiscardRetainsOnePendingUntilOwnerEpochRetirementWithoutFakeCompletion() {
        activateLongLease();var first:Boolean?=null;var second:Boolean?=null
        duringAuthority={throw AssertionError("Synthetic preceding worker failure")}
        assembly.presentation.refresh();assembly.maintainAuthenticatedTime(scope){first=it}
        assertThrows(AssertionError::class.java){worker.drain()}
        duringAuthority={};assembly.maintainAuthenticatedTime(scope){second=it};delivery.drain()
        assertNull(first);assertEquals(false,second);assertEquals(1,timeReplies)
        assembly.lifecycleLost(ConversationStopReason.WORKER_SHUTDOWN);drain()
        assertFalse(assembly.captureEligible());assertNull(first)
    }
    @Test fun closeBeforeQueuedMaintenanceRunsRefusesWithoutTimeExchange() {
        activateLongLease();var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it}
        assembly.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST);drain()
        assertEquals(false,result);assertEquals(1,timeReplies);assertFalse(assembly.captureEligible())
    }
    @Test fun monotonicRegressionDuringRefreshRefusesRatherThanWrappingOldDeadline() {
        activateLongLease();elapsed=10000;duringTime={elapsed=9999}
        assertEquals(false,maintain());assertFalse(assembly.captureEligible())
    }
    @Test fun initialProposalWithoutRepresentableConservativeDeadlineRefusesInstallation() {
        elapsed=Long.MAX_VALUE-100;propose()
        assertFalse(assembly.captureEligible());assertNull(db.journal().installation());assertEquals(0,timeReplies)
    }
    @Test fun separateAuthenticatedClockCannotRefreshThisRuntimeWitness() {
        activateLongLease();elapsed=29000
        val other=ConversationTrustedClock({elapsed},{session});val request=other.beginRequest()
        other.installAuthenticatedReply(request.challenge,phone,129000)
        elapsed=30000;assertNotNull(other.nowMs());assertEquals(false,maintain())
        assertEquals(1,timeReplies);assertFalse(assembly.captureEligible())
    }
    @Test fun delayedDeliveryBeyondRefreshedWitnessCannotPublishSuccess() {
        activateLongLease();elapsed=10000;var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it};worker.drain()
        elapsed=40000;delivery.drain();assertEquals(false,result);assertFalse(assembly.captureEligible());drain()
    }
    @Test fun wireSessionRotationAfterWorkerSuccessRefusesDelayedMaintenanceCompletion() {
        activateLongLease();elapsed=10000;var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it};worker.drain()
        session=phone.copy(connectionEpoch=2)
        delivery.drain();assertEquals(false,result);assertFalse(assembly.captureEligible());drain()
        assertEquals(1,decisions);assertEquals(1,exchanges);assertEquals(2,timeReplies)
    }
    @Test fun wireSessionRotationAtLastDeliverySampleRefusesMaintenanceCompletion() {
        activateLongLease();elapsed=10000;var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it};worker.drain()
        var samples=0
        duringElapsed={if(++samples==2){duringElapsed={};session=phone.copy(connectionEpoch=2)}}
        delivery.drain();duringElapsed={}
        assertEquals(2,samples);assertEquals(false,result);assertFalse(assembly.captureEligible());drain()
        assertEquals(1,decisions);assertEquals(1,exchanges);assertEquals(2,timeReplies)
    }
    @Test fun rejectedMaintenanceDeliveryClosesWithoutInventingCompletion() {
        activateLongLease();elapsed=10000;var result:Boolean?=null
        delivery.beforeSubmit={throw java.util.concurrent.RejectedExecutionException()}
        assembly.maintainAuthenticatedTime(scope){result=it};worker.drain()
        assertNull(result);assertFalse(assembly.captureEligible());delivery.beforeSubmit={};drain()
    }
    @Test fun throwingCompletionCannotRetainReservationOrRetryPreviousExchange() {
        activateLongLease();elapsed=10000
        assembly.maintainAuthenticatedTime(scope){error("Synthetic caller failure")};drain()
        elapsed=20000;assertEquals(true,maintain());assertEquals(3,timeReplies)
    }
    @Test fun lastAuthorityCheckAtOriginalLeaseDeadlineRefusesDespiteFreshAnchor() {
        activateLongLease();elapsed=20000;assertEquals(true,maintain())
        elapsed=40000;assertEquals(true,maintain());elapsed=59000
        var refreshed=false;var checks=0
        duringTime={refreshed=true}
        duringAuthority={if(refreshed && ++checks==4)elapsed=60000}
        assertEquals(false,maintain());assertTrue(checks>=4);assertFalse(assembly.captureEligible())
        assertEquals(ConversationStopReason.LEASE_EXPIRED,snapshots.last().stopReason)
        assertEquals(1,decisions);assertEquals(1,exchanges);assertEquals(0,captureReplies)
    }
    @Test fun deliveryAtOriginalLeaseDeadlineCannotClaimMaintenanceSuccess() {
        activateLongLease();elapsed=20000;assertEquals(true,maintain())
        elapsed=40000;assertEquals(true,maintain());elapsed=59000;var result:Boolean?=null
        assembly.maintainAuthenticatedTime(scope){result=it};worker.drain()
        elapsed=60000;delivery.drain();assertEquals(false,result);assertFalse(assembly.captureEligible());drain()
    }
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
    @Test fun verifiedDurableAckReleasesCapacityAndDuplicateRequiresCurrentAuthorityWithoutUpload() {
        activate();val token="55".repeat(32)
        assertEquals(ConversationObservation.CAPTURED,assembly.observeFirstReceipt(token,scope.peer,scope.lineId,1,"synthetic"))
        var accepted:Boolean?=null
        assembly.uploadCapture(token,{_,sequence->assertEquals(1L,sequence);byteArrayOf(1,2,3)}){accepted=it};drain()
        assertEquals(true,accepted);assertEquals(0,db.journal().contentCount());assertEquals(1,db.journal().receiptCount())
        assertNull(db.journal().wireCapture(token)!!.protectedEnvelope)
        assertEquals(Draft02OutboundPreparation.hash(byteArrayOf(1,2,3)),db.journal().wireCapture(token)!!.acknowledgedDigest)
        assembly.uploadCapture(token,{_,_->error("Already acknowledged must not seal or upload")}){accepted=it};drain()
        assertEquals(true,accepted);assertEquals(1,captureReplies)
        assertEquals(ConversationObservation.DUPLICATE,assembly.observeFirstReceipt(token,scope.peer,scope.lineId,1,"synthetic"))
        consent=false
        assembly.uploadCapture(token,{_,_->error("Revoked must not seal or upload")}){accepted=it};drain()
        assertEquals(false,accepted);assertEquals(1,captureReplies)
    }
    @Test fun malformedAckAndUncertainUploadKeepExactPacketForAuthenticatedCreatedFalseRetry() {
        activate();val token="55".repeat(32)
        assembly.observeFirstReceipt(token,scope.peer,scope.lineId,1,"synthetic")
        var accepted:Boolean?=null;var seals=0
        val mutations:List<(ByteArray)->ByteArray> = listOf(
            {it.copyOf(it.size-1)},
            {it.copyOf().apply {this[102]=(this[102].toInt() xor 1).toByte()}},
            {it.copyOf().apply {this[118]=(this[118].toInt() xor 1).toByte()}},
            {it.copyOf().apply {this[134]=(this[134].toInt() xor 1).toByte()}},
            {it.copyOf().apply {this[166]=2}},
            {throw IllegalStateException("Synthetic lost ACK")})
        for(alter in mutations) {
            alterCaptureReply=alter
            assembly.uploadCapture(token,{_,_->seals++;byteArrayOf(1,2,3)}){accepted=it};drain()
            assertEquals(false,accepted);assertEquals(1,db.journal().contentCount())
            assertNotNull(db.journal().wireCapture(token)!!.protectedEnvelope)
            assertNull(db.journal().wireCapture(token)!!.acknowledgedDigest)
        }
        alterCaptureReply={it};captureCreated=false
        assembly.uploadCapture(token,{_,_->error("Retry must reuse exact committed packet")}){accepted=it};drain()
        assertEquals(true,accepted);assertEquals(1,seals);assertEquals(0,db.journal().contentCount())
    }
    @Test fun withdrawalDuringAuthenticatedCaptureReplyCannotCommitAckOrClearContent() {
        activate();val token="55".repeat(32)
        assembly.observeFirstReceipt(token,scope.peer,scope.lineId,1,"synthetic")
        duringContent={consent=false}
        var accepted:Boolean?=null
        assembly.uploadCapture(token,{_,_->byteArrayOf(1)}){accepted=it};drain()
        assertEquals(false,accepted);assertEquals(1,db.journal().contentCount())
        assertNotNull(db.journal().wireCapture(token)!!.protectedEnvelope)
        assertNull(db.journal().wireCapture(token)!!.acknowledgedDigest)
    }
    @Test fun stopClosesAdmissionWhileCaptureReplyIsHeldAndLateAckCannotSucceed() {
        activate()
        val token="55".repeat(32)
        assertEquals(ConversationObservation.CAPTURED,assembly.observeFirstReceipt(token,scope.peer,scope.lineId,1,"synthetic"))
        heldContentCannotDelayStop {done->assembly.uploadCapture(token,{_,_->byteArrayOf(1)},done)}
        assertEquals(1,db.journal().contentCount())
        assertNull(db.journal().wireCapture(token)!!.acknowledgedDigest)
    }
    @Test fun stopClosesAdmissionWhileDeliveryReplyIsHeldAndLatePacketCannotEnterJournal() {
        activate()
        val sender=assembly.confirmedSender(object:ConversationSendVerifier {
            override fun verify(evidence:ByteArray):VerifiedConversationSend=error("Late packet must not be verified")
        },object:ConversationSendTransport {
            override fun submit(message:String,attempt:String,scope:ConversationCaptureScope,body:String):ConversationSubmission=error("No dispatch")
        })
        val message=id()
        heldContentCannotDelayStop {done->assembly.receiveConfirmed(scope,message,sender,done)}
        assertNull(sendDb.sends().receipt(message))
    }
    private fun heldContentCannotDelayStop(begin:((Boolean)->Unit)->Unit) {
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        duringContent={entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS))}
        var accepted:Boolean?=null
        begin {accepted=it}
        val pool=java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val upload=pool.submit {worker.drain()}
            assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            pool.submit {assembly.lifecycleLost(ConversationStopReason.USER_STOP)}.get(1,java.util.concurrent.TimeUnit.SECONDS)
            assertFalse(assembly.captureEligible())
            release.countDown();upload.get(2,java.util.concurrent.TimeUnit.SECONDS);delivery.drain()
            assertEquals(false,accepted)
        } finally {release.countDown();pool.shutdownNow()}
    }
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
    @Test fun serviceIngressIsDisabledByDefault() {
        activate()
        val ingress=ConversationServiceIngress(assembly,{null})
        assertEquals(ConversationObservation.DISCARDED,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        assertEquals(0,db.journal().contentCount())
    }
    @Test fun servicePauseClosesBeforeReturningAndCannotResumeThisInstance() {
        activate()
        val ingress=ConversationServiceIngress(assembly,{null},enabled=true)
        ingress.pause(ConversationStopReason.USER_STOP)
        assertFalse(assembly.captureEligible())
        assertEquals(ConversationObservation.DISCARDED,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        drain();assertEquals(ConversationCloseOutcome.DURABLY_CLOSED,snapshots.last().close)
    }
    @Test fun serviceSampledPermissionLossClosesAndDiscardsBeforeStorage() {
        activate()
        val ingress=ConversationServiceIngress(assembly,{ConversationStopReason.PERMISSION_LOST},enabled=true)
        assertEquals(ConversationObservation.DISCARDED,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        assertFalse(assembly.captureEligible());assertEquals(0,db.journal().contentCount())
        drain();assertEquals(ConversationStopReason.PERMISSION_LOST,snapshots.last().stopReason)
    }
    @Test fun serviceAuthoritySamplingFailureFailsClosed() {
        activate()
        val ingress=ConversationServiceIngress(assembly,{error("authority unavailable")},enabled=true)
        assertEquals(ConversationObservation.DISCARDED,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        assertFalse(assembly.captureEligible());assertEquals(0,db.journal().contentCount())
    }
    @Test fun serviceIngressRetainsRuntimeDuplicateAndExpiryFences() {
        activate()
        val ingress=ConversationServiceIngress(assembly,{null},enabled=true)
        assertEquals(ConversationObservation.CAPTURED,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        assertEquals(ConversationObservation.DUPLICATE,ingress.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        elapsed=10001
        assertEquals(ConversationObservation.DISCARDED,ingress.observeFirstReceipt("66".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
        assertEquals(1,db.journal().contentCount())
    }

    @Test fun normalMountDefaultsDisabledAndCannotEnableFromReceipt() {
        activate();val mount=ConversationRuntimeMount()
        assertFalse(mount.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null}))
        assertNull(mount.firstReceipt())
        assertEquals(ConversationObservation.DISCARDED,mount.receive(null,1,"55".repeat(32),scope.peer,"synthetic"))
        assertEquals(0,db.journal().contentCount())
    }
    @Test fun queuedPreApprovalReceiptCannotBecomeEligibleAfterPhoneApproval() {
        propose();val mount=ConversationRuntimeMount()
        assertTrue(mount.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null},enabled=true))
        val old=mount.firstReceipt()
        assembly.presentation.approvePhoneReview(review.requestId,snapshots.last().version);drain()
        assertTrue(assembly.captureEligible())
        assertEquals(ConversationObservation.DISCARDED,mount.receive(old,1,"55".repeat(32),scope.peer,"synthetic"))
        assertEquals(0,db.journal().contentCount())
        assertEquals(ConversationObservation.CAPTURED,mount.receive(mount.firstReceipt(),1,"66".repeat(32),scope.peer,"synthetic"))
    }
    @Test fun normalMountPauseFencesQueuedReceiptAndRequiresNewMount() {
        activate();val mount=ConversationRuntimeMount()
        assertTrue(mount.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null},enabled=true))
        val receipt=mount.firstReceipt();mount.pause(ConversationStopReason.USER_STOP)
        assertFalse(assembly.captureEligible());assertNull(mount.firstReceipt())
        assertEquals(ConversationObservation.DISCARDED,mount.receive(receipt,1,"55".repeat(32),scope.peer,"synthetic"))
        drain();assertEquals(ConversationCloseOutcome.DURABLY_CLOSED,snapshots.last().close)
    }

    @Test fun receiptDoesNotWaitForMountInstallationOrInheritIt() {
        activate();val mount=ConversationRuntimeMount()
        val finished=java.util.concurrent.CountDownLatch(1)
        val receipt=java.util.concurrent.atomic.AtomicReference<ConversationRuntimeMount.Receipt>()
        val receiver=Thread {try {receipt.set(mount.firstReceipt())} finally {finished.countDown()}}
        try {
            synchronized(mount) {
                receiver.start()
                assertTrue("Receipt snapshot cannot wait behind installation/storage monitor",
                    finished.await(2,java.util.concurrent.TimeUnit.SECONDS))
                assertTrue(mount.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null},enabled=true))
            }
            assertNull(receipt.get())
            assertEquals(ConversationObservation.DISCARDED,mount.receive(receipt.get(),1,"55".repeat(32),scope.peer,"synthetic"))
            assertEquals(ConversationObservation.CAPTURED,mount.receive(mount.firstReceipt(),1,"66".repeat(32),scope.peer,"synthetic"))
        } finally {receiver.join(3000)}
    }
    @Test fun normalMountRequiresObservedSubscriptionAndCurrentLine() {
        activate();val mount=ConversationRuntimeMount()
        mount.install(assembly,{if(it==7) ConversationRuntimeMount.ObservedLine(scope.lineId,1) else null},{null},enabled=true)
        val receipt=mount.firstReceipt()
        assertEquals(ConversationObservation.DISCARDED,mount.receive(receipt,null,"55".repeat(32),scope.peer,"synthetic"))
        assertEquals(ConversationObservation.DUPLICATE,mount.receive(receipt,8,"55".repeat(32),scope.peer,"synthetic"))
        assertEquals(ConversationObservation.DUPLICATE,mount.receive(receipt,7,"55".repeat(32),scope.peer,"synthetic"))
        assertEquals(ConversationObservation.CAPTURED,mount.receive(mount.firstReceipt(),7,"66".repeat(32),scope.peer,"synthetic"))
    }

    @Test fun observedLineSamplerFailureClosesMountedAdmission() {
        activate();val mount=ConversationRuntimeMount()
        mount.install(assembly,{error("mapping unavailable")},{null},enabled=true)
        assertEquals(ConversationObservation.DISCARDED,mount.receive(mount.firstReceipt(),1,"55".repeat(32),scope.peer,"synthetic"))
        assertFalse(assembly.captureEligible());assertNull(mount.firstReceipt());assertEquals(0,db.journal().contentCount())
    }

    @Test fun bothOrdinaryServicePauseRoutesCloseTheSharedMountBeforeReturning() {
        activate()
        for (type in listOf(GatewayService::class.java,AuthenticatedGatewayService::class.java)) {
            val global=ConversationProcessMount.runtime
            assertTrue(global.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null},enabled=true))
            val service=org.robolectric.Robolectric.buildService(type).create()
            val action=if(type==GatewayService::class.java) GatewayService.ACTION_PAUSE else AuthenticatedGatewayService.ACTION_PAUSE
            service.get().onStartCommand(android.content.Intent().setAction(action),0,1)
            assertNull(global.firstReceipt());assertFalse(assembly.captureEligible())
            service.destroy()
        }
        drain()
    }

    @Test fun preTokenOrStorageFailureClosesBeforeOuterReceiverSwallowsIt() {
        activate();val mount=ConversationRuntimeMount()
        mount.install(assembly,{ConversationRuntimeMount.ObservedLine(scope.lineId,1)},{null},enabled=true)
        assertThrows(IllegalStateException::class.java){mount.prepareAndReceive { error("fixture vault unavailable before receipt token") }}
        assertNull(mount.firstReceipt());assertFalse(assembly.captureEligible());assertEquals(0,db.journal().contentCount())
    }

    @Test fun socketGracefulOrFailureLifecycleClosesAdmissionSynchronously() {
        activate()
        val socket=object:okhttp3.WebSocket {
            override fun request()=okhttp3.Request.Builder().url("https://example.org").build()
            override fun queueSize()=0L
            override fun send(text:String)=false
            override fun send(bytes:okio.ByteString)=false
            override fun close(code:Int,reason:String?)=true
            override fun cancel()=Unit
        }
        val wire=ConversationSocketWire(socket,{session})
        val lifecycle=ConversationSocketLifecycle(wire,{session=null},{assembly.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST)})
        lifecycle.lost();lifecycle.lost()
        assertNull(session);assertNull(wire.currentSession());assertFalse(assembly.captureEligible())
        assertEquals(ConversationObservation.DISCARDED,assembly.observeFirstReceipt("55".repeat(32),scope.peer,scope.lineId,1,"synthetic"))
    }
}
