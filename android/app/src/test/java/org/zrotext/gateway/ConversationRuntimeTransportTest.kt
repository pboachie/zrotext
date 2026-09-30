// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import java.util.concurrent.Executor
import org.junit.Test
import org.junit.Assert.*

class ConversationRuntimeTransportTest {
    private fun id() = UUID.randomUUID().toString()
    private val scope = ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),"11".repeat(32),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private var session: ConversationPhoneSession? = ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),1,1,"55".repeat(32))
    private var elapsed = 100L
    private val clock = ConversationTrustedClock({elapsed},{session})
    private var changeTime: (ConversationTimeReply)->ConversationTimeReply = {it}
    private var changeClose: (ConversationClosureReply)->ConversationClosureReply = {it}
    private val channel = object: ConversationAuthenticatedChannel {
        override fun time(request:ConversationTrustedClock.Request) = changeTime(ConversationTimeReply(request.session,request.challenge,100000))
        override fun close(request:ConversationClosureRequest) = changeClose(ConversationClosureReply(request.session,request.challenge,request.scope,true))
    }
    private val transport = ConversationAuthorityTransport(channel,clock,{session},{elapsed})
    @Test fun authenticatedTimeAndExactDurableClosureAccept() { transport.refreshTime(); assertEquals(100000L,clock.nowMs());transport.close(scope) }
    @Test fun wrongTimeChallengeInvalidatesExistingAnchor() { transport.refreshTime();changeTime={it.copy(challenge=UUID.randomUUID())};assertThrows(IllegalArgumentException::class.java){transport.refreshTime()};assertNull(clock.nowMs()) }
    @Test fun timeSessionLossDuringReplyRejects() {changeTime={session=null;it};assertThrows(IllegalStateException::class.java){transport.refreshTime()};assertNull(clock.nowMs())}
    @Test fun closureMustAcknowledgeDurability() {changeClose={it.copy(durablyClosed=false)};assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun closurePeerSwapRejects() {changeClose={it.copy(scope=scope.copy(peer="+13"))};assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun closureNonceSwapRejects() {changeClose={it.copy(challenge=UUID.randomUUID())};assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun closureSessionChangedAfterWaitRejects() {changeClose={session=session!!.copy(connectionEpoch=2);it};assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun closureLateReplyCannotClaimClosed() {changeClose={elapsed+=5001;it};assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun closureTimeRegressionRejects() {changeClose={elapsed--;it};assertThrows(IllegalStateException::class.java){transport.close(scope)}}

    private class Queue:Executor {val pending=java.util.ArrayDeque<Runnable>();override fun execute(command:Runnable){pending.add(command)};fun drain(){while(pending.isNotEmpty())pending.removeFirst().run()}}
    private val queue = Queue()
    private val delivery = Queue()
    private val review = ConversationPhoneReview(id(),scope.intervalId,scope.lineId,1,"+12",ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()),1000)
    private var sample = ConversationPresentationSnapshot(1,ConversationPresentationPhase.AWAITING_PHONE_REVIEW,review=review)
    private var disabled = false
    private var approvals = 0
    private var declined = 0
    private var stops = 0
    private var duringApproval:()->Unit = {}
    private val admissionGate = Any()
    private var beforeDisable:()->Unit = {}
    private val domain = object:ConversationPresentationDomain {
        override fun sample()=sample
        override fun approve(review:ConversationPhoneReview,stillCurrent:()->Boolean) {synchronized(admissionGate){duringApproval();check(stillCurrent());approvals++;sample=active()}}
        override fun decline(review:ConversationPhoneReview){declined++;sample=ConversationPresentationSnapshot(1,ConversationPresentationPhase.OFF)}
        override fun disableAdmission(){beforeDisable();synchronized(admissionGate){disabled=true}}
        override fun stopForLifecycle(reason:ConversationStopReason) = stop(scope.intervalId).copy(stopReason=reason)
        override fun stop(intervalId:String):ConversationPresentationSnapshot {stops++;transport.close(scope);return ConversationPresentationSnapshot(1,ConversationPresentationPhase.DURABLY_CLOSED,scope.intervalId,scope.lineId,1,close=ConversationCloseOutcome.DURABLY_CLOSED)}
    }
    private val runtime = ConversationPresentationRuntime(queue,delivery,domain)
    private val observations = mutableListOf<ConversationPresentationSnapshot>()
    private fun active()=ConversationPresentationSnapshot(1,ConversationPresentationPhase.CONFIRMED_ACTIVE,scope.intervalId,scope.lineId,1,1000,true)
    private fun reviewed():ConversationPresentationSnapshot {runtime.observe{observations.add(it)};runtime.refresh();queue.drain();delivery.drain();return observations.last()}
    @Test fun duplicateApprovalConsumedOnceAndInstallNeededForActive() {val state=reviewed();runtime.approvePhoneReview(review.requestId,state.version);runtime.approvePhoneReview(review.requestId,state.version);queue.drain();delivery.drain();assertEquals(1,approvals);assertEquals(ConversationPresentationPhase.CONFIRMED_ACTIVE,observations.last().phase)}
    @Test fun expiredReviewRecheckedBeforeApproval() {val state=reviewed();sample=ConversationPresentationSnapshot(1,ConversationPresentationPhase.EXPIRED);runtime.approvePhoneReview(review.requestId,state.version);queue.drain();assertEquals(0,approvals)}
    @Test fun staleVersionCannotApprove() {val state=reviewed();runtime.refresh();queue.drain();runtime.approvePhoneReview(review.requestId,state.version);queue.drain();assertEquals(0,approvals)}
    @Test fun denialPreservesIndependentPairingAndNeverApproves() {val state=reviewed();runtime.declinePhoneReview(review.requestId,state.version);queue.drain();assertEquals(1,declined);assertEquals(0,approvals)}
    @Test fun stopClosesAdmissionBeforeWorkerRunsAndRejectsQueuedActive() {sample=active();val state=reviewed();runtime.refresh();runtime.requestStop(scope.intervalId,state.version);assertTrue(disabled);assertEquals(0,stops);queue.drain();delivery.drain();assertEquals(1,stops);assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,observations.last().phase)}
    @Test fun failedRemoteAckPublishesFailureInsteadOfClosed() {sample=active();val state=reviewed();changeClose={it.copy(durablyClosed=false)};runtime.requestStop(scope.intervalId,state.version);queue.drain();delivery.drain();assertTrue(disabled);assertEquals(ConversationPresentationPhase.FAILURE,observations.last().phase)}
    @Test fun unsubscribeSuppressesQueuedObservations() {val subscription=runtime.observe{observations.add(it)};runtime.refresh();queue.drain();subscription.close();delivery.drain();assertTrue(observations.isEmpty())}
    @Test fun observerExceptionDoesNotBreakOtherObserver() {runtime.observe{error("synthetic")};reviewed();assertEquals(ConversationPresentationPhase.AWAITING_PHONE_REVIEW,observations.last().phase)}
    @Test fun countdownDoesNotChangeReviewDecisionIdentity() {
        val state=reviewed();sample=sample.copy(review=review.copy(remainingMs=999))
        runtime.approvePhoneReview(review.requestId,state.version);queue.drain();assertEquals(1,approvals)
    }
    @Test fun changedPeerCannotConsumeOldReview() {
        val state=reviewed();sample=sample.copy(review=review.copy(peer="+13"))
        runtime.approvePhoneReview(review.requestId,state.version);queue.drain();assertEquals(0,approvals)
    }
    @Test fun stopDuringInstallCancelsWithoutAdmissionRuntimeDeadlock() {
        val state=reviewed()
        val installEntered=java.util.concurrent.CountDownLatch(1)
        val stopAtGate=java.util.concurrent.CountDownLatch(1)
        duringApproval={installEntered.countDown();check(stopAtGate.await(2,java.util.concurrent.TimeUnit.SECONDS))}
        beforeDisable={stopAtGate.countDown()}
        runtime.approvePhoneReview(review.requestId,state.version)
        val pool=java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val install=pool.submit {queue.drain()}
            assertTrue(installEntered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            delivery.drain();val preparing=observations.last()
            assertEquals(ConversationPresentationPhase.PREPARING,preparing.phase)
            val stop=pool.submit {runtime.requestStop(scope.intervalId,preparing.version)}
            install.get(2,java.util.concurrent.TimeUnit.SECONDS);stop.get(2,java.util.concurrent.TimeUnit.SECONDS)
            queue.drain();delivery.drain();assertEquals(0,approvals);assertTrue(disabled)
            assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,observations.last().phase)
        } finally {pool.shutdownNow()}
    }
    @Test fun rejectedStopSubmissionPublishesDisabledClosureFailure() {
        var reject = false
        val executor = Executor { if (reject) throw java.util.concurrent.RejectedExecutionException() else queue.execute(it) }
        val tested = ConversationPresentationRuntime(executor,delivery,domain)
        tested.observe { observations.add(it) }; sample=active(); tested.refresh();queue.drain();delivery.drain()
        val state=observations.last();reject=true
        tested.requestStop(scope.intervalId,state.version);delivery.drain()
        assertTrue(disabled);assertEquals(0,stops)
        assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,observations.last().close)
        tested.refresh();delivery.drain() // Unrelated later rejection preserves a valid failed-close snapshot.
        assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,observations.last().close)
        assertFalse(observations.last().canStop)
    }
    @Test fun rejectedNotificationDoesNotDropLifecycleClosure() {
        val tested=ConversationPresentationRuntime(queue,Executor {throw java.util.concurrent.RejectedExecutionException()},domain)
        tested.observe {};sample=active();tested.refresh();queue.drain()
        tested.lifecycleStop(ConversationStopReason.PHONE_SESSION_LOST);assertTrue(disabled);queue.drain()
        assertEquals(1,stops)
    }
    @Test fun lifecycleClosesSelectedDomainWithoutPublishedIntervalOrUiVersion() {
        runtime.refresh()
        runtime.lifecycleStop(ConversationStopReason.PHONE_SESSION_LOST)
        assertTrue(disabled);queue.drain();delivery.drain()
        assertEquals(1,stops)
    }
}
