// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import androidx.room.Room
import java.util.UUID
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationProductionBoundaryTest {
    private val scope=ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private val phone=SealedDispatchExecutor.Session(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),1,1,UUID.randomUUID(),"55".repeat(32))
    private var current:ConversationExecutionAuthority?=ConversationExecutionAuthority(scope,ConversationPhoneSession.from(phone),true,true,true,true,true)
    private var elapsed=100L
    private val clock=ConversationTrustedClock({elapsed},{current?.phoneSession})
    private lateinit var capture:ConversationCaptureDatabase
    private lateinit var sends:ConversationSendDatabase
    private lateinit var dispatch:SmsJournalDatabase
    private lateinit var admission:ConversationCaptureAdmission
    private lateinit var hooks:ConversationLifecycleHooks
    private lateinit var recoveryPolicy:ConversationFreshReviewRecovery
    private lateinit var execution:ConversationExecutionBoundary
    private var remoteCloseCalls=0;private var remoteCloseFails=false
    private var preparationCalls=0
    private var leaseChecks=0
    private var duringLeaseVerification:()->Unit = {}
    private var presentationClockFails=false
    private lateinit var initialChallenge:String
    private val protection=object:ConversationJournalProtection {
        // State-boundary fixture only; production protection remains mandatory encrypted custody.
        override fun seal(value:String,aad:String)=InboundVault.Sealed(value.toByteArray(),byteArrayOf(1))
        override fun open(value:InboundVault.Sealed,aad:String)=value.ciphertext.toString(Charsets.UTF_8)
    }
    @Before fun setup(){
        val context=RuntimeEnvironment.getApplication()
        capture=Room.inMemoryDatabaseBuilder(context,ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        sends=Room.inMemoryDatabaseBuilder(context,ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        dispatch=Room.inMemoryDatabaseBuilder(context,SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        val verifier=object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray)=scope
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray):Long {leaseChecks++;duringLeaseVerification();return 60000L}
        }
        admission=ConversationCaptureAdmission(capture.journal(),verifier,protection,{elapsed},{check(it==scope)})
        recoveryPolicy=ConversationFreshReviewRecovery(capture.journal(),admission,verifier){check(it==scope)}
        admission.prepare(byteArrayOf(1),true);val recovery=admission.beginRecovery();initialChallenge=recovery.challenge;admission.completeRecovery(recovery.challenge,byteArrayOf(1))
        val time=clock.beginRequest();clock.installAuthenticatedReply(time.challenge,time.session,100000)
        hooks=ConversationLifecycleHooks(admission,sends.sends(),clock,recoveryPolicy){check(it==scope);remoteCloseCalls++;if(remoteCloseFails)throw java.io.IOException("fixture closure uncertain")}
        execution=ConversationExecutionBoundary(admission,clock,{current},dispatch,DevicePayloadKeyStore("fixture-unused")){preparationCalls++;null}
    }
    @After fun cleanup(){capture.close();sends.close();dispatch.close()}
    private fun prepare(generation:Long=1,version:Long=2,digest:String=scope.activationDigest):SealedDispatchExecutor.Outcome {
        val grant=SealedExecutionGrantValidator.Fields(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.fromString(scope.lineId),UUID.randomUUID(),UUID.randomUUID(),1,ByteArray(32),110000,1,1,ByteArray(32),1,1,1,ByteArray(32))
        val local=SealedDispatchExecutor.Local(LocalLineBinding(accountId=scope.accountId,deviceId=scope.deviceId,lineId=scope.lineId,generation=1,subscriptionId=1,installedAtMs=1,cardId=1),ByteArray(32),generation,version,digest,"44".repeat(32))
        return execution.prepare(scope,grant,byteArrayOf(1),phone,local)
    }
    @Test fun absentPermissionCannotReachExistingExecutorPreparation(){current=current!!.copy(sendPermission=false);assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls);assertEquals(0,dispatch.sealedPreparations().count())}
    private fun presentationDomain(exchange:(ConversationRecoveryRequest)->ByteArray = {byteArrayOf(1)}):ConversationJournalPresentationDomain {
        capture.close() // Separate fresh journal fixture: never reopen a durably closed interval.
        capture=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val verifier=object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray)=scope
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray):Long {duringLeaseVerification();return 60000L}
        }
        admission=ConversationCaptureAdmission(capture.journal(),verifier,protection,{elapsed},{check(it==scope)})
        recoveryPolicy=ConversationFreshReviewRecovery(capture.journal(),admission,verifier){check(it==scope)}
        hooks=ConversationLifecycleHooks(admission,sends.sends(),clock,recoveryPolicy){check(it==scope);remoteCloseCalls++}
        return ConversationJournalPresentationDomain(admission,recoveryPolicy,hooks,verifier,{check(!presentationClockFails);elapsed},exchange)
    }
    private fun phoneReview()=ConversationPhoneReview(id(),scope.intervalId,scope.lineId,1,scope.peer,
        ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",
        Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()),1000)
    @Test fun runtimeIntegratesPhoneReviewProtectedJournalInstallAndDurableStop() {
        val domain=presentationDomain();val review=phoneReview();domain.propose(review,byteArrayOf(1))
        assertFalse(admission.captureEligible());assertEquals(ConversationPresentationPhase.AWAITING_PHONE_REVIEW,domain.sample().phase)
        domain.approve(review){true};assertTrue(admission.captureEligible())
        assertEquals("installed",capture.journal().installation()!!.state)
        assertEquals(ConversationPresentationPhase.CONFIRMED_ACTIVE,domain.sample().phase)
        domain.disableAdmission();assertFalse(admission.captureEligible())
        assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,domain.stop(scope.intervalId).phase)
        assertEquals("closed",capture.journal().installation()!!.state);assertEquals(1,remoteCloseCalls)
    }
    @Test fun cancelledInstallResponseNeverOpensCapture() {
        var accepted=true;val domain=presentationDomain {accepted=false;byteArrayOf(1)};val review=phoneReview()
        domain.propose(review,byteArrayOf(1))
        assertThrows(IllegalStateException::class.java){domain.approve(review){accepted}}
        assertFalse(admission.captureEligible());assertEquals("prepared",capture.journal().installation()!!.state)
    }
    @Test fun noCaptureWhileServerAcceptancePending() {
        val domain=presentationDomain {assertFalse(admission.captureEligible());assertEquals("prepared",capture.journal().installation()!!.state);byteArrayOf(1)}
        val review=phoneReview();domain.propose(review,byteArrayOf(1));domain.approve(review){true};assertTrue(admission.captureEligible())
    }
    @Test fun freshCountdownCanApproveActualJournal() {
        val domain=presentationDomain();domain.propose(phoneReview(),byteArrayOf(1));elapsed++
        domain.approve(domain.sample().review!!){true};assertTrue(admission.captureEligible())
    }
    @Test fun activeScopeCannotBeSilentlyReplaced() {
        val domain=presentationDomain();val review=phoneReview();domain.propose(review,byteArrayOf(1));domain.approve(review){true}
        assertThrows(IllegalStateException::class.java){domain.propose(phoneReview(),byteArrayOf(1))}
        assertTrue(admission.captureEligible())
    }
    @Test fun reviewExpiryDuringFinalInstallCannotLeaveAdmissionOpen() {
        val domain=presentationDomain();val review=phoneReview();domain.propose(review,byteArrayOf(1))
        duringLeaseVerification={elapsed+=1001}
        assertThrows(IllegalStateException::class.java){domain.approve(review){true}}
        assertFalse(admission.captureEligible())
        assertEquals("installed",capture.journal().installation()!!.state) // Durable installed never means active.
    }
    @Test fun displayedDisclosureMustMatchVerifiedConsentScope() {
        val verifier=object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray)=scope.copy(disclosureDigest="99".repeat(32))
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L
        }
        val domain=ConversationJournalPresentationDomain(admission,recoveryPolicy,hooks,verifier,{elapsed}){byteArrayOf(1)}
        assertThrows(IllegalArgumentException::class.java){domain.propose(phoneReview(),byteArrayOf(1))}
        assertFalse(admission.captureEligible())
    }
    @Test fun throwingFinalClockDisablesInstalledAdmissionBeforeReturning() {
        val domain=presentationDomain();val review=phoneReview();domain.propose(review,byteArrayOf(1))
        duringLeaseVerification={presentationClockFails=true}
        assertThrows(IllegalStateException::class.java){domain.approve(review){true}}
        assertFalse(admission.captureEligible());assertEquals("installed",capture.journal().installation()!!.state)
    }
    @Test fun receivePermissionLossCannotPrepare(){current=current!!.copy(receivePermission=false);assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun ownerLogoutCannotPrepare(){current=current!!.copy(ownerSessionLive=false);assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun withdrawnContentConsentCannotPrepare(){current=current!!.copy(contentConsentLive=false);assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun changedSimCannotPrepare(){current=current!!.copy(selectedLineCurrent=false);assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun changedPhoneSessionCannotPrepare(){current=current!!.copy(phoneSession=current!!.phoneSession.copy(session=UUID.randomUUID()));assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun expiredTimeCannotPrepare(){elapsed+=30000;assertSame(SealedDispatchExecutor.Unavailable,prepare());assertEquals(0,preparationCalls)}
    @Test fun everyLifecycleReasonClosesSameCaptureAndClock(){for(reason in ConversationStopReason.entries){val state=hooks.stop(scope,reason);assertEquals(ConversationCloseOutcome.DURABLY_CLOSED,state.close);assertEquals(reason,state.stopReason);assertFalse(admission.captureEligible());assertNull(clock.nowMs());assertEquals("closed",capture.journal().installation()!!.state)}}
    @Test fun durableCloseFailureDisablesWithoutClaimingClosed(){capture.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON");val state=hooks.stop(scope,ConversationStopReason.USER_STOP);assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,state.close);assertEquals(ConversationPresentationPhase.FAILURE,state.phase);assertFalse(admission.captureEligible());assertNull(clock.nowMs());assertFalse(state.canStop);assertEquals(1,remoteCloseCalls)}
    @Test fun sendJournalCloseFailureStillDisablesReceiver(){sends.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON");val state=hooks.stop(scope,ConversationStopReason.WITHDRAWAL);assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,state.close);assertEquals("closed",capture.journal().installation()!!.state);assertFalse(admission.captureEligible())}
    @Test fun malformedEnvelopeNeverBecomesHardwarePreparation(){assertTrue(prepare() is SealedDispatchExecutor.Refused);assertEquals(0,preparationCalls);assertEquals(0,dispatch.sealedPreparations().count())}
    @Test fun newLifecycleInstanceNeverClaimsRecoveredActive(){assertEquals(ConversationPresentationPhase.UNAVAILABLE,hooks.snapshot().phase);assertFalse(hooks.snapshot().canStop)}
    @Test fun changedRootGenerationRefusesBeforeEnvelopeParsing(){assertSame(SealedDispatchExecutor.Unavailable,prepare(generation=2));assertEquals(0,preparationCalls)}
    @Test fun manifestBelowActivationFloorRefuses(){assertSame(SealedDispatchExecutor.Unavailable,prepare(version=1));assertEquals(0,preparationCalls)}
    @Test fun sameVersionChangedManifestRefuses(){assertSame(SealedDispatchExecutor.Unavailable,prepare(digest="66".repeat(32)));assertEquals(0,preparationCalls)}
    @Test fun benignManifestRenewalCanReachExistingEnvelopeParser(){assertTrue(prepare(version=3) is SealedDispatchExecutor.Refused)}
    @Test fun coldLoadedInstalledRowCannotAutoRecover(){val cold=ConversationFreshReviewRecovery(capture.journal(),admission,object:ConversationActivationVerifier{override fun verifiedPreparation(evidence:ByteArray)=scope;override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L}){};assertFalse(admission.captureEligible());assertThrows(IllegalStateException::class.java){cold.beginRecovery()};assertThrows(IllegalStateException::class.java){cold.approveFreshReview(byteArrayOf(1))}}
    @Test fun explicitFreshPhoneDecisionAllowsSameProcessRecovery(){recoveryPolicy.approveFreshReview(byteArrayOf(1));val request=recoveryPolicy.beginRecovery();recoveryPolicy.completeRecovery(request.challenge,byteArrayOf(1));assertTrue(admission.captureEligible())}
    @Test fun failedCloseCannotUseRecoveryAsErrorShortcut(){capture.openHelper.writableDatabase.execSQL("PRAGMA query_only=ON");hooks.stop(scope,ConversationStopReason.USER_STOP);assertThrows(IllegalStateException::class.java){recoveryPolicy.beginRecovery()};assertThrows(IllegalStateException::class.java){recoveryPolicy.approveFreshReview(byteArrayOf(1))};assertFalse(admission.captureEligible())}
    @Test fun constructorStorageFailureClearsAcceptedLeaseBeforeReading(){
        assertTrue(admission.captureEligible());val checks=leaseChecks;capture.close()
        assertThrows(IllegalStateException::class.java){ConversationFreshReviewRecovery(capture.journal(),admission,object:ConversationActivationVerifier{override fun verifiedPreparation(evidence:ByteArray)=scope;override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L}){}}
        assertThrows(IllegalStateException::class.java){admission.completeRecovery(initialChallenge,byteArrayOf(1))}
        assertEquals(checks,leaseChecks)
    }
    @Test fun uncertainServerCloseCannotPublishDurableSuccess(){remoteCloseFails=true;val state=hooks.stop(scope,ConversationStopReason.USER_STOP);assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,state.close);assertEquals(ConversationPresentationFailure.AUTHORITY_UNAVAILABLE,state.failure);assertFalse(admission.captureEligible());assertNull(clock.nowMs());assertEquals("closed",capture.journal().installation()!!.state);assertThrows(IllegalStateException::class.java){recoveryPolicy.beginRecovery()}}
    private fun holder(chars:CharArray)=FixtureHolder(chars)
    private class FixtureHolder(private val chars:CharArray) {
        fun consume(consumer:(CharArray)->Unit){try{consumer(chars)}finally{chars.fill('\u0000')}}
        fun close(){chars.fill('\u0000')}
    }
    @Test fun delayedPreparedConsumeAfterCloseCannotExposeText(){val chars="fixture".toCharArray();val ready=execution.consumptionFence(scope,ConversationPhoneSession.from(phone),{chars.fill('\u0000')});hooks.stop(scope,ConversationStopReason.USER_STOP);var calls=0;assertThrows(IllegalStateException::class.java){ready.consume(holder(chars)::consume){calls++}};assertEquals(0,calls);assertTrue(chars.all{it=='\u0000'})}
    @Test fun preparedWrapperCannotConsumeTwice(){val ready=execution.consumptionFence(scope,ConversationPhoneSession.from(phone),{});var calls=0;ready.consume(holder("fixture".toCharArray())::consume){calls++};assertThrows(IllegalStateException::class.java){ready.consume(holder("fixture".toCharArray())::consume){calls++}};assertEquals(1,calls)}
    @Test fun pauseAndPreparedConsumerShareOneMonitor(){
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        val pool=java.util.concurrent.Executors.newFixedThreadPool(2)
        val chars="fixture".toCharArray();val ready=execution.consumptionFence(scope,ConversationPhoneSession.from(phone),{chars.fill('\u0000')})
        try {
            val consuming=pool.submit{ready.consume(holder(chars)::consume){entered.countDown();check(release.await(2,java.util.concurrent.TimeUnit.SECONDS))}}
            assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            val stopping=pool.submit<ConversationPresentationSnapshot>{hooks.stop(scope,ConversationStopReason.USER_STOP)}
            assertThrows(java.util.concurrent.TimeoutException::class.java){stopping.get(50,java.util.concurrent.TimeUnit.MILLISECONDS)}
            release.countDown();consuming.get(2,java.util.concurrent.TimeUnit.SECONDS)
            assertEquals(ConversationCloseOutcome.DURABLY_CLOSED,stopping.get(2,java.util.concurrent.TimeUnit.SECONDS).close)
            assertTrue(chars.all{it=='\u0000'});assertFalse(admission.captureEligible())
        } finally {release.countDown();pool.shutdownNow()}
    }
    companion object {private fun id()=UUID.randomUUID().toString()}
}
