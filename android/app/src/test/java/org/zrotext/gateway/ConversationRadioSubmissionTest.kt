// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real typed evidence, guarded consumption, metadata ACK and Room CAS; explicit fixture custody
 * and a fake Android driver. No platform SMS call, user key creation or hardware claim. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34], application=android.app.Application::class)
class ConversationRadioSubmissionTest {
    private class Harness(enabled:Boolean=true):AutoCloseable {
        // Reuse the existing canonical signed manifest/envelope/protected-ZTCR fixture, rather
        // than inventing a body-only transport or a constructible validated-context shortcut.
        private val fixtureClass=Class.forName("org.zrotext.gateway.ConversationExecutionTransportTest\$Fixture")
        private val fixture=fixtureClass.declaredConstructors.first{it.parameterCount==0}.apply{isAccessible=true}.newInstance()
        @Suppress("UNCHECKED_CAST") private fun <T> get(name:String):T =
            fixtureClass.getDeclaredMethod(name).apply{isAccessible=true}.invoke(fixture) as T
        val scope:ConversationCaptureScope=get("getScope")
        val phone:ConversationPhoneSession=get("getSession")
        val local:SealedDispatchExecutor.Local=get("getLocal")
        val sends:ConversationSendDatabase=get("getDb")
        val crypto:ConversationContentCrypto=get("getCrypto")
        val protection:ConversationJournalProtection=get("getProtection")
        val original:ByteArray=get("getOriginal")
        private val holder:Draft02OutboundPreparation.Prepared=get("getPrepared")
        val body:CharArray=get("getPreparedBody")
        val message:String=ConversationContentCrypto.Confirmation.decode(
            ConversationContentCrypto.unpackConfirmedEvidence(original).confirmation).message
        private var elapsed=100L
        var now:Long
            get()=get("getNow")
            set(value){elapsed+=value-now;fixtureClass.getDeclaredMethod("setNow",java.lang.Long.TYPE)
                .apply{isAccessible=true}.invoke(fixture,value)}
        val radio=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        private val capture=Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),ConversationCaptureDatabase::class.java)
            .allowMainThreadQueries().build()
        private val clock=ConversationTrustedClock({elapsed},{phone})
        val admission=ConversationCaptureAdmission(capture.journal(),object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray)=scope
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L
        },protection,{elapsed},{check(it==scope)})
        private val boundary=ConversationExecutionBoundary(admission,clock,{
            ConversationExecutionAuthority(scope,phone,true,true,true,true,true)
        },radio,DevicePayloadKeyStore("fixture-unused")){error("No hardware preparation in this fixture")}
        var metadataCalls=0;var fakeCalls=0;var platformFactories=0;var selections=0
        var permit=true;var lostAck=false;var ambiguous=false
        var ackHook:()->Unit={};var selectedHook:()->Unit={}
        var event:AlphaRadioEvent?=null
        var context:ConversationPreparedSubmissionContext?=null
        private val driver=object:ConversationRadioDriver {
            override fun requireSelected(){selections++;selectedHook()}
            override fun divide(body:String):ArrayList<String> {
                assertEquals("Synthetic reply",body);return arrayListOf(body)
            }
            override fun prepare(attempt:String,parts:ArrayList<String>){assertEquals(1,parts.size)}
            override fun close()=Unit
            override fun send(peer:String,attempt:String,parts:ArrayList<String>) {
                assertEquals(scope.peer,peer)
                assertEquals(AttemptState.RADIO_STARTED,radio.attempts().getAttempt(attempt)?.state)
                fakeCalls++
                if(ambiguous)throw IOException("Synthetic uncertain platform result")
            }
        }
        private val metadataWire=object:ConversationRadioIntentWire {
            override fun submitIntent(session:ConversationPhoneSession,value:AlphaRadioEvent):Boolean {
                assertEquals(phone,session);assertTrue(ConversationRadioIntentOwnership.owns(value))
                assertEquals("claimed",sends.sends().receipt(message)?.state)
                metadataCalls++;event=value;ackHook()
                if(lostAck)throw IOException("Synthetic lost writer ACK")
                return permit
            }
        }
        private fun requireCurrent(value:ConversationPreparedSubmissionContext):Long {
            assertEquals(scope,value.scope);assertEquals(phone,ConversationPhoneSession.from(value.session))
            context=value;check(admission.captureEligible());return now
        }
        private val consumer=ConversationPreparedRadioSubmission(radio.attempts(),metadataWire,::requireCurrent,{
            assertEquals(local.binding,it);platformFactories++
            ConversationRadioPlatform(it,driver,ConversationExistingSuppressionTokens {
                SecretKeySpec(ByteArray(32){9},"HmacSHA256")
            },true)
        },enabled)
        private fun transport():ConversationExecutionTransport {
            val template:ConversationExecutionTransport=get("transport")
            val wire=ConversationExecutionTransport::class.java.getDeclaredField("wire").apply{isAccessible=true}
                .get(template) as ConversationAuthenticatedWire
            return ConversationExecutionTransport(sends.sends(),protection,crypto,wire,{
                ConversationExecutionCurrent(SealedDispatchExecutor.Session(phone.account,phone.device,
                    phone.connectionEpoch,phone.deploymentEpoch,phone.session,phone.originHash),local,now,get("getDeadline"))
            },{selected,fields,_,session,current->
                assertEquals(scope,selected)
                val grant=SealedDispatchExecutor.candidate(fields,session,current)
                val record=SealedPreparationRecord(grant.accountId,grant.messageId,grant.attemptId,
                    grant.unsignedDigest,grant.identity())
                radio.sealedPreparations().reserve(record){assertEquals(local.binding,it)}
                radio.sealedPreparations().finish(record,holder.segmentCount){assertEquals(local.binding,it)}
                SealedDispatchExecutor.Ready(boundary.guardedPrepared(scope,phone,holder))
            },consumer)
        }
        fun sender()=ConversationConfirmedSend(sends.sends(),admission,crypto,protection,{now},transport())
        val sender:ConversationConfirmedSend
        init {
            assertTrue(radio.attempts().installVerifiedLineBinding(local.binding,
                listOf(ActiveSimCard(local.binding.subscriptionId,local.binding.cardId))))
            admission.prepare(byteArrayOf(1),true)
            val recovery=admission.beginRecovery();admission.completeRecovery(recovery.challenge,byteArrayOf(1))
            val request=clock.beginRequest();clock.installAuthenticatedReply(request.challenge,phone,now)
            sender=sender();sender.receiveConfirmed(original)
        }
        fun submit()=sender.submitConfirmed(message)
        fun assertNoReplay() {
            assertThrows(IllegalStateException::class.java){sender().submitConfirmed(message)}
        }
        fun attempt()=radio.attempts().getAttempt(checkNotNull(event).attemptId)
        override fun close(){(fixture as AutoCloseable).close();capture.close();radio.close()}
    }
    @Test fun disabledConsumerNeverReservesMetadataOrEntersDriver()=Harness(false).use { h->
        assertEquals(ConversationSubmission.UNKNOWN,h.submit())
        assertEquals(0,h.metadataCalls);assertEquals(0,h.platformFactories);assertEquals(0,h.fakeCalls)
        assertEquals(0,h.radio.openHelper.readableDatabase.query("SELECT COUNT(*) FROM sms_attempts").use{it.moveToFirst();it.getInt(0)})
        assertEquals("unknown",h.sends.sends().receipt(h.message)?.state);h.assertNoReplay()
        assertTrue(h.body.all{it=='\u0000'})
    }
    @Test fun lostWriterAckRemainsUnknownWithoutRadioOrRetry()=Harness().use { h->
        h.lostAck=true;assertEquals(ConversationSubmission.UNKNOWN,h.submit())
        assertEquals(AttemptState.UNKNOWN,h.attempt()?.state)
        assertNull(h.radio.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
        assertEquals(0,h.platformFactories);assertEquals(0,h.fakeCalls);h.assertNoReplay()
        assertFalse(ConversationRadioIntentOwnership.owns(h.event!!))
    }
    @Test fun deniedWriterAckDurablyProvesNoRadioAndNeverConsumes()=Harness().use { h->
        h.permit=false;assertEquals(ConversationSubmission.UNKNOWN,h.submit())
        assertEquals(AttemptState.NOT_SUBMITTED,h.attempt()?.state)
        assertNotNull(h.radio.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
        assertEquals(0,h.platformFactories);assertEquals(0,h.fakeCalls);h.assertNoReplay()
    }
    @Test fun exactAckAndGuardedPreparedCommitOneUseBeforeOneFakePlatformCall()=Harness().use { h->
        assertEquals(ConversationSubmission.SUBMITTED,h.submit())
        assertEquals(1,h.metadataCalls);assertEquals(1,h.platformFactories);assertEquals(1,h.fakeCalls)
        assertEquals(AttemptState.RADIO_STARTED,h.attempt()?.state)
        assertEquals("submitted",h.sends.sends().receipt(h.message)?.state)
        assertTrue(h.context!!.deadlineMs<h.context!!.originalDeadlineMs)
        assertEquals(h.context!!.grant.expiresAtMs,h.context!!.deadlineMs)
        assertEquals(h.sends.sends().receipt(h.message)?.evidenceDigest,h.context!!.evidenceDigest)
        assertEquals(0,h.radio.attempts().consumeRadioStart(h.event!!.attemptId,h.message,
            h.local.binding.subscriptionId,1,h.now))
        h.assertNoReplay();assertEquals(1,h.fakeCalls);assertTrue(h.body.all{it=='\u0000'})
    }
    @Test fun throwAfterFakeInvocationRetainsUnknownAndNeverProvesNoRadioOrRetries()=Harness().use { h->
        h.ambiguous=true;assertEquals(ConversationSubmission.UNKNOWN,h.submit())
        assertEquals(1,h.fakeCalls);assertEquals(AttemptState.UNKNOWN,h.attempt()?.state)
        assertEquals("unknown",h.sends.sends().receipt(h.message)?.state)
        assertEquals(0,h.radio.openHelper.readableDatabase.query("SELECT COUNT(*) FROM alpha_radio_events WHERE evidence='proven_no_submit'").use{it.moveToFirst();it.getInt(0)})
        h.assertNoReplay();assertEquals(1,h.metadataCalls);assertEquals(1,h.fakeCalls)
    }
    @Test fun expiryDuringSelectedProviderIsRecheckedBeforeCasAndAfterCas() {
        listOf(1,4).forEach { target->Harness().use { h->
            h.selectedHook={if(h.selections==target)h.now=checkNotNull(h.context).deadlineMs}
            assertEquals(ConversationSubmission.UNKNOWN,h.submit())
            assertEquals(0,h.fakeCalls);assertNotEquals(AttemptState.RADIO_STARTED,h.attempt()?.state)
            if(target==4)assertEquals(AttemptState.NOT_SUBMITTED,h.attempt()?.state)
            h.assertNoReplay();assertTrue(h.body.all{it=='\u0000'})
        } }
    }
    @Test fun grantExpiryWhileAckWaitsNeverEntersPlatform()=Harness().use { h->
        h.ackHook={h.now=checkNotNull(h.context).deadlineMs}
        assertEquals(ConversationSubmission.UNKNOWN,h.submit())
        assertEquals(0,h.platformFactories);assertEquals(0,h.fakeCalls)
        assertNull(h.radio.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
        h.assertNoReplay()
    }
    @Test fun heldMetadataAckCannotDelayActualStopOrPermitLateFakeRadio()=Harness().use { h->
        val held=CountDownLatch(1);val release=CountDownLatch(1);val stopped=CountDownLatch(1)
        val pool=Executors.newFixedThreadPool(2)
        h.ackHook={held.countDown();check(release.await(5,TimeUnit.SECONDS))}
        try {
            val send=pool.submit<ConversationSubmission>{h.submit()}
            assertTrue(held.await(2,TimeUnit.SECONDS))
            val stop=pool.submit{h.sender.close(h.scope.intervalId);stopped.countDown()}
            assertTrue("Stop must finish before metadata ACK release",stopped.await(1,TimeUnit.SECONDS))
            assertFalse(h.admission.captureEligible());assertEquals(0,h.fakeCalls)
            release.countDown();stop.get(2,TimeUnit.SECONDS)
            assertEquals(ConversationSubmission.UNKNOWN,send.get(3,TimeUnit.SECONDS))
            assertEquals(0,h.platformFactories);assertEquals(0,h.fakeCalls)
            assertEquals("unknown",h.sends.sends().receipt(h.message)?.state);h.assertNoReplay()
        } finally {release.countDown();pool.shutdown();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS))}
    }
}
