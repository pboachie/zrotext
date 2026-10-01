// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.room.Room
import java.util.UUID
import java.util.concurrent.Executor
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Integrates the reviewed pane/real runtime/Room journal/serialized authority, with fixture service.
 * No receiver, carrier, hardware-key provisioning or production activity mount is exercised.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34],qualifiers="w320dp-h480dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationPaneRuntimeTest {
    @get:Rule val compose=createAndroidComposeRule<MainActivity>()
    private fun id()=UUID.randomUUID().toString()
    private val disclosure=Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray())
    private val scope=ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),disclosure,"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private val session=ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),1,1,"55".repeat(32))
    private class Queue:Executor {private val tasks=java.util.ArrayDeque<Runnable>();override fun execute(r:Runnable){tasks.add(r)};fun drain(){while(tasks.isNotEmpty())tasks.removeFirst().run()}}
    private val worker=Queue()
    private val delivery=Queue()
    private lateinit var capture:ConversationCaptureDatabase
    private lateinit var sends:ConversationSendDatabase
    private lateinit var admission:ConversationCaptureAdmission
    private lateinit var port:ConversationPresentationRuntime
    private var remoteCommitted=true
    private var installCalls=0
    private var closeCalls=0
    @Before fun setup() {
        val context=RuntimeEnvironment.getApplication()
        capture=Room.inMemoryDatabaseBuilder(context,ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        sends=Room.inMemoryDatabaseBuilder(context,ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        val verifier=object:ConversationActivationVerifier {
            override fun verifiedPreparation(evidence:ByteArray)=scope.also{check(evidence.contentEquals(byteArrayOf(1)))}
            override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray)=60000L.also{check(evidence.contentEquals(byteArrayOf(2)))}
        }
        val protection=object:ConversationJournalProtection {
            // State-integration fixture only; encrypted production custody remains mandatory.
            override fun seal(value:String,aad:String)=InboundVault.Sealed(value.toByteArray(),byteArrayOf(1))
            override fun open(value:InboundVault.Sealed,aad:String)=value.ciphertext.toString(Charsets.UTF_8)
        }
        admission=ConversationCaptureAdmission(capture.journal(),verifier,protection,{100L},{check(it==scope)})
        val recovery=ConversationFreshReviewRecovery(capture.journal(),admission,verifier){check(it==scope)}
        val clock=ConversationTrustedClock({100L},{session})
        val wire=object:ConversationAuthenticatedWire {
            override fun currentSession()=session
            override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
                val parsed=ConversationChannelCodec.parseCloseRequest(request,session)
                check(parsed.scope==scope);closeCalls++
                return ConversationAuthenticatedWire.Reply(session,ConversationChannelCodec.closeReply(ConversationClosureReply(session,parsed.challenge,parsed.scope,remoteCommitted)))
            }
        }
        val transport=ConversationAuthorityTransport(ConversationSerializedChannel(wire),clock,{session},{100L})
        val hooks=ConversationLifecycleHooks(admission,sends.sends(),clock,recovery,transport::close)
        val domain=ConversationJournalPresentationDomain(admission,recovery,hooks,verifier,{100L}){
            assertFalse(admission.captureEligible());assertEquals("prepared",capture.journal().installation()!!.state)
            installCalls++;byteArrayOf(2)
        }
        domain.propose(ConversationPhoneReview(id(),scope.intervalId,scope.lineId,1,scope.peer,
            ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",disclosure,60000),byteArrayOf(1))
        port=ConversationPresentationRuntime(worker,delivery,domain)
        port.refresh();worker.drain()
        compose.runOnIdle {compose.activity.setContent {GatewayTheme {FutureConversationPane(port,{_,_->"Test line"})}}}
        compose.runOnIdle{delivery.drain()};compose.waitForIdle()
    }
    @After fun cleanup(){capture.close();sends.close()}
    private fun click(label:String){compose.onNodeWithText(label).performScrollTo().performClick()}
    private fun drain(){worker.drain();compose.runOnIdle{delivery.drain()};compose.waitForIdle()}
    private fun activate(){
        assertFalse(admission.captureEligible());click("Agree and continue")
        assertEquals(0,installCalls);assertFalse(admission.captureEligible());drain()
        assertEquals(1,installCalls);assertTrue(admission.captureEligible())
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertExists()
    }
    @Test fun explicitPaneApprovalInstallsAndStopNeedsSerializedDurableAck(){
        activate();click("Stop content transfer");assertFalse(admission.captureEligible());assertEquals(0,closeCalls)
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist();drain()
        assertEquals(1,closeCalls);assertEquals("closed",capture.journal().installation()!!.state)
        compose.onNodeWithText("Content transfer: Interval closed").assertExists()
    }
    @Test fun uncertainServerAckKeepsPaneDisabledWithoutClaimingClosed(){
        activate();remoteCommitted=false;click("Stop content transfer");assertFalse(admission.captureEligible());drain()
        assertEquals(1,closeCalls);compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        assertFalse(admission.captureEligible())
    }
}
