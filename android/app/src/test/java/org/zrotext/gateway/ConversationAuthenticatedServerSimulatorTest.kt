// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.file.Files
import java.nio.file.Paths
import java.util.UUID
import java.util.concurrent.Executor
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Authenticated runtime assembly; ephemeral loopback fixture keys, no carrier dispatch. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationAuthenticatedServerSimulatorTest {
    private class Queue : Executor {
        private val pending = java.util.ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { pending.add(command) }
        fun drain() { while(pending.isNotEmpty()) pending.removeFirst().run() }
    }
    @Test fun authenticatedActivationCaptureReadableBrowserReplyAndDurableStop() {
        val directory=System.getenv("ZT_CONVERSATION_SIM_DIR")
        assumeTrue("Explicit isolated simulator required",directory!=null)
        val fixture=ConversationSimulatorFixture(JSONObject(Files.readString(Paths.get(directory!!,"ready.json"))))
        val context=RuntimeEnvironment.getApplication()
        val db=Room.inMemoryDatabaseBuilder(context,ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val sends=Room.inMemoryDatabaseBuilder(context,ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        val worker=Queue();val delivery=Queue();val snapshots=mutableListOf<ConversationPresentationSnapshot>()
        val scope=fixture.parsed.scope
        val start=System.nanoTime()
        var decisions=0;var installs=0;var submissions=0
        var permission=true
        var installedGate: () -> Boolean = { false }
        val runtime=ConversationAuthenticatedRuntime(db.journal(),sends.sends(),fixture,fixture.protection,
            fixture.authenticatedWire(),{(System.nanoTime()-start)/1_000_000},
            { selected,now -> check(permission && selected==scope && now<fixture.parsed.expiresMs) },
            { selected -> check(selected==scope);decisions++ },
            { request ->
                check(decisions==1)
                check(fixture.command("approve",data=fixture.b64(fixture.statement),signature=fixture.sign(ConversationActivationCodec.APPROVE_DOMAIN)).getBoolean("ok"))
                check(!installedGate())
                check(fixture.command("installed",data=fixture.b64(fixture.statement),signature=fixture.sign(ConversationActivationCodec.INSTALL_DOMAIN)).getBoolean("ok"))
                installs++
                fixture.command("lease",challenge=UUID.fromString(request.challenge)).toString().toByteArray(Charsets.UTF_8)
            },worker,delivery)
        installedGate = runtime::captureEligible
        runtime.presentation.observe { snapshots.add(it) }
        fun drain() {worker.drain();delivery.drain()}
        try {
            val review=ConversationPhoneReview(UUID.randomUUID().toString(),scope.intervalId,scope.lineId,scope.bindingGeneration,
                scope.peer,ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",scope.disclosureDigest,30000)
            runtime.propose(review,fixture.statement);drain()
            assertEquals(ConversationPresentationPhase.AWAITING_PHONE_REVIEW,snapshots.last().phase)
            assertFalse(runtime.captureEligible());assertEquals(0,decisions);assertEquals(0,installs)
            runtime.presentation.approvePhoneReview(review.requestId,snapshots.last().version);drain()
            assertEquals(1,decisions);assertEquals(1,installs)
            assertEquals(ConversationPresentationPhase.CONFIRMED_ACTIVE,snapshots.last().phase)
            val token="01".repeat(32);val body="Synthetic authenticated inbound \u03A9\nSecond line"
            assertEquals(ConversationObservation.CAPTURED,runtime.observeFirstReceipt(token,scope.peer,scope.lineId,scope.bindingGeneration,body))
            assertEquals(ConversationObservation.DUPLICATE,runtime.observeFirstReceipt(token,scope.peer,scope.lineId,scope.bindingGeneration,body))
            val captured=checkNotNull(runtime.retryCapture(token))
            val encrypted=fixture.envelope(captured.body,captured.captureId,captured.firstObservedAtMs,1)
            assertTrue(fixture.command("capture",data=encrypted.getString("envelope")).getBoolean("ok"))
            val event=UUID.fromString(captured.captureId)
            val before=fixture.command("history",event=event)
            assertEquals(body,fixture.open(before.getString("envelope")).getString("opened"))
            assertTrue(fixture.command("renew").getBoolean("ok"))
            val after=fixture.command("history",event=event)
            assertEquals(before.getString("envelope"),after.getString("envelope"))
            val browser=fixture.browser(event,body)
            assertEquals(1,browser.getInt("signed"));assertEquals(1,browser.getInt("verified"))
            val packet=browser.getJSONObject("packet")
            val verifier=object:ConversationSendVerifier {
                override fun verify(evidence:ByteArray)=fixture.verifiedSend(evidence,false)
            }
            val transport=object:ConversationSendTransport {
                override fun submit(message:String,attempt:String,scope:ConversationCaptureScope,body:String):ConversationSubmission {
                    assertEquals("claimed",sends.sends().receipt(message)!!.state)
                    assertEquals("Synthetic browser reply \u03A9\nExact trailing spaces  ",body)
                    submissions++;return ConversationSubmission.UNKNOWN
                }
            }
            val sender=runtime.confirmedSender(verifier,transport)
            sender.receiveConfirmed(packet.toString().toByteArray(Charsets.UTF_8))
            assertEquals(ConversationSubmission.UNKNOWN,sender.submitConfirmed(packet.getString("message")))
            assertEquals(1,submissions)
            assertThrows(IllegalStateException::class.java) {runtime.confirmedSender(verifier,transport).submitConfirmed(packet.getString("message"))}
            assertEquals(1,submissions)
            runtime.lifecycleLost(ConversationStopReason.OWNER_SESSION_LOST)
            assertFalse(runtime.captureEligible());drain()
            assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,snapshots.last().phase)
            assertFalse(fixture.command("lease",challenge=UUID.randomUUID()).getBoolean("ok"))
            assertFalse(fixture.command("capture",data=encrypted.getString("envelope")).getBoolean("ok"))
            assertFalse(fixture.command("browser_authority").getBoolean("ok"))
            assertNull(runtime.retryCapture(token))
            // Stop retains eligible history; explicit withdrawal revokes access without claiming deletion.
            assertTrue(fixture.command("history",event=event).getBoolean("ok"))
            assertTrue(fixture.command("withdraw").getBoolean("ok"))
            assertFalse(fixture.command("history",event=event).getBoolean("ok"))
        } finally {db.close();sends.close();fixture.command("finish")}
    }
}
