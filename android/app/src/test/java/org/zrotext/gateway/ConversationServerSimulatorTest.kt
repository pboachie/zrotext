// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.file.Files
import java.nio.file.Paths
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Runs in the explicit cross-language fixture workflow, never against a real gateway. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationServerSimulatorTest {
    @Test fun canonicalServerInstallJournalCaptureAndBrowserHistory() {
        val directory = System.getenv("ZT_CONVERSATION_SIM_DIR")
        assumeTrue("Explicit loopback fixture runner required", directory != null)
        val fixture = ConversationSimulatorFixture(JSONObject(Files.readString(Paths.get(directory!!, "ready.json"))))
        val context = RuntimeEnvironment.getApplication()
        val name = "conversation-server-test.db"
        context.deleteDatabase(name)
        var db = Room.databaseBuilder(context, ConversationCaptureDatabase::class.java, name).allowMainThreadQueries().build()
        val start = System.nanoTime()
        var enabled = true
        fun gate() = ConversationCaptureAdmission(db.journal(), fixture, fixture.protection,
            { (System.nanoTime() - start) / 1_000_000 }, { expected -> check(enabled && expected == fixture.parsed.scope) })
        var admission = gate()
        val scope = fixture.parsed.scope
        val token = "01".repeat(32)
        val body = "Fixture phone to browser Ω\nSecond line"
        var closeStatus = "unconfirmed"
        fun observe() = admission.observe(token, System.currentTimeMillis(), scope.peer, scope.lineId, scope.bindingGeneration, body)
        fun recover() {
            val request = admission.beginRecovery()
            val response = fixture.command("lease", challenge = UUID.fromString(request.challenge))
            check(response.getBoolean("ok"))
            admission.completeRecovery(request.challenge, response.toString().toByteArray(Charsets.UTF_8))
        }
        try {
            assertThrows(IllegalArgumentException::class.java) { admission.prepare(fixture.statement, false) }
            assertTrue(enabled) // Denial preserves the simulated pairing/runtime selection.
            admission.prepare(fixture.statement, true)
            assertFalse(admission.captureEligible())
            val premature = fixture.envelope(body, UUID.randomUUID().toString(), System.currentTimeMillis(), 1)
            assertFalse(fixture.command("capture", data = premature.getString("envelope")).getBoolean("ok"))
            assertFalse(fixture.command("lease", challenge = UUID.randomUUID()).getBoolean("ok"))
            assertTrue(fixture.command("approve", data = fixture.b64(fixture.statement),
                signature = fixture.sign(ConversationActivationCodec.APPROVE_DOMAIN)).getBoolean("ok"))
            assertFalse(admission.captureEligible())
            assertFalse(fixture.command("lease", challenge = UUID.randomUUID()).getBoolean("ok"))
            assertFalse(fixture.command("capture", data = premature.getString("envelope")).getBoolean("ok"))
            assertTrue(fixture.command("installed", data = fixture.b64(fixture.statement),
                signature = fixture.sign(ConversationActivationCodec.INSTALL_DOMAIN)).getBoolean("ok"))
            assertFalse(admission.captureEligible()) // Server-installed is not local confirmed admission.
            recover()
            assertTrue(admission.captureEligible())
            assertEquals(ConversationObservation.CAPTURED, observe())
            val captured = admission.retry(token)!!
            val original = db.journal().receipt(token)!!.protectedCapture!!.copyOf()
            val envelope = fixture.envelope(captured.body, captured.captureId, captured.firstObservedAtMs, 1)
            assertEquals(body, envelope.getString("opened"))
            assertTrue(fixture.command("capture", data = envelope.getString("envelope")).getBoolean("ok"))
            val event = UUID.fromString(captured.captureId)
            val before = fixture.command("history", event = event)
            assertTrue(before.getBoolean("ok"))
            assertEquals(body, fixture.open(before.getString("envelope")).getString("opened"))
            assertTrue(fixture.command("renew").getBoolean("ok"))
            val after = fixture.command("history", event = event)
            assertEquals(before.getString("envelope"), after.getString("envelope"))
            assertEquals(body, fixture.open(after.getString("envelope")).getString("opened"))
            db.close()
            db = Room.databaseBuilder(context, ConversationCaptureDatabase::class.java, name).allowMainThreadQueries().build()
            admission = gate()
            assertFalse(admission.captureEligible())
            assertNull(admission.retry(token))
            recover()
            assertArrayEquals(original, db.journal().receipt(token)!!.protectedCapture)
            assertEquals(captured.captureId, admission.retry(token)!!.captureId)
            assertEquals(captured.firstObservedAtMs, admission.retry(token)!!.firstObservedAtMs)
            assertEquals(ConversationObservation.DUPLICATE, observe())
            assertTrue(admission.captureEligible()) // Same simulated phone admission gate is active.
            val browser = fixture.browser(event, body)
            assertEquals(1, browser.getInt("signed"))
            val sendClosed = browser.getBoolean("closedDuringDecrypt")
            if (sendClosed) enabled = false
            // Record synthetic phone acceptance under the exact same monitor/gate
            // as receiver observation and Pause, only after verified decryption.
            var simulatedPhoneAcceptances = 0
            val sent = browser.getJSONObject("packet")
            val proof = java.util.Base64.getDecoder().decode(sent.getString("confirmation"))
            val deadline = java.nio.ByteBuffer.wrap(proof, 125, 8).long
            if (browser.getInt("verified") == 1) {
                assertTrue(admission.captureEligible())
                assertEquals(scope, fixture.parsed.scope)
                // A verified result handed off after the 30s intent deadline is
                // refused even though the conversation's 60s lease remains live.
                assertFalse(fixture.recordVerifiedAcceptance(admission, deadline, { deadline }) { simulatedPhoneAcceptances++ })
                val sendName = "conversation-server-send-test.db"
                context.deleteDatabase(sendName)
                var sendDb = Room.databaseBuilder(context, ConversationSendDatabase::class.java, sendName).allowMainThreadQueries().build()
                try {
                    var verificationCount = 0
                    val verifier = object : ConversationSendVerifier {
                        override fun verify(evidence: ByteArray): VerifiedConversationSend {
                            verificationCount++
                            return fixture.verifiedSend(evidence, System.getenv("ZT_CONVERSATION_SIM_MODE") == "send_verify_close" && verificationCount == 3)
                        }
                    }
                    // Fixture time only; production requires refreshed authenticated monotonic time.
                    fun sender() = ConversationConfirmedSend(sendDb.sends(), admission, verifier, fixture.protection,
                        System::currentTimeMillis, object : ConversationSendTransport {
                            override fun submit(message: String, attempt: String, scope: ConversationCaptureScope, body: String): ConversationSubmission {
                                assertEquals("claimed", sendDb.sends().receipt(message)!!.state)
                                assertEquals(attempt, sendDb.sends().receipt(message)!!.attempt)
                                assertEquals("Synthetic browser reply \u03A9\nExact trailing spaces  ", body)
                                simulatedPhoneAcceptances++
                                return ConversationSubmission.SUBMITTED
                            }
                        })
                    val durable = sender()
                    durable.receiveConfirmed(sent.toString().toByteArray(Charsets.UTF_8))
                    assertEquals("confirmed", sendDb.sends().receipt(sent.getString("message"))!!.state)
                    if (System.getenv("ZT_CONVERSATION_SIM_MODE") == "send_verify_close") {
                        assertThrows(IllegalStateException::class.java) { durable.submitConfirmed(sent.getString("message")) }
                        assertEquals("claimed", sendDb.sends().receipt(sent.getString("message"))!!.state)
                        assertEquals(0, simulatedPhoneAcceptances)
                    } else assertEquals(ConversationSubmission.SUBMITTED, durable.submitConfirmed(sent.getString("message")))
                    sendDb.close()
                    sendDb = Room.databaseBuilder(context, ConversationSendDatabase::class.java, sendName).allowMainThreadQueries().build()
                    assertEquals(if (System.getenv("ZT_CONVERSATION_SIM_MODE") == "send_verify_close") "claimed" else "submitted", sendDb.sends().receipt(sent.getString("message"))!!.state)
                    assertThrows(IllegalStateException::class.java) { sender().submitConfirmed(sent.getString("message")) }
                } finally { sendDb.close(); context.deleteDatabase(sendName) }
            }
            assertEquals(if (sendClosed || System.getenv("ZT_CONVERSATION_SIM_MODE") == "send_verify_close") 0 else 1, simulatedPhoneAcceptances)

            // All receiver / close actions use this same admission instance. Never infer Closed on failure.
            val mode = System.getenv("ZT_CONVERSATION_SIM_MODE") ?: "pause"
            enabled = false
            if (mode == "close_failure") db.openHelper.writableDatabase.execSQL("PRAGMA query_only = ON")
            val local = runCatching { admission.close(scope.intervalId) }
            val remote = fixture.command(if (mode == "logout") "logout" else "pause")
            closeStatus = if (local.isSuccess && remote.getBoolean("ok")) "closed" else "capture_disabled_closure_failed"
            assertFalse(admission.captureEligible())
            assertEquals(if (mode == "close_failure") "capture_disabled_closure_failed" else "closed", closeStatus)
            assertFalse(fixture.command("lease", challenge = UUID.randomUUID()).getBoolean("ok"))
            assertFalse(fixture.command("capture", data = envelope.getString("envelope")).getBoolean("ok"))
            assertFalse(fixture.command("browser_authority").getBoolean("ok"))
            assertFalse(fixture.command("send", data = sent.getString("envelope"), confirmation = sent.getString("confirmation"), signature = sent.getString("signature")).getBoolean("ok"))
            if (mode == "close_failure") {
                db.close()
                db = Room.databaseBuilder(context, ConversationCaptureDatabase::class.java, name).allowMainThreadQueries().build()
                enabled = true
                admission = gate()
                assertEquals("installed", db.journal().installation()!!.state)
                assertFalse(admission.captureEligible())
                val recovery = admission.beginRecovery()
                assertFalse(fixture.command("lease", challenge = UUID.fromString(recovery.challenge)).getBoolean("ok"))
                assertFalse(admission.captureEligible()) // Durable server stop blocks recovery despite failed local close.
            }
        } finally {
            db.close(); context.deleteDatabase(name)
            fixture.command("finish")
        }
    }
}
