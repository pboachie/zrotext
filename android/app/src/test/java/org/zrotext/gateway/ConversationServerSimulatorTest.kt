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
