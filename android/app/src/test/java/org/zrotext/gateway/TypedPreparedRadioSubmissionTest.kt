// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.IOException
import java.util.UUID
import javax.crypto.spec.SecretKeySpec
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Actual typed factory/Room/socket/selected-driver consumer after a trusted adapter handoff.
 * Synthetic real P256/election/V2/body-GCM proofs and a genuine fixture SIM issuer are used.
 * The adapter and prepared-holder seam do NOT prove hardware HPKE, server/native admission,
 * a complete installed113 consumer, or a carrier effect. Only the platform driver is called.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedPreparedRadioSubmissionTest {
    private class Harness : AutoCloseable {
        private val f = Profile03ExecutionFixture(distinctEventSigner = true)
        val db = f.line.db
        private val health = InboundProtectionEpochs()
        private val epoch = health.snapshot()
        private var elapsed = 100L
        private var live = true
        private val metadata = mutableListOf<JSONObject>()
        private val time = Profile03SessionTime(f.line.account, f.line.device, f.session.connectionEpoch,
            f.origins.routingHash, { elapsed }, { live }, { 2 }, { metadata.add(JSONObject(it)); true })
        private val v: ConversationInterval03TestFixture
        private val wire: TypedSubmit03WireTest.Fixture
        private val body: CharArray
        private val prepared: Draft02OutboundPreparation.Prepared
        private lateinit var transport: TypedSubmit03Transport
        var submissions = 0
        var invocations = 0
        var selections = 0
        var checks = 0
        var accepted = true
        var loseAck = false
        var throwAtPlatform = false
        var ackHook: () -> Unit = {}
        var selectedHook: () -> Unit = {}
        var currentHook: () -> Unit = {}
        var observed: TypedSubmit03Record? = null
        val attempt get() = f.attempt.toString()

        init {
            f.install()
            check(time.request())
            time.accept(JSONObject().put("v", 1).put("type", "payload_profile_session03")
                .put("challenge", metadata.single().getString("challenge")).put("account_id", f.line.account)
                .put("device_id", f.line.device).put("connection_epoch", f.session.connectionEpoch)
                .put("deployment_epoch", f.session.deploymentEpoch).put("session_id", f.session.sessionId)
                .put("server_time_ms", f.now - 1).put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
                .put("line_activation_version", 2).toString().toByteArray())
            elapsed++ // A real snapshot must follow its anchor; keep trusted now exactly f.now.
            val identity = checkNotNull(time.snapshot()).first
            v = ConversationInterval03TestFixture(f, identity.deviceSessionDigest(Profile03ExecutionFixture.point(f.enrollment)))
            wire = TypedSubmit03WireTest.Fixture(v)
            val proof = Draft03OutboundEnvelope.verify(f.envelope, f.authority, f.intentV2.request()) { checkNotNull(time.nowMs()) }
            body = Draft03Body.open(proof, f.authority, f.intentV2.request(), f.now, f.key.copyOf())
            // Explicit trusted prepared interface, with no reflection and no runtime provider substitute.
            prepared = Draft02OutboundPreparation.relayPrepared(1) { consumer ->
                try { check(live); consumer(body) } finally { body.fill('\u0000') }
            }
            val socket = object : WebSocket {
                override fun request() = Request.Builder().url(f.origins.protocolOrigin).build()
                override fun queueSize() = 0L
                override fun send(text: String): Boolean {
                    submissions++
                    val row = checkNotNull(db.typedSubmits03().get(attempt)); observed = row
                    val entered = checkNotNull(db.typedSubmits03().submitRequest(attempt))
                    assertArrayEquals(entered.bytes(), text.toByteArray())
                    assertNull(db.attempts().getAlphaEvent(row.eventId))
                    assertNull(db.attempts().getAttempt(attempt))
                    ackHook()
                    if (loseAck) return true
                    val command = row.command()
                    val reply = wire.ack(command)
                    if (!accepted) reply.put("disposition", "history_only").put("current", JSONObject.NULL)
                        .put("interval_permission", JSONObject.NULL)
                    check(transport.accept(reply.toString().toByteArray()))
                    return true
                }
                override fun send(bytes: ByteString) = false
                override fun close(code: Int, reason: String?) = true
                override fun cancel() = Unit
            }
            transport = TypedSubmit03Transport(socket, { time.snapshot()?.first?.session }, { check(live) }, timeoutMs = 20)
        }

        private fun current(): Draft03OutboundPreparation.Current {
            checks++; currentHook(); check(live)
            health.checked(epoch)
            val current = f.current()
            val at = checkNotNull(time.nowMs())
            current.intent.verifyReceipt(current.signature(), current.authority,
                current.election.requireCurrent(current.authority, current.selection, at), current.acceptedMs, at,
                current.selectionEpoch, current.origins.protocolDigest(), current.intervalStartsMs, current.intervalExpiresMs)
            return current
        }
        private fun platform(binding: LocalLineBinding) = ConversationRadioPlatform(binding,
            object : ConversationRadioDriver {
                override fun requireSelected() { selections++; selectedHook(); check(live) }
                override fun divide(body: String) = arrayListOf(body).also {
                    assertEquals(f.body.toString(Charsets.UTF_8), body)
                }
                override fun prepare(attempt: String, parts: ArrayList<String>) { assertEquals(this@Harness.attempt, attempt) }
                override fun send(peer: String, attempt: String, parts: ArrayList<String>) {
                    assertEquals("+12", peer)
                    assertEquals("platform_entry_reserved", db.typedSubmits03().get(attempt)?.phase)
                    assertNull(db.attempts().getAttempt(attempt))
                    invocations++
                    if (throwAtPlatform) throw IOException("Synthetic uncertain platform result")
                }
                override fun close() = Unit
            }, ConversationExistingSuppressionTokens { SecretKeySpec(ByteArray(32) { 9 }, "HmacSHA256") },
            true, healthCurrent = { health.checked(epoch) })

        fun submit() = TypedPreparedRadioSubmission(db, transport, time,
            { Profile03ExecutionFixture.point(f.enrollment) }, { check(live); health.checked(epoch) }, ::platform,
            { row, withdraw -> withdraw(); db.typedSubmits03().beginClosing(row, UUID.randomUUID().toString()); Unit })
            .submit(f.grant, prepared, ::current) { ack, command ->
                ack.requireOriginal(command)
                ack.intervalPermission().verifyCurrent(v.selected(), Profile03ExecutionFixture.point(f.reader),
                    f.origins.protocolDigest(), checkNotNull(time.nowMs()))
                current()
            }
        fun expire() { elapsed += 500 }
        fun stop() { f.intervalCurrent = false }
        fun revokeHealth() { health.revoke() }
        fun row() = db.typedSubmits03().get(attempt)
        fun assertNoRearm() {
            val before = submissions
            assertEquals(ConversationSubmission.UNKNOWN, submit())
            assertEquals(before, submissions)
        }
        fun assertBodyCleared() { assertTrue(body.all { it == '\u0000' }) }
        override fun close() { prepared.close(); body.fill('\u0000'); transport.close(); time.close(); wire.close() }
    }

    @Test fun firstVerifiedTypedAckCommitsOnePlatformEntryAndNeverCreatesALegacyEvent() {
        Harness().use { h ->
            assertEquals(ConversationSubmission.SUBMITTED, h.submit())
            assertEquals(1, h.submissions); assertEquals(1, h.invocations)
            val row = checkNotNull(h.row())
            assertEquals("platform_entry_reserved", row.phase)
            assertNotNull(row.ackSha256); assertNotNull(row.entryReservedMs)
            assertNotNull(h.db.typedSubmits03().submitRequest(h.attempt))
            h.assertBodyCleared(); h.assertNoRearm(); assertEquals(1, h.invocations)
        }
    }
    @Test fun historyOnlyAndLostAckRetainOriginalBurnAndCannotReachThePlatform() {
        for (lost in listOf(false, true)) Harness().use { h ->
            h.loseAck = lost; h.accepted = false
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(1, h.submissions); assertEquals(0, h.invocations)
            assertEquals("pre_entry_closing", h.row()?.phase)
            assertNotNull(h.db.typedSubmits03().submitRequest(h.attempt))
            h.assertNoRearm()
        }
    }
    @Test fun expiryOrStopWhileTheAckWaitsNeverAuthorizesEntry() {
        for (stop in listOf(false, true)) Harness().use { h ->
            h.ackHook = { if (stop) h.stop() else h.expire() }
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(0, h.invocations)
            assertEquals("pre_entry_closing", h.row()?.phase)
            assertNull(h.row()?.ackSha256)
            h.assertNoRearm()
        }
    }
    @Test fun stopOrProtectionWithdrawalDuringSelectedProviderNeverInvokesTheDriver() {
        for (health in listOf(false, true)) Harness().use { h ->
            h.selectedHook = { if (h.selections == 2) { if (health) h.revokeHealth() else h.stop() } }
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(0, h.invocations); assertEquals("pre_entry_closing", h.row()?.phase)
            assertNotNull(h.row()?.ackSha256)
            h.assertNoRearm()
        }
    }
    @Test fun anAmbiguousPlatformCallRemainsEnteredAndCannotBeClassifiedNoSubmitOrRepeated() {
        Harness().use { h ->
            h.throwAtPlatform = true
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(1, h.invocations); assertEquals("platform_entry_reserved", h.row()?.phase)
            assertNull(h.row()?.closingId)
            h.assertBodyCleared(); h.assertNoRearm(); assertEquals(1, h.invocations)
        }
    }
    @Test fun withdrawalAfterTheEntryCommitCannotInvokeOrRearmAndRemainsConservativelyEntered() {
        Harness().use { h ->
            h.currentHook = { if (h.row()?.phase == "platform_entry_reserved") h.revokeHealth() }
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(0, h.invocations); assertEquals("platform_entry_reserved", h.row()?.phase)
            assertNull(h.row()?.closingId)
            h.assertBodyCleared(); h.assertNoRearm()
        }
    }
}
