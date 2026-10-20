// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual consent orchestration, Room/GCM and real synthetic P256 proofs. The explicit source
 * and signer ports are component fixtures: no authenticated hosted service, Android hardware,
 * maintained receiver, framework SMS or carrier acceptance is asserted by these tests.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ConversationInterval03RuntimeTest {
    private class Fixture : AutoCloseable {
        val app = RuntimeEnvironment.getApplication()
        val base = Profile03ExecutionFixture(distinctEventSigner = true)
        private val metadata = mutableListOf<String>()
        private val live = AtomicBoolean(true)
        private var elapsed = 100L
        val time = Profile03SessionTime(base.line.account, base.line.device, base.line.epoch, base.session.originHash,
            { elapsed }, live::get, { 2 }, { metadata.add(it); true }).also { clock ->
            check(clock.request())
            val request = JSONObject(metadata.single())
            clock.accept(JSONObject().put("v", 1).put("type", "payload_profile_session03")
                .put("challenge", request.getString("challenge")).put("account_id", base.line.account)
                .put("device_id", base.line.device).put("connection_epoch", base.line.epoch).put("deployment_epoch", 1)
                .put("session_id", base.session.sessionId).put("server_time_ms", base.now - 1).put("site_id", "synthetic-site")
                .put("instance_id", "synthetic-instance").put("line_activation_version", 2).toString().toByteArray())
            elapsed++ // The real clock refuses a snapshot at or below its anchor; never weaken it.
        }
        val f = ConversationInterval03TestFixture(base, checkNotNull(time.snapshot()).first
            .deviceSessionDigest(Profile03ExecutionFixture.point(base.enrollment)))
        val statement = f.statement()
        val initial = ConversationInterval03Proof(statement,
            Profile03ExecutionFixture.rawSign(base.signer, ConversationInterval03.requestTranscript(statement)), 100_001)
        val sent = CopyOnWriteArrayList<String>()
        var approvals = 0
        var installations = 0
        var wrongPhone = false
        var approvalWait: (() -> Unit)? = null
        private val signer = object : ConversationInterval03ProofSigner {
            override fun readerPoint() = Profile03ExecutionFixture.point(base.reader)
            override fun phonePoint() = Profile03ExecutionFixture.point(if (wrongPhone) base.enrollment else base.eventSigning)
            override fun approval(statement: ConversationInterval03.Statement, owner: ByteArray, expected: ByteArray,
                current: () -> Unit): ByteArray {
                current(); assertArrayEquals(Profile03ExecutionFixture.point(base.eventSigning), expected); approvals++
                val signature = Profile03ExecutionFixture.rawSign(base.eventSigning, ConversationInterval03.approvalTranscript(statement, owner))
                approvalWait?.invoke(); current(); return signature
            }
            override fun installed(statement: ConversationInterval03.Statement, owner: ByteArray, phone: ByteArray,
                expected: ByteArray, current: () -> Unit): ByteArray {
                current(); assertArrayEquals(Profile03ExecutionFixture.point(base.eventSigning), expected); installations++
                return Profile03ExecutionFixture.rawSign(base.eventSigning,
                    ConversationInterval03.installedTranscript(statement, owner, phone)).also { current() }
            }
        }
        private var owner = Any()
        var store = newStore()
        var runtime = newRuntime()
        init { app.deleteDatabase(ConversationInterval03Database.FILE); attach() }
        private fun newStore() = ConversationInterval03Store(app,
            ConversationExistingJournalProtection { SecretKeySpec(ByteArray(32) { 11 }, "AES") },
            ConversationExistingSuppressionTokens { SecretKeySpec(ByteArray(32) { 12 }, "HmacSHA256") })
        private fun newRuntime() = ConversationInterval03Runtime(owner, Profile03ExecutionFixture.unhex(base.session.originHash),
            store, signer, time, live::get, { raw, line ->
                assertEquals("{\"v\":1}", raw.toString(Charsets.UTF_8)); assertEquals(base.line.line, line); f.selected()
            }, { sent.add(it); true })
        private fun attach() = ConversationInterval03Mount.attach(owner, live::get, runtime::approve, runtime::retry,
            runtime::requestStatus, runtime::stop)
        fun restart() { runtime.close(); ConversationInterval03Mount.detach(owner); owner = Any(); store = newStore(); runtime = newRuntime(); attach() }
        fun <T> io(action: () -> T): T {
            val future = CompletableFuture<T>()
            JournalRuntime.io.execute { try { future.complete(action()) } catch (failure: Throwable) { future.completeExceptionally(failure) } }
            return future.get(5, TimeUnit.SECONDS)
        }
        fun challenge(): ConversationInterval03Mount.Review {
            val permission = f.permission(initial, "requested", "interval_challenge", statement.receipt)
            io { runtime.challenge(JSONObject().put("v", 1).put("type", "conversation_interval_challenge03")
                .put("interval_id", statement.interval).put("statement", b64(statement.bytes()))
                .put("owner_signature", b64(initial.ownerSignature())).put("current", JSONObject().put("v", 1))
                .put("interval_permission", permission).toString().toByteArray()) }
            return checkNotNull(ConversationInterval03Mount.review)
        }
        fun row() = checkNotNull(store.openForDecision().find(statement.interval.toString()))
        fun proof() = store.proof(row())
        fun approved() = runtime.approved(JSONObject().put("v", 1).put("type", "conversation_interval_approved03")
            .put("interval_id", statement.interval).put("statement_sha256", b64(statement.sha256())).put("approved_ms", base.now.toString()).toString().toByteArray())
        fun installed() = runtime.installed(JSONObject().put("v", 1).put("type", "conversation_interval_installed03")
            .put("interval_id", statement.interval).put("statement_sha256", b64(statement.sha256())).put("installed_ms", base.now.toString())
            .put("device_session_digest", b64(f.deviceSession)).toString().toByteArray())
        fun packet(proof: ConversationInterval03Proof, acceptedMs: Long = base.now): Profile03FetchPacket = Profile03FetchPacket.decode(JSONObject()
            .put("v", 1).put("envelope", b64(base.envelope)).put("reviewed_intent", b64(base.intentBytes))
            .put("reviewed_signature", b64(base.intentSignature)).put("accepted_ms", acceptedMs.toString())
            .put("interval_starts_ms", statement.intervalStartsMs.toString()).put("interval_expires_ms", statement.intervalExpiresMs.toString())
            .put("selection_epoch", "3").put("current", JSONObject().put("v", 1))
            .put("interval_permission", f.permission(proof)).toString().toByteArray(), base.grant)
        fun activeStatus(shown: ConversationInterval03Mount.Review, proof: ConversationInterval03Proof) {
            runtime.requestStatus(shown)
            val request = JSONObject(sent.last())
            val challenge = UUID.fromString(request.getString("challenge"))
            val permission = f.permission(proof, "active", "interval_status", challenge)
            runtime.status(JSONObject().put("v", 1).put("type", "conversation_interval_status03").put("interval_id", statement.interval)
                .put("challenge", challenge).put("statement_sha256", b64(statement.sha256())).put("phase", "active")
                .put("approved_ms", proof.approvedMs.toString()).put("installed_ms", proof.installedMs.toString())
                .put("device_session_digest", b64(f.deviceSession)).put("interval_permission", permission).toString().toByteArray())
        }
        override fun close() { live.set(false); runtime.close(); ConversationInterval03Mount.detach(owner); time.close(); base.close(); app.deleteDatabase(ConversationInterval03Database.FILE) }
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
    }
    @Test fun backgroundApprovalAckNeedsFreshForegroundBeforeUnusedInstallPhase(): Unit = Fixture().use { v ->
        val shown = v.challenge(); val foreground = AtomicBoolean(true)
        v.io { v.runtime.approve(shown, foreground) }; foreground.set(false)
        v.io { v.approved(); assertEquals("approved", v.row().state) }
        assertEquals(1, v.approvals); assertEquals(0, v.installations)
        v.io { v.runtime.approve(shown, AtomicBoolean(true)); assertEquals("install_signed", v.row().state) }
        assertEquals(1, v.approvals); assertEquals(1, v.installations)
    }
    @Test fun activeStatusCannotReplaceOriginalAckAndRetryNeverResigns(): Unit = Fixture().use { v ->
        val shown = v.challenge(); v.io { v.runtime.approve(shown, AtomicBoolean(true)); v.approved() }
        val original = v.sent.last()
        val proof = v.io { v.proof().installed(v.base.now) }
        v.io {
            v.activeStatus(shown, proof)
            assertEquals("install_signed", v.row().state)
            assertThrows(Exception::class.java) { v.runtime.requireFetch(v.packet(proof), v.base.grant, v.f.selected()) }
            v.runtime.retry(shown, AtomicBoolean(true))
            assertEquals(original, v.sent.last())
            v.installed(); assertEquals("active", v.row().state)
            assertThrows(Exception::class.java) { v.runtime.requireFetch(v.packet(proof, v.base.now - 1), v.base.grant, v.f.selected()) }
            v.runtime.requireFetch(v.packet(proof), v.base.grant, v.f.selected()).invoke()
        }
        assertEquals(1, v.approvals); assertEquals(1, v.installations)
    }
    @Test fun stopWithdrawsRamBeforeQueuedDurableWriterAndRetainsEveryOriginal(): Unit = Fixture().use { v ->
        val shown = v.challenge(); val guard = v.io {
            v.runtime.approve(shown, AtomicBoolean(true)); v.approved(); v.installed()
            v.runtime.requireFetch(v.packet(v.proof()), v.base.grant, v.f.selected())
        }
        val bytes = v.io { v.proof().bytes() }
        v.runtime.stop(shown)
        assertThrows(Exception::class.java) { guard() }
        v.io { assertEquals("stopped", v.row().state); assertArrayEquals(bytes, v.proof().bytes()) }
    }
    @Test fun stopDuringBlockedSigningBurnsUnknownWithoutReleasingOrRegenerating(): Unit = Fixture().use { v ->
        val shown = v.challenge(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        v.approvalWait = { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)) }
        val pending = CompletableFuture<Boolean>()
        JournalRuntime.io.execute { pending.complete(runCatching { v.runtime.approve(shown, AtomicBoolean(true)) }.isFailure) }
        try { assertTrue(entered.await(3, TimeUnit.SECONDS)); v.runtime.stop(shown) } finally { release.countDown() }
        assertTrue(pending.get(5, TimeUnit.SECONDS))
        v.io { assertEquals("stopped", v.row().state); assertNull(v.proof().phoneSignature())
            assertThrows(Exception::class.java) { v.runtime.retry(shown, AtomicBoolean(true)) } }
        assertEquals(1, v.approvals); assertEquals(0, v.installations)
        assertTrue(v.sent.none { JSONObject(it).getString("type") == "conversation_interval_approve03" })
    }
    @Test fun coldJournalAndDownloadedProofsCannotReconstructOrRepeatTheOriginal(): Unit = Fixture().use { v ->
        val shown = v.challenge(); v.io { v.runtime.approve(shown, AtomicBoolean(true)); v.approved() }
        val full = v.io { v.proof().installed(v.base.now) }
        v.restart(); val cold = v.challenge()
        v.io {
            assertThrows(Exception::class.java) { v.activeStatus(cold, full) }
            assertThrows(Exception::class.java) { v.runtime.requireFetch(v.packet(full), v.base.grant, v.f.selected()) }
            assertThrows(Exception::class.java) { v.runtime.approve(cold, AtomicBoolean(true)) }
            assertEquals("install_signed", v.row().state)
        }
        assertEquals(1, v.approvals); assertEquals(1, v.installations)
    }
    @Test fun selectedRoleFourMustMatchActualSignerBeforeAnyReservation(): Unit = Fixture().use { v ->
        val shown = v.challenge(); v.wrongPhone = true
        v.io { assertThrows(Exception::class.java) { v.runtime.approve(shown, AtomicBoolean(true)) }
            assertNull(v.store.openForDecision().find(v.statement.interval.toString())) }
        assertEquals(0, v.approvals); assertEquals(0, v.installations)
    }
}
