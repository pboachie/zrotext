// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual runtime, session-time engine and protected Room history with genuine ephemeral
 * original/successor proofs. The test original port is explicit component verification; it
 * does not assert authenticated transport, nonexportable custody, physical readiness or SMS. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ManifestRuntimeTest {
    private fun <T> io(action: () -> T): T {
        val future = CompletableFuture<T>()
        JournalRuntime.io.execute { try { future.complete(action()) } catch (failure: Throwable) { future.completeExceptionally(failure) } }
        return future.get(20, TimeUnit.SECONDS)
    }
    private inner class Harness(val f: Profile03ManifestTestFixture, private val retainDatabase: Boolean = false,
        preserveDatabase: Boolean = false, val connectionEpoch: Long = f.f.line.epoch,
        private val serverBaseMs: Long = 200_000) : AutoCloseable {
        val app = RuntimeEnvironment.getApplication()
        var elapsed = 100L
        var live = true
        var withdrawals = 0
        var selected = 0
        val sent = mutableListOf<JSONObject>()
        private val samples = mutableListOf<JSONObject>()
        val clock = Profile03SessionTime(f.f.line.account, f.f.line.device, connectionEpoch, f.f.session.originHash,
            { elapsed }, { live }, { 2 }, { samples.add(JSONObject(it)); true })
        val storage: Profile03ManifestStore
        val runtime: Profile03ManifestRuntime
        init {
            if (!preserveDatabase) app.deleteDatabase(Profile03ManifestDatabase.FILE)
            sample()
            storage = Profile03ManifestStore(app, ConversationExistingJournalProtection { SecretKeySpec(ByteArray(32) { 41 }, "AES") })
            val original = Profile03ManifestOriginalReader { evidence, line, binding, session ->
                require(line == f.f.line.line && binding == f.f.newBinding && session === clock.snapshot()!!.first.session)
                f.selected.requireEvidence(evidence)
                Profile03RetainedElection.historical(evidence, f.original.installed, f.original.activation,
                    f.original.store, f.original.reader, f.original.devicePoint, f.original.origin) { checkNotNull(clock.nowMs()) }
                f.selected
            }
            runtime = Profile03ManifestRuntime(f.f.origins, f.f.line.db, original, storage, clock, { live }, { f.original.devicePoint },
                { sent.add(JSONObject(it)); true }, { withdrawals++ }, {}, { _, _ -> selected++ }, { elapsed })
        }
        private fun sample() {
            assertTrue(clock.request())
            clock.accept(JSONObject().put("v", 1).put("type", "payload_profile_session03").put("challenge", samples.last().getString("challenge"))
                .put("account_id", f.f.line.account).put("device_id", f.f.line.device).put("connection_epoch", connectionEpoch)
                .put("deployment_epoch", 1).put("session_id", UUID(0, 98)).put("server_time_ms", serverBaseMs + elapsed)
                .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance").put("line_activation_version", 2).toString().toByteArray())
            elapsed++
        }
        fun advance(sampleNow: Boolean = true) { elapsed += 25_000; if (sampleNow) sample(); io { runtime.requestIfDue() } }
        fun reply(type: String) = JSONObject().put("v", 1).put("type", type).put("connection_epoch", connectionEpoch)
            .put("challenge", sent.last().getString("challenge"))
        fun accept(json: JSONObject) { runtime.accept(json.toString().toByteArray()); io {} }
        fun original() {
            io { runtime.requestIfDue() }
            assertEquals("payload_profile_manifest_original03_request", sent.last().getString("type"))
            accept(reply("payload_profile_manifest_original03").put("line_id", f.f.line.line).put("binding_id", f.f.newBinding)
                .put("evidence", JSONObject(f.original.evidence)))
            // A second barrier includes the separately queued bounded cold-restoration chunk.
            io {}
        }
        fun history(): Profile03ManifestHistory.Checkpoint {
            advance(); assertEquals("payload_profile_manifest03_request", sent.last().getString("type"))
            val entries = f.entries(1); val tip = f.checkpoint(entries)
            val page = f.page(f.base, entries, tip, checkNotNull(clock.nowMs()))
            accept(reply("payload_profile_manifest03").put("history", JSONObject(page.bytes().toString(Charsets.UTF_8))))
            return tip
        }
        fun acknowledgement(tip: Profile03ManifestHistory.Checkpoint) = reply("payload_profile_manifest03_installed_ack")
            .put("line_id", f.f.line.line).put("tip_version", tip.authority.version.toString()).put("tip_digest", b64(tip.authority.digest))
            .put("tip_ancestry_sha256", b64(tip.ancestry())).put("election_digest", b64(f.original.accepted.electionCommitment))
            .put("compared_ms", checkNotNull(clock.nowMs()).toString())
        override fun close() { io { runtime.close() }; clock.close(); if (!retainDatabase) app.deleteDatabase(Profile03ManifestDatabase.FILE) }
    }
    @Test fun onlyExactLiveReadbackPublishesRamHistoryAndAnyNewTipWithdrawsBeforeQueuedWork(): Unit = Profile03ManifestTestFixture().use { f ->
        Harness(f).use { h ->
            h.original(); assertThrows(Exception::class.java) { h.runtime.currentInstalled() }
            val tip = h.history(); assertThrows(Exception::class.java) { h.runtime.currentInstalled() }
            h.advance(); assertEquals("payload_profile_manifest03_installed", h.sent.last().getString("type"))
            h.accept(h.acknowledgement(tip))
            val installed = h.runtime.currentInstalled(); installed.requireRamCurrent()
            assertEquals(3L, installed.saved.head!!.version); assertEquals(0, h.selected)
            h.advance(); assertEquals("payload_profile_manifest_current03_request", h.sent.last().getString("type"))
            val changed = h.reply("payload_profile_manifest_current03").put("current", JSONObject().put("manifest_version", "4")
                .put("manifest_digest", b64(ByteArray(32) { 3 })).put("manifest_ancestry_sha256", b64(ByteArray(32) { 4 })))
            // This synchronous entry must invalidate old lifetimes before the worker/Room queue.
            h.runtime.accept(changed.toString().toByteArray())
            assertThrows(Exception::class.java) { installed.requireRamCurrent() }
            io {}; assertEquals(0, h.selected)
            assertEquals("installed", io { h.storage.dao().head(f.selected.electionId)!!.state })
        }
    }
    @Test fun wrongAckAndTimedOutReadRetainPreparedHistoryAndExplicitResumeDoesNotResetRate(): Unit = Profile03ManifestTestFixture().use { f ->
        Harness(f).use { h ->
            h.original(); val tip = h.history(); h.advance()
            h.accept(h.acknowledgement(tip).put("tip_ancestry_sha256", b64(ByteArray(32) { 9 })))
            assertThrows(Exception::class.java) { h.runtime.currentInstalled() }
            assertEquals("prepared", io { h.storage.dao().head(f.selected.electionId)!!.state })
            val count = h.sent.size
            h.runtime.checkSetup(); io {}; assertEquals(count, h.sent.size)
            h.advance(); assertEquals(count + 1, h.sent.size)
            assertEquals("payload_profile_manifest_original03_request", h.sent.last().getString("type"))
            h.elapsed += 2_001; io { h.runtime.requestIfDue() }
            h.elapsed += 25_000; io { h.runtime.requestIfDue() }
            assertEquals(count + 1, h.sent.size)
            assertEquals("prepared", io { h.storage.dao().head(f.selected.electionId)!!.state })
        }
    }
    @Test fun coldInstalledPhaseAndPriorReadbackRequireNewHistoryAndActualLeaseAcknowledgement(): Unit = Profile03ManifestTestFixture().use { f ->
        val tip = Harness(f, retainDatabase = true).use { h ->
            h.original(); val tip = h.history(); h.advance(); h.accept(h.acknowledgement(tip))
            h.runtime.currentInstalled().requireRamCurrent()
            tip
        }
        Harness(f, preserveDatabase = true, connectionEpoch = f.f.line.epoch + 1, serverBaseMs = 400_000).use { cold ->
            assertThrows(Exception::class.java) { cold.runtime.currentInstalled() }
            cold.original()
            assertEquals("installed", io { cold.storage.dao().head(f.selected.electionId)!!.state })
            assertThrows(Exception::class.java) { cold.runtime.currentInstalled() }
            cold.advance()
            assertEquals("payload_profile_manifest03_request", cold.sent.last().getString("type"))
            assertEquals(tip.authority.version.toString(), cold.sent.last().getString("after_version"))
            val page = f.page(tip, emptyList(), tip, checkNotNull(cold.clock.nowMs()))
            cold.accept(cold.reply("payload_profile_manifest03").put("history", JSONObject(page.bytes().toString(Charsets.UTF_8))))
            assertThrows(Exception::class.java) { cold.runtime.currentInstalled() }
            cold.advance(); assertEquals("payload_profile_manifest03_installed", cold.sent.last().getString("type"))
            cold.accept(cold.acknowledgement(tip))
            val held = cold.runtime.currentInstalled(); held.requireRamCurrent()
            assertEquals(cold.connectionEpoch, held.session.connectionEpoch)
            assertEquals(0, cold.selected)
        }
    }
    @Test fun explicitCheckNeverRenewsTheSixtyFourNonceBudget(): Unit = Profile03ManifestTestFixture().use { f ->
        Harness(f).use { h ->
            io { h.runtime.requestIfDue() }
            repeat(64) { index ->
                if (index > 0) {
                    // Actual trusted time is freshly resampled at least every50seconds;
                    //64 history requests do not need64 additional metadata samples.
                    h.runtime.checkSetup(); io {}; h.advance(sampleNow = index % 2 == 0)
                }
                assertEquals(index + 1, h.sent.size)
                h.accept(h.reply("payload_profile_manifest_original03").put("line_id", f.f.line.line)
                    .put("binding_id", UUID(0, 991)).put("evidence", JSONObject(f.original.evidence)))
                assertThrows(Exception::class.java) { h.runtime.currentInstalled() }
            }
            h.runtime.checkSetup(); io {}; h.advance()
            assertEquals(64, h.sent.size)
            assertEquals(64, h.sent.map { it.getString("challenge") }.toSet().size)
            assertNull(io { h.storage.dao().head(f.selected.electionId) })
            assertTrue(h.withdrawals >= 64)
        }
    }
    private fun b64(b: ByteArray) = Profile03ElectionEncoding.encode(b)
}
