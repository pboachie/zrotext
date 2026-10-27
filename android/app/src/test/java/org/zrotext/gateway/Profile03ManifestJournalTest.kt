// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room/GCM plus genuine ephemeral proof chains. No authenticated socket, hardware
 * custody, physical permission, current readback handle or effect acceptance is asserted. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ManifestJournalTest {
    private fun store() = Profile03ManifestStore(RuntimeEnvironment.getApplication(), ConversationExistingJournalProtection {
        SecretKeySpec(ByteArray(32) { 71 }, "AES")
    })
    private fun <T> io(action: () -> T): T {
        val future = CompletableFuture<T>()
        JournalRuntime.io.execute { try { future.complete(action()) } catch (failure: Throwable) { future.completeExceptionally(failure) } }
        return future.get(20, TimeUnit.SECONDS)
    }
    @Test fun fortyOneAcceptedRenewalsPersistInPagesAndRestoreInBoundedChunksWithoutALifetimeCap(): Unit = Profile03ManifestTestFixture().use { f ->
        val app = RuntimeEnvironment.getApplication(); app.deleteDatabase(Profile03ManifestDatabase.FILE)
        val entries = f.entries(41); val tip = f.checkpoint(entries)
        var first = store()
        try {
            io {
                val chain = Profile03ManifestChain(first)
                val start = chain.begin(f.selected) { 800_000 }
                var saved = checkNotNull(chain.advance(start) { 800_000 })
                entries.chunked(8).forEachIndexed { index, page ->
                    saved = chain.append(saved, f.page(saved.checkpoint, page, tip), { 800_000 }, {})
                    assertEquals(if (index == 5) "prepared" else "progress", saved.head!!.state)
                }
                assertEquals(43L, saved.head!!.version)
                first.close(); first = store()
                val cold = Profile03ManifestChain(first); val restoration = cold.begin(f.selected) { 800_000 }
                var complete: Profile03ManifestChain.Saved? = null; var chunks = 0
                while (complete == null) { complete = cold.advance(restoration) { 800_000 }; chunks++; assertTrue(chunks <= 6) }
                val recovered = checkNotNull(complete)
                assertEquals(6, chunks); assertEquals("prepared", recovered.head!!.state)
                assertArrayEquals(tip.authority.signedBytes, recovered.checkpoint.authority.signedBytes)
                assertArrayEquals(tip.ancestry(), recovered.checkpoint.ancestry())
                assertEquals(1, first.dao().entries(f.selected.electionId, 42).size)
                assertTrue(first.dao().entries(f.selected.electionId, 43).isEmpty())
                // A lower cursor/fork does not replace the retained highwater or originals.
                assertTrue(runCatching { cold.append(recovered, f.page(f.base, entries.take(1), tip), { 800_000 }, {}) }.isFailure)
                assertEquals(43L, first.dao().head(f.selected.electionId)!!.version)
            }
        } finally { io { first.close() }; app.deleteDatabase(Profile03ManifestDatabase.FILE) }
    }
    @Test fun protectedCheckpointAndEntryBindOriginalAcceptancePrefixAndScope(): Unit = Profile03ManifestTestFixture().use { f ->
        val app = RuntimeEnvironment.getApplication(); app.deleteDatabase(Profile03ManifestDatabase.FILE)
        val entry = f.entries(1).single(); val tip = f.checkpoint(listOf(entry)); val storage = store()
        try { io {
            val page = f.page(f.base, listOf(entry), tip)
            val head = storage.head(f.selected.electionId, f.identity, 2, tip, page, "prepared")
            assertArrayEquals(tip.authority.signedBytes, storage.manifest(head))
            for (changed in listOf(head.copy(acceptedMs = head.acceptedMs + 1, tipAcceptedMs = head.tipAcceptedMs + 1), head.copy(ancestry = "aa".repeat(32)),
                head.copy(originalIdentity = "bb".repeat(32)), head.copy(state = "installed")))
                assertTrue(runCatching { storage.manifest(changed) }.isFailure)
            val row = storage.entry(f.selected.electionId, f.base.ancestry(), tip.ancestry(), entry)
            assertArrayEquals(entry.statement.bytes(), storage.entry(row).statement.bytes())
            assertTrue(runCatching { storage.entry(row.copy(acceptedMs = row.acceptedMs + 1)) }.isFailure)
            assertTrue(runCatching { storage.entry(row.copy(priorAncestry = "cc".repeat(32))) }.isFailure)
        } } finally { io { storage.close() }; app.deleteDatabase(Profile03ManifestDatabase.FILE) }
    }
    @Test fun withdrawalInsideAtomicAppendRollsBackEntriesAndHighwaterTogether(): Unit = Profile03ManifestTestFixture().use { f ->
        val app = RuntimeEnvironment.getApplication(); app.deleteDatabase(Profile03ManifestDatabase.FILE)
        val entry = f.entries(1).single(); val tip = f.checkpoint(listOf(entry)); val storage = store()
        try { io {
            val head = storage.head(f.selected.electionId, f.identity, 2, tip, f.page(f.base, listOf(entry), tip), "prepared")
            val row = storage.entry(f.selected.electionId, f.base.ancestry(), tip.ancestry(), entry)
            val checks = AtomicInteger()
            assertTrue(runCatching { storage.dao().append(null, head, listOf(row)) { check(checks.incrementAndGet() == 1) } }.isFailure)
            assertEquals(2, checks.get()); assertNull(storage.dao().head(f.selected.electionId))
            assertTrue(storage.dao().entries(f.selected.electionId, 2).isEmpty())
            storage.dao().append(null, head, listOf(row)) {}
            assertEquals(3L, storage.dao().head(f.selected.electionId)!!.version)
        } } finally { io { storage.close() }; app.deleteDatabase(Profile03ManifestDatabase.FILE) }
    }
}
