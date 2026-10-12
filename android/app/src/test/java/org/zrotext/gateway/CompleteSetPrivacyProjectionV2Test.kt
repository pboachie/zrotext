// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Synthetic sources only. These declarations confer no signing, installation or radio authority. */
class CompleteSetPrivacyProjectionV2Test {
    private val physical = row(7, false, 20, 0, 0)
    private val embedded = row(8, true, 30, 0, 1)

    @Test fun foreignAndEqualCopiedSnapshotsCannotObtainIssuerProjection() {
        val local = Fixture()
        val other = Fixture()
        val actual = local.snapshot()
        val equal = copiedSnapshot(actual)
        assertNotSame(actual, equal)
        assertEquals(actual.selected, equal.selected)
        assertEquals(actual.activeRows, equal.activeRows)
        assertFalse(local.observer.isCurrent(equal))
        assertNull(issue(other, actual))
        assertNull(issue(local, equal))
        assertNull(local.observer.capturePrivacyProjection(equal))
        val projection = requireNotNull(issue(local, actual))
        assertTrue(projection.isCurrent())
        assertNull(issue(local, other.snapshot()))
        assertSame(projection, issue(local, actual))
    }

    @Test fun bothReadinessBarriersPrecedeProjectionIssuance() {
        for (barrier in listOf("registration", "callback")) {
            val f = Fixture(ready = false)
            if (barrier == "registration") f.observer.initialCallback(f.token)
            else f.observer.registrationSucceeded(f.token)
            assertNull(f.observer.observeSelected(7))
            assertNull(issue(f, copiedSnapshot(Fixture().snapshot(), physical, listOf(physical))))
            assertEquals(0, f.reads.get())
        }
    }

    @Test fun mixedFullSetAllowsEitherExplicitSelectionWithoutRemovingPeer() {
        val f = Fixture()
        val first = requireNotNull(issue(f, f.snapshot(7)))
        val firstBytes = ByteBuffer.wrap(first.observation().bytes())
        assertEquals(33, firstBytes.short.toInt() and 0xffff)
        assertEquals(2, firstBytes.short.toInt() and 0xffff)
        assertEquals(7, firstBytes.int)
        assertEquals(1, firstBytes.get().toInt())
        val secondSnapshot = f.snapshot(8)
        val second = requireNotNull(CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
            f.observer, secondSnapshot) { assertFalse(first.isCurrent()) })
        val secondBytes = ByteBuffer.wrap(second.observation().bytes())
        secondBytes.position(4)
        assertEquals(8, secondBytes.int)
        assertEquals(2, secondBytes.get().toInt())
        assertEquals(2, second.count)
        assertEquals(listOf(7, 8), f.rows.map { it.subscriptionId })
        assertFalse(first.isCurrent())
        assertTrue(second.isCurrent())
        assertNotEquals(first.selectedLease, second.selectedLease)
        assertEquals(first.monitorLifetime, second.monitorLifetime)
    }

    @Test fun sameEuiccAndSlotUsesOneCardAliasAndDistinctPortProfiles() {
        val f = Fixture(listOf(row(7, true, 30, 0, 1), row(8, true, 30, 1, 1)))
        val projection = requireNotNull(issue(f, f.snapshot(8)))
        val opaque = rows(projection)
        assertEquals(2, opaque.size)
        assertEquals(1, opaque.map { it.card }.toSet().size)
        assertEquals(2, opaque.map { it.profile }.toSet().size)
        assertEquals(setOf(0, 1), opaque.map { it.port }.toSet())
        assertEquals(setOf(1), opaque.map { it.slot }.toSet())
        assertEquals(setOf(2), opaque.map { it.kind }.toSet())
        val selected = ByteBuffer.wrap(projection.observation().bytes())
        selected.position(41)
        assertEquals(1, selected.int)
        assertEquals(1, selected.int)
    }

    @Test fun differentCardsAndProfilesHaveIndependentNonzeroAliases() {
        val projection = requireNotNull(issue(Fixture()))
        val opaque = rows(projection)
        assertEquals(2, opaque.map { it.card }.toSet().size)
        assertEquals(2, opaque.map { it.profile }.toSet().size)
        val all = opaque.flatMap { listOf(it.card, it.profile) } +
            listOf(projection.monitorLifetime, projection.selectedLease)
        assertFalse(all.contains(UUID(0, 0)))
        assertEquals(all.size, all.toSet().size)
        assertEquals("CompleteSetPrivacyProjectionV2(local declaration, redacted)", projection.toString())
    }

    @Test fun cachedCurrentProjectionDoesNotRereadOrReenterAssembly() {
        val f = Fixture()
        val snapshot = f.snapshot()
        val reads = f.reads.get()
        val first = requireNotNull(issue(f, snapshot))
        val assemblies = AtomicInteger()
        val second = CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
            f.observer, snapshot) { assemblies.incrementAndGet(); error("Unexpected reconstruction") }
        assertSame(first, second)
        assertEquals(0, assemblies.get())
        assertEquals(reads, f.reads.get())
        assertTrue(first.isCurrent())
    }

    @Test fun callbackRetiresOldProjectionBeforeAnyRefreshAndChangesEpoch() {
        val f = Fixture()
        val snapshot = f.snapshot()
        val first = requireNotNull(issue(f, snapshot))
        f.observer.subscriptionsChanged(f.token)
        assertFalse(first.isCurrent())
        assertNull(issue(f, snapshot))
        val fresh = requireNotNull(issue(f, f.snapshot()))
        assertTrue(fresh.isCurrent())
        assertTrue(fresh.observerEpoch > first.observerEpoch)
        assertEquals(first.monitorLifetime, fresh.monitorLifetime)
        assertNotEquals(first.selectedLease, fresh.selectedLease)
        assertFalse(first.completeSetPreimage().contentEquals(fresh.completeSetPreimage()))
    }

    @Test fun permissionStopAndReplacementCannotRestoreOldProjection() {
        for (event in listOf("permission", "stop", "replacement")) {
            val f = Fixture()
            val snapshot = f.snapshot()
            val first = requireNotNull(issue(f, snapshot))
            when (event) {
                "permission" -> f.observer.permissionLost()
                "stop" -> f.observer.stop()
                else -> f.token = f.observer.beginRegistration()
            }
            assertFalse(first.isCurrent())
            assertNull(issue(f, snapshot))
            assertNull(f.observer.observeSelected(7))
            if (event != "replacement") f.token = f.observer.beginRegistration()
            f.observer.registrationSucceeded(f.token)
            f.observer.initialCallback(f.token)
            val freshSnapshot = f.snapshot()
            val fresh = requireNotNull(CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
                f.observer, freshSnapshot) { assertFalse(first.isCurrent()) })
            assertNotEquals(first.monitorLifetime, fresh.monitorLifetime)
            assertTrue(fresh.isCurrent())
            assertNull(issue(f, snapshot))
            assertTrue(fresh.isCurrent())
        }
    }

    @Test fun equalCountPeerReplacementRetiresBeforeNewCommitment() {
        val f = Fixture()
        val old = requireNotNull(issue(f, f.snapshot()))
        f.rows = listOf(physical, row(9, true, 40, 1, 2))
        assertNull(f.observer.observeSelected(7))
        assertFalse(old.isCurrent())
        val fresh = requireNotNull(issue(f, f.snapshot()))
        assertEquals(old.count, fresh.count)
        assertFalse(old.observation().bytes().copyOfRange(89, 121)
            .contentEquals(fresh.observation().bytes().copyOfRange(89, 121)))
        assertTrue(fresh.isCurrent())
    }

    @Test fun actualApiChangeWithEqualRowsRetiresPreviouslyCapturedApi() {
        val f = Fixture()
        val old = requireNotNull(issue(f, f.snapshot()))
        f.api = 34
        assertNull(f.observer.observeSelected(7))
        assertFalse(old.isCurrent())
        val fresh = requireNotNull(issue(f, f.snapshot()))
        assertEquals(34, fresh.apiLevel)
        assertTrue(fresh.observerEpoch > old.observerEpoch)
        assertEquals(34, ByteBuffer.wrap(fresh.observation().bytes()).short.toInt() and 0xffff)
    }

    @Test fun unencodableApiAndIncompleteReadCannotMintDeclaration() {
        val high = Fixture()
        high.api = 65536
        assertNull(issue(high, high.snapshot()))
        for (condition in listOf("permission", "complete", "readable", "oldApi")) {
            val f = Fixture()
            val old = requireNotNull(issue(f, f.snapshot()))
            when (condition) {
                "permission" -> f.permission = false
                "complete" -> f.complete = false
                "readable" -> f.readable = false
                else -> f.api = 32
            }
            assertNull(f.observer.observeSelected(7))
            assertFalse(old.isCurrent())
        }
    }

    @Test fun returnedByteCopiesCannotAlterCachedCanonicalDeclaration() {
        val f = Fixture()
        val snapshot = f.snapshot()
        val projection = requireNotNull(issue(f, snapshot))
        val expected = projection.observation().bytes()
        val preimage = projection.completeSetPreimage()
        projection.observation().bytes().fill(0)
        projection.completeSetPreimage().fill(0)
        assertArrayEquals(expected, projection.observation().bytes())
        assertArrayEquals(preimage, projection.completeSetPreimage())
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(preimage),
            expected.copyOfRange(89, 121))
        assertSame(projection, issue(f, snapshot))
        assertTrue(projection.isCurrent())
    }

    @Test fun constructionBarrierDoesNotDelayCallbackRetirement() {
        val f = Fixture()
        val snapshot = f.snapshot()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val builder = Worker { CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
            f.observer, snapshot) { entered.countDown(); await(release) } }
        builder.start()
        val callback = Worker { f.observer.subscriptionsChanged(f.token); null }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            callback.start()
            assertTrue(callback.finished.await(2, TimeUnit.SECONDS))
            callback.assertSucceeded()
            assertFalse(f.observer.isCurrent(snapshot))
        } finally { release.countDown(); builder.join(); callback.joinIfStarted() }
        builder.assertSucceeded()
        assertNull(builder.result.get())
        assertNotNull(issue(f, f.snapshot()))
    }

    @Test fun delayedOldConstructionCannotCacheAfterEveryWithdrawal() {
        for (event in listOf("selection", "permission", "stop", "replacement")) {
            val f = Fixture()
            val snapshot = f.snapshot()
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val builder = Worker { CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
                f.observer, snapshot) { entered.countDown(); await(release) } }
            builder.start()
            val withdraw = Worker {
                when (event) {
                    "selection" -> f.observer.observeSelected(8)
                    "permission" -> f.observer.permissionLost()
                    "stop" -> f.observer.stop()
                    else -> f.token = f.observer.beginRegistration()
                }
                null
            }
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                withdraw.start()
                assertTrue(withdraw.finished.await(2, TimeUnit.SECONDS))
                withdraw.assertSucceeded()
                assertFalse(f.observer.isCurrent(snapshot))
            } finally { release.countDown(); builder.join(); withdraw.joinIfStarted() }
            builder.assertSucceeded()
            assertNull(builder.result.get())
        }
    }

    @Test fun concurrentFirstBuildersReturnOneActualCachedProjection() {
        val f = Fixture()
        val snapshot = f.snapshot()
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val workers = List(2) { Worker {
            CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(f.observer, snapshot) {
                entered.countDown(); await(release)
            }
        } }
        workers.forEach { it.start() }
        try { assertTrue(entered.await(2, TimeUnit.SECONDS)) }
        finally { release.countDown(); workers.forEach { it.join() } }
        workers.forEach { it.assertSucceeded() }
        val actual = requireNotNull(workers[0].result.get())
        assertSame(actual, workers[1].result.get())
        assertSame(actual, issue(f, snapshot))
        assertTrue(actual.isCurrent())
    }

    @Test fun staleBuildDoesNotRetireFreshProjectionPublishedDuringItsBarrier() {
        val f = Fixture()
        val stale = f.snapshot()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val builder = Worker { CompleteSetPrivacyProjectionV2.issueWithAssemblyBarrierForTest(
            f.observer, stale) { entered.countDown(); await(release) } }
        builder.start()
        var fresh: CompleteSetPrivacyProjectionV2? = null
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            f.observer.subscriptionsChanged(f.token)
            fresh = requireNotNull(issue(f, f.snapshot()))
        } finally { release.countDown(); builder.join() }
        builder.assertSucceeded()
        assertNull(builder.result.get())
        assertTrue(requireNotNull(fresh).isCurrent())
        assertSame(fresh, issue(f, f.snapshot()))
    }

    @Test fun adapterProjectsOnlyItsHeldSnapshotWithoutAdditionalPlatformReads() {
        val f = AdapterFixture()
        assertEquals(0, f.source.reads.get())
        f.adapter.select(7)
        val snapshot = requireNotNull(f.adapter.observe())
        val before = f.source.reads.get()
        val actual = requireNotNull(f.adapter.privacyProjection(snapshot))
        assertEquals(before, f.source.reads.get())
        assertSame(actual, f.adapter.privacyProjection(snapshot))
        assertNull(f.adapter.privacyProjection(Fixture().snapshot()))
        assertTrue(actual.isCurrent())
        assertEquals(2, actual.count)
        f.adapter.close()
        assertFalse(actual.isCurrent())
        assertNull(f.adapter.privacyProjection(snapshot))
    }

    @Test fun adapterReplacementRetiresBeforeHeldOldHandleClosure() {
        val f = AdapterFixture()
        f.adapter.select(7)
        val oldSnapshot = requireNotNull(f.adapter.observe())
        val old = requireNotNull(f.adapter.privacyProjection(oldSnapshot))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        f.source.onClose = { entered.countDown(); await(release) }
        val replacement = Worker { f.adapter.select(8); null }
        replacement.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertFalse(old.isCurrent())
            assertNull(f.adapter.privacyProjection(oldSnapshot))
        } finally { release.countDown(); replacement.join() }
        replacement.assertSucceeded()
        f.source.onClose = null
        val fresh = requireNotNull(f.adapter.privacyProjection(requireNotNull(f.adapter.observe())))
        assertTrue(fresh.isCurrent())
        assertFalse(old.isCurrent())
        assertEquals(1, f.source.closes.get())
        f.adapter.close()
    }

    @Test fun adapterCallbackPermissionAndStopSynchronouslyRetireProjections() {
        for (event in listOf("callback", "permission", "stop")) {
            val f = AdapterFixture()
            f.adapter.select(7)
            val snapshot = requireNotNull(f.adapter.observe())
            val old = requireNotNull(f.adapter.privacyProjection(snapshot))
            when (event) {
                "callback" -> requireNotNull(f.source.changed).invoke()
                "permission" -> f.adapter.permissionLost()
                else -> f.adapter.stop()
            }
            assertFalse(old.isCurrent())
            assertNull(f.adapter.privacyProjection(snapshot))
            f.adapter.close()
        }
    }

    private fun row(sub: Int, embedded: Boolean, card: Int, port: Int, slot: Int) =
        SubscriptionObservationRow(sub,
            if (embedded) ObservedSubscriptionKind.EMBEDDED else ObservedSubscriptionKind.PHYSICAL,
            card, port, slot)

    private inner class Fixture(var rows: List<SubscriptionObservationRow> = listOf(physical, embedded),
        ready: Boolean = true) {
        var api = 33
        var permission = true
        var complete = true
        var readable = true
        val reads = AtomicInteger()
        val observer = CompleteSubscriptionObserver(CompleteSubscriptionSource {
            reads.incrementAndGet()
            CompleteSubscriptionRead(api, permission, readable, complete, rows)
        })
        var token = observer.beginRegistration()
        init { if (ready) { observer.registrationSucceeded(token); observer.initialCallback(token) } }
        fun snapshot(selected: Int = 7) = requireNotNull(observer.observeSelected(selected))
    }

    private fun issue(f: Fixture, snapshot: CompleteSelectionSnapshot? = null) =
        CompleteSetPrivacyProjectionV2.issue(f.observer, snapshot ?: f.snapshot())

    // Copy the existing permitted implementation; test modules cannot subclass a sealed type.
    // No observer owns this new object, even when its rows, generation and API are equal.
    private fun copiedSnapshot(source: CompleteSelectionSnapshot,
        selected: SubscriptionObservationRow = source.selected,
        activeRows: List<SubscriptionObservationRow> = source.activeRows.toList()): CompleteSelectionSnapshot {
        val implementation = source.javaClass
        val constructor = implementation.getDeclaredConstructor(SubscriptionObservationRow::class.java,
            List::class.java, java.lang.Long.TYPE, java.lang.Integer.TYPE)
        constructor.isAccessible = true
        val generation = implementation.getDeclaredField("generation").also { it.isAccessible = true }
            .getLong(source)
        val apiLevel = implementation.getDeclaredField("apiLevel").also { it.isAccessible = true }
            .getInt(source)
        return constructor.newInstance(selected, activeRows, generation, apiLevel)
    }

    private data class OpaqueRow(val kind: Int, val card: UUID, val profile: UUID,
        val port: Int, val slot: Int)

    private fun rows(projection: CompleteSetPrivacyProjectionV2): List<OpaqueRow> {
        val input = ByteBuffer.wrap(projection.completeSetPreimage())
        input.position("ZT/line/complete-set/v2\u0000".toByteArray(Charsets.US_ASCII).size + 28)
        val rows = List(projection.count) { OpaqueRow(input.get().toInt(), UUID(input.long, input.long),
            UUID(input.long, input.long), input.int, input.int) }
        assertEquals(0, input.remaining())
        return rows
    }

    private inner class AdapterFixture {
        val source = PlatformSource()
        val adapter = CompleteSubscriptionObservationAdapter({ 33 }, source,
            { operation -> operation(); true }, Executor { _ -> })
    }

    private inner class PlatformSource : ProfileObservationSource {
        val reads = AtomicInteger()
        val closes = AtomicInteger()
        var changed: (() -> Unit)? = null
        var onClose: (() -> Unit)? = null
        override fun permissionGranted() = true
        override fun register(changed: () -> Unit): AutoCloseable {
            this.changed = changed
            changed()
            return AutoCloseable { closes.incrementAndGet(); onClose?.invoke() }
        }
        override fun readComplete(): List<ProfileSubscriptionObservation> {
            reads.incrementAndGet()
            return listOf(physical, embedded).map { ProfileSubscriptionObservation(it.subscriptionId,
                it.cardId, it.kind == ObservedSubscriptionKind.EMBEDDED, it.portIndex, it.slotIndex) }
        }
    }

    private fun await(latch: CountDownLatch) {
        check(latch.await(3, TimeUnit.SECONDS)) { "Synthetic operation did not release" }
    }

    private class Worker(operation: () -> CompleteSetPrivacyProjectionV2?) {
        val result = AtomicReference<CompleteSetPrivacyProjectionV2?>()
        val finished = CountDownLatch(1)
        private val failure = AtomicReference<Throwable?>()
        private var started = false
        private val thread = Thread {
            try { result.set(operation()) }
            catch (error: Throwable) { failure.set(error) }
            finally { finished.countDown() }
        }.also { it.isDaemon = true }
        fun start() { started = true; thread.start() }
        fun joinIfStarted() { if (started) join() }
        fun join() {
            thread.join(4000)
            if (thread.isAlive) { thread.interrupt(); thread.join(1000) }
            assertFalse("Synthetic worker remained alive", thread.isAlive)
        }
        fun assertSucceeded() { failure.get()?.let { throw AssertionError("Synthetic worker failed", it) } }
    }
}
