// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class CompleteSelectionPreparationCoordinatorTest {
    private fun physical(id: Int = 7) = ProfileSubscriptionObservation(id, 40, false, 0, 0)
    private fun embedded(id: Int = 8, port: Int = 1) =
        ProfileSubscriptionObservation(id, 50, true, port, 1)

    private class Reads : Executor {
        var queued = false
        var rejected = false
        val work = ArrayList<Runnable>()
        override fun execute(command: Runnable) {
            if (rejected) throw java.util.concurrent.RejectedExecutionException()
            if (queued) work.add(command) else command.run()
        }
        fun take() = work.removeAt(0)
        fun drain() {
            var count = 0
            while (work.isNotEmpty()) { check(++count <= 64); take().run() }
        }
    }

    private class Source(var rows: List<ProfileSubscriptionObservation>?) {
        var api = 34
        var permission = true
        var initialCallback = true
        var reads = 0
        var registrations = 0
        var closes = 0
        val changed = ArrayList<() -> Unit>()
        var beforeRead: (() -> Unit)? = null
        var beforeClose: ((Int) -> Unit)? = null
        fun adapter(notify: () -> Unit, executor: Executor): CompleteSubscriptionObservationAdapter {
            val actual = object : ProfileObservationSource {
                override fun permissionGranted() = permission
                override fun register(callback: () -> Unit): AutoCloseable {
                    val number = ++registrations
                    val update = { callback(); notify() }
                    changed.add(update)
                    if (initialCallback) update()
                    return AutoCloseable { beforeClose?.invoke(number); closes++ }
                }
                override fun readComplete(): List<ProfileSubscriptionObservation>? {
                    reads++
                    beforeRead?.invoke()
                    return rows
                }
            }
            return CompleteSubscriptionObservationAdapter({ api }, actual, { it(); true }, executor)
        }
    }

    private fun coordinator(source: Source, reads: Reads = Reads()) =
        CompleteSelectionPreparationCoordinator({ source.adapter(it, reads) }, reads)

    @Test fun explicitPhysicalSelectionKeepsAllActivePeersInPreparation() {
        val rows = listOf(physical(), embedded())
        val source = Source(rows)
        val owner = coordinator(source)
        try {
            assertEquals(0, source.registrations)
            owner.select(7)
            val held = checkNotNull(owner.currentPreparation())
            assertEquals(ObservedSubscriptionKind.PHYSICAL, held.selected.kind)
            assertEquals(7, held.selected.subscriptionId)
            assertEquals(listOf(7, 8), held.activeRows.map { it.subscriptionId })
            assertEquals(rows, source.rows)
            assertTrue(owner.isCurrent(held))
        } finally { owner.close() }
    }

    @Test fun explicitlySelectedSameCardEmbeddedPortKeepsTheOtherPortActive() {
        val rows = listOf(embedded(7, 0), embedded(8, 1))
        val source = Source(rows)
        val owner = coordinator(source)
        try {
            owner.select(8)
            val held = checkNotNull(owner.currentPreparation())
            assertEquals(ObservedSubscriptionKind.EMBEDDED, held.selected.kind)
            assertEquals(1, held.selected.portIndex)
            assertEquals(2, held.activeRows.size)
            assertEquals(rows, source.rows)
        } finally { owner.close() }
    }

    @Test fun absentExplicitSelectionNeverChoosesTheFirstOrRemainingPeer() {
        val source = Source(listOf(physical(), embedded()))
        val owner = coordinator(source)
        try {
            owner.select(null)
            owner.select(-1)
            owner.refresh()
            assertNull(owner.currentPreparation())
            assertEquals(0, source.registrations)
            assertEquals(0, source.reads)
            owner.select(9)
            assertNull(owner.currentPreparation())
            assertEquals(listOf(7, 8), checkNotNull(source.rows).map { it.subscriptionId })
        } finally { owner.close() }
    }

    @Test fun preparationWaitsForSuccessfulRegistrationAndItsInitialCallback() {
        val source = Source(listOf(physical(), embedded())).apply { initialCallback = false }
        val owner = coordinator(source)
        try {
            owner.select(7)
            assertEquals(1, source.registrations)
            assertEquals(0, source.reads)
            assertNull(owner.currentPreparation())
            source.changed[0].invoke()
            assertTrue(owner.isCurrent(checkNotNull(owner.currentPreparation())))
        } finally { owner.close() }
    }

    @Test fun sameCountPeerReplacementRetiresBeforeQueuedCoherentRefresh() {
        val source = Source(listOf(physical(), embedded()))
        val reads = Reads()
        val owner = coordinator(source, reads)
        try {
            owner.select(7)
            val old = checkNotNull(owner.currentPreparation())
            reads.queued = true
            source.rows = listOf(physical(), embedded(9))
            source.changed[0].invoke()
            assertFalse(owner.isCurrent(old))
            assertNull(owner.currentPreparation())
            reads.drain()
            val fresh = checkNotNull(owner.currentPreparation())
            assertEquals(listOf(7, 9), fresh.activeRows.map { it.subscriptionId })
            assertTrue(owner.isCurrent(fresh))
        } finally { owner.close() }
    }

    @Test fun staleQueuedReadCannotTouchOrRetireAReplacementSelection() {
        val source = Source(listOf(physical(), embedded()))
        val reads = Reads()
        val owner = coordinator(source, reads)
        try {
            owner.select(7)
            reads.queued = true
            owner.refresh()
            val oldJob = reads.take()
            owner.select(8)
            reads.drain()
            val fresh = checkNotNull(owner.currentPreparation())
            val before = source.reads
            oldJob.run()
            assertEquals(before, source.reads)
            assertSame(fresh, owner.currentPreparation())
            assertTrue(owner.isCurrent(fresh))
            assertEquals(8, fresh.selected.subscriptionId)
            assertEquals(1, source.closes)
        } finally { owner.close() }
    }

    @Test fun replacementRetiresBeforeHeldCleanupAndCannotOverrideALaterChoice() {
        val source = Source(listOf(physical(), embedded(), embedded(9, 2)))
        val owner = coordinator(source)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var worker: FutureTask<Unit>? = null
        try {
            owner.select(7)
            val old = checkNotNull(owner.currentPreparation())
            source.beforeClose = { number -> if (number == 1) {
                entered.countDown(); check(release.await(2, TimeUnit.SECONDS))
            } }
            worker = FutureTask { owner.select(8); Unit }
            Thread(worker, "synthetic-selection-cleanup").start()
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertFalse(owner.isCurrent(old))
            assertNull(owner.currentPreparation())
            owner.select(9)
            val latest = checkNotNull(owner.currentPreparation())
            release.countDown()
            worker.get(2, TimeUnit.SECONDS)
            assertSame(latest, owner.currentPreparation())
            assertTrue(owner.isCurrent(latest))
            assertEquals(9, latest.selected.subscriptionId)
            assertEquals(2, source.registrations)
        } finally { release.countDown(); worker?.get(2, TimeUnit.SECONDS); owner.close() }
    }

    @Test fun stopDuringHeldReadPreventsAnyLatePreparationPublication() {
        val source = Source(listOf(physical(), embedded()))
        val reads = Reads()
        val owner = coordinator(source, reads)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val once = AtomicBoolean()
        var worker: FutureTask<Unit>? = null
        try {
            owner.select(7)
            val old = checkNotNull(owner.currentPreparation())
            reads.queued = true
            owner.refresh()
            val job = reads.take()
            source.beforeRead = { if (once.compareAndSet(false, true)) {
                entered.countDown(); check(release.await(2, TimeUnit.SECONDS))
            } }
            worker = FutureTask { job.run(); Unit }
            Thread(worker, "synthetic-selection-read").start()
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            owner.stop()
            assertFalse(owner.isCurrent(old))
            release.countDown()
            worker.get(2, TimeUnit.SECONDS)
            assertNull(owner.currentPreparation())
            assertEquals(1, source.closes)
        } finally { release.countDown(); worker?.get(2, TimeUnit.SECONDS); owner.close() }
    }

    @Test fun permissionWithdrawalRetiresBeforeListenerCleanup() {
        val source = Source(listOf(physical(), embedded()))
        val owner = coordinator(source)
        try {
            owner.select(7)
            val old = checkNotNull(owner.currentPreparation())
            source.beforeClose = {
                assertFalse(owner.isCurrent(old))
                assertNull(owner.currentPreparation())
            }
            source.permission = false
            owner.permissionLost()
            assertFalse(owner.isCurrent(old))
            assertEquals(1, source.closes)
        } finally { owner.close() }
    }

    @Test fun refusedReadSubmissionClosesOnlyItsOwnLateRegistrationHandle() {
        val source = Source(listOf(physical(), embedded()))
        val reads = Reads().apply { rejected = true }
        val owner = coordinator(source, reads)
        try {
            owner.select(7)
            assertNull(owner.currentPreparation())
            assertEquals(1, source.registrations)
            assertEquals(1, source.closes)
            assertEquals(0, source.reads)
        } finally { owner.close() }
    }

    @Test fun olderApiAndIncompleteOrAmbiguousWholeReadsRemainRefused() {
        val sources = listOf(
            Source(listOf(physical(), embedded())).apply { api = 32 },
            Source(null),
            Source(listOf(physical(), physical())),
            Source(listOf(ProfileSubscriptionObservation(7, 40, true, -1, 0)))
        )
        sources.forEach { source ->
            val owner = coordinator(source)
            try { owner.select(7); assertNull(owner.currentPreparation()) }
            finally { owner.close() }
        }
    }

    @Test fun closeIsPermanentAndStopRequiresAFreshHeldPreparation() {
        val source = Source(listOf(physical(), embedded()))
        val owner = coordinator(source)
        owner.select(7)
        val old = checkNotNull(owner.currentPreparation())
        owner.stop()
        assertFalse(owner.isCurrent(old))
        owner.select(7)
        val fresh = checkNotNull(owner.currentPreparation())
        assertNotSame(old, fresh)
        owner.close()
        val registrations = source.registrations
        owner.select(8)
        owner.refresh()
        assertFalse(owner.isCurrent(fresh))
        assertNull(owner.currentPreparation())
        assertEquals(registrations, source.registrations)
    }

    @Test fun explicitReselectionAfterRefusedWholeReadRequiresANewRegistration() {
        val source = Source(null)
        val owner = coordinator(source)
        try {
            owner.select(7)
            assertNull(owner.currentPreparation())
            val refusedRegistrations = source.registrations
            source.rows = listOf(physical(), embedded())
            owner.select(7)
            val fresh = checkNotNull(owner.currentPreparation())
            assertEquals(refusedRegistrations + 1, source.registrations)
            assertEquals(7, fresh.selected.subscriptionId)
            assertTrue(owner.isCurrent(fresh))
        } finally { owner.close() }
    }
}
