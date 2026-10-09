// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Synthetic source and schedulers only. No platform registration or authority consumer. */
class CompleteSubscriptionObservationAdapterTest {
    private val physical = row(7, 20, false, 0, 0)
    private val embedded = row(8, 30, true, 0, 1)
    private val hiddenPeer = row(9, 40, true, 1, 2)

    @Test fun completeMixedSetRetainsEveryPeerAndExplicitSelection() {
        val fixture = Fixture(listOf(physical, embedded, hiddenPeer))
        assertEquals(0, fixture.source.registerCalls.get())
        assertEquals(0, fixture.source.readCalls.get())
        assertEquals(0, fixture.reads.executions.get())
        fixture.adapter.select(7)
        val snapshot = requireNotNull(fixture.adapter.observe())
        assertEquals(7, snapshot.selected.subscriptionId)
        assertEquals(ObservedSubscriptionKind.PHYSICAL, snapshot.selected.kind)
        assertEquals(listOf(7, 8, 9), snapshot.activeRows.map { it.subscriptionId })
        assertEquals(listOf(20, 30, 40), snapshot.activeRows.map { it.cardId })
        assertEquals(listOf(0, 0, 1), snapshot.activeRows.map { it.portIndex })
        assertEquals(listOf(0, 1, 2), snapshot.activeRows.map { it.slotIndex })
        fixture.adapter.select(7)
        assertEquals(1, fixture.source.registerCalls.get())
        assertSame(snapshot, fixture.adapter.observe())
        fixture.adapter.select(null)
        assertFalse(fixture.adapter.isCurrent(snapshot))
        assertNull(fixture.adapter.observe())
        assertEquals(1, fixture.source.handles.single().closes.get())
    }

    @Test fun sharedEuiccAndSlotWithDistinctPortsSupportsEitherExplicitChoice() {
        val fixture = Fixture(listOf(row(7, 30, true, 0, 1), row(8, 30, true, 1, 1)))
        val first = fixture.ready(7)
        val oldHandle = fixture.source.handles.single()
        oldHandle.onClose = { assertFalse(fixture.adapter.isCurrent(first)) }
        fixture.adapter.select(8)
        assertFalse(fixture.adapter.isCurrent(first))
        val second = requireNotNull(fixture.adapter.observe())
        assertEquals(8, second.selected.subscriptionId)
        assertEquals(ObservedSubscriptionKind.EMBEDDED, second.selected.kind)
        assertEquals(listOf(0, 1), second.activeRows.map { it.portIndex })
        assertEquals(listOf(1, 1), second.activeRows.map { it.slotIndex })
        assertEquals(2, second.activeRows.size)
        assertEquals(1, oldHandle.closes.get())
        assertEquals(2, fixture.source.registerCalls.get())
    }

    @Test fun olderApiAndMissingOrdinaryPermissionNeverAttachOrRead() {
        for (api in listOf(28, 29, 30, 32, 33)) {
            val fixture = Fixture()
            fixture.api = api
            fixture.source.permission = api != 33
            fixture.adapter.select(7)
            assertNull(fixture.adapter.observe())
            assertEquals(0, fixture.source.registerCalls.get())
            assertEquals(0, fixture.source.readCalls.get())
            assertEquals(0, fixture.reads.executions.get())
        }
    }

    @Test fun initialCallbackBeforeRegisterReturnCannotReadUntilSuccess() {
        val fixture = Fixture()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        fixture.source.onRegister = { _, _ -> entered.countDown(); awaitRelease(release) }
        val worker = Worker { fixture.adapter.select(7) }
        worker.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertNull(fixture.adapter.observe())
            assertEquals(0, fixture.source.readCalls.get())
            assertEquals(0, fixture.reads.executions.get())
        } finally { release.countDown(); worker.join() }
        worker.assertSucceeded()
        assertNotNull(fixture.adapter.observe())
        assertEquals(1, fixture.source.registerCalls.get())
    }

    @Test fun successfulReturnWithoutInitialCallbackCannotRead() {
        val fixture = Fixture()
        fixture.source.callbackBeforeReturn = false
        fixture.adapter.select(7)
        assertNull(fixture.adapter.observe())
        assertEquals(0, fixture.source.readCalls.get())
        assertEquals(0, fixture.reads.executions.get())
        fixture.source.callbacks.single().invoke()
        assertNotNull(fixture.adapter.observe())
        assertEquals(2, fixture.source.readCalls.get())
    }

    @Test fun callbackThenRegistrationThrowNeverExposesObservation() {
        val fixture = Fixture()
        fixture.source.onRegister = { _, _ -> throw IllegalStateException("synthetic attach failure") }
        fixture.adapter.select(7)
        assertNull(fixture.adapter.observe())
        assertEquals(0, fixture.source.readCalls.get())
        assertEquals(1, fixture.source.partialCleanups.get())
        assertEquals(1, fixture.source.handles.single().closes.get())
        val stale = fixture.source.callbacks.single()
        fixture.source.onRegister = null
        val fresh = fixture.ready(7)
        stale()
        assertTrue(fixture.adapter.isCurrent(fresh))
        assertSame(fresh, fixture.adapter.observe())
    }

    @Test fun queuedStartCancelledBeforeMainDispatchNeverRegisters() {
        val main = MainQueue()
        val fixture = Fixture(mainDispatch = main::dispatch)
        fixture.adapter.select(7)
        fixture.adapter.stop()
        main.drain()
        assertEquals(0, fixture.source.registerCalls.get())
        fixture.adapter.select(8)
        fixture.adapter.select(7)
        main.repeatLast()
        main.drain()
        assertEquals(1, fixture.source.registerCalls.get())
        assertEquals(7, requireNotNull(fixture.adapter.observe()).selected.subscriptionId)
    }

    @Test fun lateRegistrationHandleIsClosedExactlyOnceAfterEveryWithdrawal() {
        for (withdrawal in listOf("stop", "permission", "replacement", "close")) {
            val fixture = Fixture()
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            fixture.source.onRegister = { _, _ ->
                if (fixture.source.registerCalls.get() == 1) {
                    entered.countDown(); awaitRelease(release)
                }
            }
            val worker = Worker { fixture.adapter.select(7) }
            worker.start()
            var replacement: CompleteSelectionSnapshot? = null
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                when (withdrawal) {
                    "stop" -> fixture.adapter.stop()
                    "permission" -> { fixture.source.permission = false; fixture.adapter.permissionLost() }
                    "replacement" -> { fixture.adapter.select(8); replacement = fixture.adapter.observe() }
                    else -> fixture.adapter.close()
                }
                assertEquals(0, fixture.source.handles.first().closes.get())
                if (withdrawal != "replacement") assertNull(fixture.adapter.observe())
            } finally { release.countDown(); worker.join() }
            worker.assertSucceeded()
            assertEquals(1, fixture.source.handles.first().closes.get())
            fixture.source.callbacks.get(0).invoke()
            if (withdrawal == "replacement") {
                assertNotNull(replacement)
                assertTrue(fixture.adapter.isCurrent(requireNotNull(replacement)))
                assertEquals(0, fixture.source.handles.last().closes.get())
            } else {
                fixture.source.permission = true
                assertNull(fixture.adapter.observe())
                val calls = fixture.source.registerCalls.get()
                fixture.adapter.select(7)
                if (withdrawal == "close") {
                    assertEquals(calls, fixture.source.registerCalls.get())
                    assertNull(fixture.adapter.observe())
                } else assertNotNull(fixture.adapter.observe())
            }
            assertEquals(1, fixture.source.handles.first().closes.get())
        }
    }

    @Test fun staleCallbackCannotRetireReplacementRegistration() {
        for (replacement in listOf(false, true)) {
            val fixture = Fixture()
            // ready() leaves the original request/revision's refresh queued.
            val old = fixture.ready(7)
            val callback = fixture.source.callbacks.single()
            if (replacement) fixture.adapter.select(8) else callback()
            val fresh = requireNotNull(fixture.adapter.observe())
            val currentHandle = fixture.source.handles.last()
            assertEquals(if (replacement) 8 else 7, fresh.selected.subscriptionId)
            assertFalse(fixture.adapter.isCurrent(old))
            val readsBeforeQueuedJobs = fixture.source.readCalls.get()

            // FIFO executes the OLD captured job after a fresh snapshot already exists.
            fixture.reads.runOne()
            assertEquals(readsBeforeQueuedJobs, fixture.source.readCalls.get())
            assertTrue(fixture.adapter.isCurrent(fresh))
            assertEquals(0, currentHandle.closes.get())

            // Execute the current job too: this harness actually performs both coherent reads.
            fixture.reads.runOne()
            assertEquals(readsBeforeQueuedJobs + 2, fixture.source.readCalls.get())
            assertTrue(fixture.adapter.isCurrent(fresh))
            assertEquals(0, currentHandle.closes.get())
            if (replacement) callback()
            assertTrue(fixture.adapter.isCurrent(fresh))
            assertSame(fresh, fixture.adapter.observe())
            assertEquals(0, currentHandle.closes.get())
        }
    }

    @Test fun callbackStopAndCloseDuringHeldReadRetireBeforeReadRelease() {
        for (withdrawal in listOf("callback", "stop", "close")) {
            val fixture = Fixture()
            val old = fixture.ready(7)
            val hold = holdSecondRead(fixture) { fixture.source.rows }
            val result = AtomicReference<CompleteSelectionSnapshot?>()
            val reader = Worker { result.set(fixture.adapter.observe()) }
            val retired = CountDownLatch(1)
            val retirement = Worker {
                when (withdrawal) {
                    "callback" -> fixture.source.callbacks.get(0).invoke()
                    "stop" -> fixture.adapter.stop()
                    else -> fixture.adapter.close()
                }
                retired.countDown()
            }
            reader.start()
            try {
                assertTrue(hold.entered.await(2, TimeUnit.SECONDS))
                retirement.start()
                assertTrue(retired.await(2, TimeUnit.SECONDS))
                assertFalse(fixture.adapter.isCurrent(old))
            } finally { hold.release.countDown(); reader.join(); retirement.joinIfStarted() }
            reader.assertSucceeded(); retirement.assertSucceeded()
            assertNull(result.get())
            if (withdrawal == "callback") assertNotNull(fixture.adapter.observe())
            else {
                assertNull(fixture.adapter.observe())
                fixture.adapter.select(7)
                if (withdrawal == "stop") assertNotNull(fixture.adapter.observe())
                else assertNull(fixture.adapter.observe())
            }
        }
    }

    @Test fun oldReadNullAfterCallbackCannotWithdrawFreshEpoch() {
        for (throws in listOf(false, true)) {
            val fixture = Fixture()
            val old = fixture.ready(7)
            val hold = holdSecondRead(fixture) {
                if (throws) throw SecurityException("synthetic old read failure") else null
            }
            val result = AtomicReference<CompleteSelectionSnapshot?>()
            val reader = Worker { result.set(fixture.adapter.observe()) }
            reader.start()
            var fresh: CompleteSelectionSnapshot? = null
            try {
                assertTrue(hold.entered.await(2, TimeUnit.SECONDS))
                fixture.source.callbacks.single().invoke()
                fresh = fixture.adapter.observe()
                assertNotNull(fresh)
                assertFalse(fixture.adapter.isCurrent(old))
                assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh)))
            } finally { hold.release.countDown(); reader.join() }
            reader.assertSucceeded()
            assertNull(result.get())
            assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh)))
            assertSame(fresh, fixture.adapter.observe())
            assertEquals(0, fixture.source.handles.single().closes.get())
        }
    }

    @Test fun permissionLossAndRegrantRequireFreshInitialCallback() {
        val fixture = Fixture()
        val old = fixture.ready(7)
        val hold = holdSecondRead(fixture) { null }
        val reader = Worker { assertNull(fixture.adapter.observe()) }
        val withdrawn = CountDownLatch(1)
        val withdrawal = Worker { fixture.source.permission = false; fixture.adapter.permissionLost(); withdrawn.countDown() }
        reader.start()
        var fresh: CompleteSelectionSnapshot? = null
        try {
            assertTrue(hold.entered.await(2, TimeUnit.SECONDS))
            withdrawal.start()
            assertTrue(withdrawn.await(2, TimeUnit.SECONDS))
            assertFalse(fixture.adapter.isCurrent(old))
            fixture.source.permission = true
            assertNull(fixture.adapter.observe())
            fixture.source.callbackBeforeReturn = false
            fixture.adapter.select(7)
            assertNull(fixture.adapter.observe())
            fixture.source.callbacks.get(fixture.source.callbacks.size - 1).invoke()
            fresh = fixture.adapter.observe()
            assertNotNull(fresh)
        } finally { hold.release.countDown(); reader.join(); withdrawal.joinIfStarted() }
        reader.assertSucceeded(); withdrawal.assertSucceeded()
        assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh)))
        assertFalse(fixture.adapter.isCurrent(old))
        assertEquals(1, fixture.source.handles.first().closes.get())
        assertEquals(0, fixture.source.handles.last().closes.get())
    }

    @Test fun selectionChangeDuringReadCannotPublishOrSelectAnotherPeer() {
        val fixture = Fixture()
        val old = fixture.ready(7)
        fixture.source.handles.single().onClose = { assertFalse(fixture.adapter.isCurrent(old)) }
        val hold = holdSecondRead(fixture) { fixture.source.rows }
        val result = AtomicReference<CompleteSelectionSnapshot?>()
        val reader = Worker { result.set(fixture.adapter.observe()) }
        reader.start()
        var fresh: CompleteSelectionSnapshot? = null
        try {
            assertTrue(hold.entered.await(2, TimeUnit.SECONDS))
            fixture.adapter.select(8)
            assertFalse(fixture.adapter.isCurrent(old))
            fresh = fixture.adapter.observe()
            assertEquals(8, requireNotNull(fresh).selected.subscriptionId)
        } finally { hold.release.countDown(); reader.join() }
        reader.assertSucceeded()
        assertNull(result.get())
        assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh)))
        fixture.adapter.select(99)
        assertNull(fixture.adapter.observe())
        assertFalse(fixture.adapter.isCurrent(requireNotNull(fresh)))
        fixture.adapter.select(-1)
        assertNull(fixture.adapter.observe())
    }

    @Test fun postReadPermissionFailureAndSchedulingRejectionWithdrawOwnedRequest() {
        val invalid = listOf<(Fixture) -> Unit>(
            { it.source.rows = null },
            { it.source.rows = emptyList() },
            { it.source.permissionFailure = SecurityException("synthetic permission failure") },
            { it.source.onRead = { throw IllegalStateException("synthetic read failure") } },
            { it.source.rows = listOf(physical, embedded.copy(cardId = null)) },
            { it.source.rows = listOf(physical, embedded.copy(portIndex = null)) },
            { it.source.rows = listOf(physical, embedded.copy(logicalSlotIndex = null)) },
            { it.source.rows = listOf(physical, embedded.copy(subscriptionId = 7)) },
            { it.source.rows = listOf(physical, embedded.copy(cardId = 20, portIndex = 0)) },
            { fixture -> fixture.source.onRead = { fixture.source.permission = false; fixture.source.rows } }
        )
        for (change in invalid) {
            val fixture = Fixture()
            val old = fixture.ready(7)
            change(fixture)
            assertNull(fixture.adapter.observe())
            assertFalse(fixture.adapter.isCurrent(old))
            assertEquals(1, fixture.source.handles.single().closes.get())
        }
        val mainRejected = Fixture(mainDispatch = { false })
        mainRejected.adapter.select(7)
        assertNull(mainRejected.adapter.observe())
        assertEquals(0, mainRejected.source.registerCalls.get())
        val readRejected = Fixture()
        readRejected.reads.reject = true
        readRejected.adapter.select(7)
        assertNull(readRejected.adapter.observe())
        assertEquals(0, readRejected.source.readCalls.get())
        assertEquals(1, readRejected.source.handles.single().closes.get())

        val newerRevision = Fixture()
        newerRevision.reads.onExecute = {
            if (newerRevision.reads.executions.get() == 1) {
                newerRevision.source.callbacks.single().invoke()
                throw RejectedExecutionException("synthetic obsolete scheduling failure")
            }
        }
        val fresh = newerRevision.ready(7)
        assertTrue(newerRevision.adapter.isCurrent(fresh))
        assertEquals(0, newerRevision.source.handles.single().closes.get())

        val accesses = AtomicInteger()
        val oversized = object : AbstractList<ProfileSubscriptionObservation>() {
            override val size = 257
            override fun get(index: Int): ProfileSubscriptionObservation {
                accesses.incrementAndGet()
                error("Oversized rows must not be mapped")
            }
        }
        val fixture = Fixture()
        val old = fixture.ready(7)
        fixture.source.rows = oversized
        assertNull(fixture.adapter.observe())
        assertFalse(fixture.adapter.isCurrent(old))
        assertEquals(0, accesses.get())
        val atBudget = Fixture((0 until 256).map { row(it, it, it % 2 == 0, 0, 0) })
        assertEquals(256, atBudget.ready(7).activeRows.size)
    }

    @Test fun cleanupFailureAndCloseCannotReviveSavedOrOldSnapshots() {
        val fixture = Fixture()
        val old = fixture.ready(7)
        fixture.source.handles.single().onClose = { throw IllegalStateException("synthetic close failure") }
        fixture.adapter.stop()
        assertFalse(fixture.adapter.isCurrent(old))
        assertTrue(fixture.adapter.cleanupFailureObserved)
        fixture.source.callbacks.get(0).invoke()
        assertNull(fixture.adapter.observe())
        val fresh = fixture.ready(7)
        assertNotSame(old, fresh)
        fixture.adapter.close()
        assertFalse(fixture.adapter.isCurrent(fresh))
        fixture.adapter.select(7)
        assertNull(fixture.adapter.observe())
        assertEquals(2, fixture.source.registerCalls.get())
        val replacement = Fixture()
        assertNotNull(replacement.ready(7))
        assertFalse(replacement.adapter.isCurrent(old))
        assertFalse(replacement.adapter.isCurrent(fresh))
    }

    @Test fun callbackRevisionOverflowClosesOnlyItsOwnHandleOutsideLocks() {
        val fixture = Fixture()
        val old = fixture.ready(7)
        val oldHandle = fixture.source.handles.single()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        oldHandle.onClose = { entered.countDown(); awaitRelease(release) }
        val scheduled = fixture.reads.executions.get()
        fixture.adapter.advanceCallbackRevisionToLimitForTest()
        val callback = Worker { fixture.source.callbacks.get(0).invoke() }
        val completed = CountDownLatch(1)
        val fresh = AtomicReference<CompleteSelectionSnapshot?>()
        val other = Worker {
            assertFalse(fixture.adapter.isCurrent(old))
            fixture.adapter.stop()
            fixture.adapter.select(8)
            fresh.set(fixture.adapter.observe())
            completed.countDown()
        }
        callback.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertEquals(scheduled, fixture.reads.executions.get())
            other.start()
            assertTrue(completed.await(2, TimeUnit.SECONDS))
            assertNotNull(fresh.get())
            assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh.get())))
        } finally { release.countDown(); callback.join(); other.joinIfStarted() }
        callback.assertSucceeded(); other.assertSucceeded()
        fixture.source.callbacks.get(0).invoke()
        assertEquals(1, oldHandle.closes.get())
        assertEquals(0, fixture.source.handles.last().closes.get())
        assertTrue(fixture.adapter.isCurrent(requireNotNull(fresh.get())))
        assertFalse(fixture.adapter.isCurrent(old))
    }

    private inner class Fixture(
        rows: List<ProfileSubscriptionObservation> = listOf(physical, embedded),
        mainDispatch: ((() -> Unit) -> Boolean) = { it(); true }
    ) {
        @Volatile var api = 33
        val source = Source(rows)
        val reads = ReadQueue()
        val adapter = CompleteSubscriptionObservationAdapter({ api }, source, mainDispatch, reads)
        fun ready(selected: Int): CompleteSelectionSnapshot {
            adapter.select(selected)
            return requireNotNull(adapter.observe())
        }
    }

    private class Source(@Volatile var rows: List<ProfileSubscriptionObservation>?) : ProfileObservationSource {
        @Volatile var permission = true
        @Volatile var permissionFailure: Exception? = null
        @Volatile var callbackBeforeReturn = true
        @Volatile var onRegister: ((() -> Unit, Handle) -> Unit)? = null
        @Volatile var onRead: ((Int) -> List<ProfileSubscriptionObservation>?)? = null
        val registerCalls = AtomicInteger()
        val readCalls = AtomicInteger()
        val partialCleanups = AtomicInteger()
        val callbacks = CopyOnWriteArrayList<() -> Unit>()
        val handles = CopyOnWriteArrayList<Handle>()
        override fun permissionGranted(): Boolean {
            permissionFailure?.let { throw it }
            return permission
        }
        override fun register(changed: () -> Unit): AutoCloseable {
            registerCalls.incrementAndGet()
            val handle = Handle()
            callbacks.add(changed)
            handles.add(handle)
            try {
                if (callbackBeforeReturn) changed()
                onRegister?.invoke(changed, handle)
            } catch (failure: Exception) {
                partialCleanups.incrementAndGet()
                handle.close()
                throw failure
            }
            return handle
        }
        override fun readComplete(): List<ProfileSubscriptionObservation>? {
            val call = readCalls.incrementAndGet()
            val hook = onRead
            return if (hook == null) rows else hook(call)
        }
    }

    private class Handle : AutoCloseable {
        val closes = AtomicInteger()
        @Volatile var onClose: (() -> Unit)? = null
        override fun close() { closes.incrementAndGet(); onClose?.invoke() }
    }

    private class ReadQueue : Executor {
        val executions = AtomicInteger()
        private val queue = CopyOnWriteArrayList<Runnable>()
        fun runOne() = queue.removeAt(0).run()
        @Volatile var reject = false
        @Volatile var onExecute: (() -> Unit)? = null
        override fun execute(command: Runnable) {
            executions.incrementAndGet()
            onExecute?.invoke()
            if (reject) throw RejectedExecutionException("synthetic rejected read")
            queue.add(command)
        }
    }

    private class MainQueue {
        private val queue = CopyOnWriteArrayList<() -> Unit>()
        fun dispatch(action: () -> Unit): Boolean { queue.add(action); return true }
        fun repeatLast() { queue.add(queue.get(queue.size - 1)) }
        fun drain() { while (queue.isNotEmpty()) queue.removeAt(0).invoke() }
    }

    private class Worker(action: () -> Unit) {
        private val failure = AtomicReference<Throwable?>()
        private val thread = Thread { try { action() } catch (error: Throwable) { failure.set(error) } }
        fun start() = thread.start()
        fun join() { thread.join(2000); assertFalse("synthetic worker did not settle", thread.isAlive) }
        fun joinIfStarted() { if (thread.state != Thread.State.NEW) join() }
        fun assertSucceeded() { assertFalse(thread.isAlive); assertNull(failure.get()) }
    }

    private data class HeldRead(val entered: CountDownLatch, val release: CountDownLatch)

    private fun holdSecondRead(fixture: Fixture, afterRelease: () -> List<ProfileSubscriptionObservation>?): HeldRead {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val heldCall = fixture.source.readCalls.get() + 2
        fixture.source.onRead = { call ->
            if (call == heldCall) { entered.countDown(); awaitRelease(release); afterRelease() }
            else fixture.source.rows
        }
        return HeldRead(entered, release)
    }

    private fun awaitRelease(release: CountDownLatch) {
        check(release.await(5, TimeUnit.SECONDS)) { "synthetic operation was not released" }
    }

    private fun row(sub: Int, card: Int, embedded: Boolean, port: Int, slot: Int) =
        ProfileSubscriptionObservation(sub, card, embedded, port, slot)
}
