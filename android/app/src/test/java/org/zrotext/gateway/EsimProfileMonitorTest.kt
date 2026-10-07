// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.ArrayDeque
import java.util.concurrent.Executor

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class EsimProfileMonitorTest {
    private class Queue : Executor {
        private val actions = ArrayDeque<Runnable>()
        override fun execute(command: Runnable) { actions.add(command) }
        fun drain() {
            var remaining = 100
            while (actions.isNotEmpty()) { check(--remaining > 0); actions.remove().run() }
        }
    }
    private class Source : ProfileObservationSource {
        var permission = true
        var callbackBeforeReturn = true
        var throwAfterCallback = false
        var readFailure = false
        var registerCount = 0
        var closeCount = 0
        var observations = listOf(ProfileSubscriptionObservation(10, 100, true, 0, 0))
        var onRead: (() -> Unit)? = null
        val callbacks = mutableListOf<() -> Unit>()
        override fun permissionGranted() = permission
        override fun register(changed: () -> Unit): AutoCloseable {
            registerCount += 1
            callbacks.add(changed)
            if (callbackBeforeReturn) changed()
            if (throwAfterCallback) throw IllegalStateException("synthetic registration failure")
            return AutoCloseable { closeCount += 1 }
        }
        override fun readComplete(): List<ProfileSubscriptionObservation>? {
            val action = onRead
            onRead = null
            action?.invoke()
            if (readFailure) throw IllegalStateException("synthetic read failure")
            return observations
        }
        fun change() { callbacks.last().invoke() }
    }
    private fun monitor(source: Source, queue: Queue) = SimProfileMonitor(source, { it() }, queue)

    @Test fun initialCallbackCannotExposeReadyBeforeRegistrationSuccessfullyReturns() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        source.throwAfterCallback = true
        monitor.start()
        queue.drain()
        assertNull(monitor.currentTracker())
        assertNull(monitor.candidate(10))
    }
    @Test fun missingInitialCallbackRemainsUnreadyUntilCompleteBarrierAndReads() {
        val source = Source()
        source.callbackBeforeReturn = false
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        assertNull(monitor.candidate(10))
        source.change()
        assertNull(monitor.candidate(10))
        queue.drain()
        assertNotNull(monitor.candidate(10))
    }
    @Test fun deniedPermissionThenGrantCreatesFreshRegistrationLifetime() {
        val source = Source()
        source.permission = false
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        assertEquals(0, source.registerCount)
        assertNull(monitor.candidate(10))
        source.permission = true
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        source.permission = false
        assertNull(monitor.observe())
        assertFalse(first.isCurrent())
        source.permission = true
        monitor.start()
        queue.drain()
        val replacement = checkNotNull(monitor.candidate(10))
        assertNotEquals(first.record.incarnation, replacement.record.incarnation)
        assertFalse(first.isCurrent())
    }
    @Test fun callbackDuringBlockingReadCannotCommitStaleSnapshot() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        source.onRead = { source.change() }
        assertNull(monitor.observe())
        assertFalse(first.isCurrent())
        queue.drain()
        assertNotSame(first, monitor.candidate(10))
    }
    @Test fun everyCallbackRetiresSynchronouslyBeforeQueuedRead() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        source.change()
        assertFalse(first.isCurrent())
        assertNull(monitor.candidate(10))
        queue.drain()
        assertNotSame(first, monitor.candidate(10))
    }
    @Test fun frameworkReadFailureNeverReturnsPreviousReadyLease() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        source.readFailure = true
        assertNull(monitor.observe())
        assertFalse(first.isCurrent())
        assertNull(monitor.candidate(10))
        source.readFailure = false
        assertNotNull(monitor.observe())
        assertNotSame(first, monitor.candidate(10))
    }
    @Test fun teardownAndDelayedRetiredCallbackCannotAlterNewRegistration() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        val retiredCallback = source.callbacks.first()
        monitor.stop()
        assertFalse(first.isCurrent())
        assertEquals(1, source.closeCount)
        monitor.start()
        queue.drain()
        val replacement = checkNotNull(monitor.candidate(10))
        retiredCallback()
        queue.drain()
        assertSame(replacement, monitor.candidate(10))
        assertTrue(replacement.isCurrent())
    }
    @Test fun queuedStartThenStopCannotRegisterAfterStop() {
        val source = Source()
        val reads = Queue()
        val main = Queue()
        val monitor = SimProfileMonitor(source, { action -> main.execute(Runnable { action() }) }, reads)
        monitor.start()
        monitor.stop()
        main.drain()
        reads.drain()
        assertEquals(0, source.registerCount)
        assertNull(monitor.currentTracker())
        assertNull(monitor.candidate(10))
        monitor.start()
        main.drain()
        reads.drain()
        assertNotNull(monitor.candidate(10))
    }
    @Test fun actualPreferenceAdapterRejectsMalformedMissingAndWrongTypeJson() {
        val context = RuntimeEnvironment.getApplication()
        val preferences = context.getSharedPreferences("sim_profile_challenge_fence", android.content.Context.MODE_PRIVATE)
        val persistence = PreferenceProfileChallengePersistence(context)
        for (malformed in listOf("{", "{}", "{\"version\":1,\"reservations\":{},\"installed\":{}}",
            "{\"version\":1,\"reservations\":[{}],\"installed\":{}}",
            "{\"version\":1,\"reservations\":[],\"installed\":{\"malformed\":\"1\"}}")) {
            assertTrue(preferences.edit().putString("ledger_v1", malformed).commit())
            assertNull(persistence.read())
            // Restarted adapters retain denial; malformed data is never replaced with empty state.
            assertNull(PreferenceProfileChallengePersistence(context).read())
        }
    }
    @Test fun observerRegistrationAndReadsNeverRunInsideTrackerStateLock() {
        val source = Source()
        val queue = Queue()
        val monitor = monitor(source, queue)
        monitor.start()
        queue.drain()
        val first = checkNotNull(monitor.candidate(10))
        source.onRead = {
            val check = java.util.concurrent.FutureTask { first.isCurrent() }
            val worker = Thread(check)
            worker.start()
            try { assertTrue(check.get(1, java.util.concurrent.TimeUnit.SECONDS)) }
            finally { worker.interrupt(); worker.join(1000) }
        }
        assertNotNull(monitor.observe())
        assertSame(first, monitor.candidate(10))
    }
}
