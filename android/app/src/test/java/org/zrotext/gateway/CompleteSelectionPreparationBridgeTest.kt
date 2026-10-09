// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class CompleteSelectionPreparationBridgeTest {
    @Test fun physicalAndEmbeddedPreparationRetainsEveryActivePeer() {
        for (selected in listOf(7, 8)) {
            CompletePreparationTestFixture(selected).use { fixture ->
                val held = fixture.snapshot()
                val reads = fixture.source.reads
                val prepared = requireNotNull(fixture.bridge.prepareHeld(selected, held))
                assertEquals(selected, prepared.selected.subscriptionId)
                assertEquals(if (selected == 7) ObservedSubscriptionKind.PHYSICAL else
                    ObservedSubscriptionKind.EMBEDDED, prepared.selected.kind)
                assertEquals(held.activeRows, prepared.activeRows)
                assertEquals(2, prepared.activeRows.size)
                assertTrue(fixture.bridge.isCurrent(prepared))
                assertEquals(reads, fixture.source.reads)
                assertEquals(0, fixture.source.closes)
            }
        }
    }

    @Test fun sameEuiccAndSharedSlotWithDistinctPortsAllowsEitherPreparedSelection() {
        val rows = listOf(
            ProfileSubscriptionObservation(7, 202, true, 0, 0),
            ProfileSubscriptionObservation(8, 202, true, 1, 0))
        for (selected in listOf(7, 8)) {
            CompletePreparationTestFixture(selected, rows).use { fixture ->
                val prepared = requireNotNull(fixture.bridge.prepareHeld(selected, fixture.snapshot()))
                assertEquals(2, prepared.activeRows.size)
                assertEquals(202, prepared.selected.cardId)
                assertEquals(if (selected == 7) 0 else 1, prepared.selected.portIndex)
                assertEquals(0, prepared.selected.slotIndex)
                assertTrue(fixture.bridge.isCurrent(prepared))
            }
        }
    }

    @Test fun foreignSnapshotWrongSelectionAndForeignPreparationCannotMintCurrentness() {
        CompletePreparationTestFixture().use { own ->
            CompletePreparationTestFixture().use { other ->
                val held = own.snapshot()
                val prepared = requireNotNull(own.bridge.prepareHeld(7, held))
                val otherPrepared = requireNotNull(other.bridge.prepareHeld(7, other.snapshot()))
                assertFalse(own.bridge.isCurrent(otherPrepared))
                assertTrue(own.bridge.isCurrent(prepared))
                assertNull(own.bridge.prepareHeld(7, other.snapshot()))
                assertFalse(own.bridge.isCurrent(prepared))
                val fresh = requireNotNull(own.bridge.prepareHeld(7, held))
                assertNull(own.bridge.prepareHeld(8, held))
                assertFalse(own.bridge.isCurrent(fresh))
                assertNull(own.bridge.prepareHeld(-1, held))
            }
        }
    }

    @Test fun sameCountPeerReplacementAndCallbackRetireBothPreparedSelectionKinds() {
        for (selected in listOf(7, 8)) {
            CompletePreparationTestFixture(selected).use { fixture ->
                val old = fixture.snapshot()
                val prepared = requireNotNull(fixture.bridge.prepareHeld(selected, old))
                fixture.source.rows = fixture.source.rows.map {
                    if (it.subscriptionId == selected) it else it.copy(cardId = 303)
                }
                fixture.source.changed()
                assertFalse(fixture.bridge.isCurrent(prepared))
                assertNull(fixture.bridge.prepareHeld(selected, old))
                val fresh = requireNotNull(fixture.bridge.prepareHeld(selected, fixture.snapshot()))
                assertEquals(2, fresh.activeRows.size)
                assertTrue(fixture.bridge.isCurrent(fresh))
                assertFalse(fixture.bridge.isCurrent(prepared))
            }
        }
    }

    @Test fun permissionRegrantNeedsNewObserverLifetimeAndIncompletePeerRefuses() {
        CompletePreparationTestFixture().use { fixture ->
            val old = fixture.snapshot()
            val prepared = requireNotNull(fixture.bridge.prepareHeld(7, old))
            fixture.source.permission = false
            fixture.adapter.permissionLost()
            assertFalse(fixture.bridge.isCurrent(prepared))
            fixture.source.permission = true
            assertNull(fixture.adapter.observe())
            assertNull(fixture.bridge.prepareHeld(7, old))
            fixture.adapter.select(7)
            val fresh = requireNotNull(fixture.bridge.prepareHeld(7, fixture.snapshot()))
            assertTrue(fixture.bridge.isCurrent(fresh))
            fixture.source.rows = fixture.source.rows.map {
                if (it.subscriptionId == 8) it.copy(cardId = null) else it
            }
            assertNull(fixture.adapter.observe())
            assertFalse(fixture.bridge.isCurrent(fresh))
            assertNull(fixture.bridge.prepareHeld(7, old))
        }
    }

    @Test fun withdrawAndCloseFencePreparationWithoutStoppingCallerOwnedObserver() {
        CompletePreparationTestFixture().use { fixture ->
            val held = fixture.snapshot()
            val prepared = requireNotNull(fixture.bridge.prepareHeld(7, held))
            fixture.bridge.withdraw()
            assertFalse(fixture.bridge.isCurrent(prepared))
            assertTrue(fixture.adapter.isCurrent(held))
            val fresh = requireNotNull(fixture.bridge.prepareHeld(7, held))
            assertTrue(fixture.bridge.isCurrent(fresh))
            assertFalse(fixture.bridge.isCurrent(prepared))
            fixture.bridge.close()
            assertFalse(fixture.bridge.isCurrent(fresh))
            assertNull(fixture.bridge.prepareHeld(7, held))
            assertTrue(fixture.adapter.isCurrent(held))
            assertEquals(0, fixture.source.closes)
        }
    }

    @Test fun adapterRetirementPrecedesHeldListenerCloseForBothPreparedKinds() {
        for (selected in listOf(7, 8)) {
            CompletePreparationTestFixture(selected).use { fixture ->
                val held = fixture.snapshot()
                val prepared = requireNotNull(fixture.bridge.prepareHeld(selected, held))
                val entered = CountDownLatch(1)
                val release = CountDownLatch(1)
                val failure = AtomicReference<Throwable?>()
                fixture.source.onClose = {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                val worker = Thread {
                    try { fixture.adapter.stop() } catch (problem: Throwable) { failure.set(problem) }
                }.also { it.isDaemon = true; it.start() }
                try {
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    assertTrue(worker.isAlive)
                    assertFalse(fixture.bridge.isCurrent(prepared))
                    assertNull(fixture.bridge.prepareHeld(selected, held))
                } finally {
                    release.countDown()
                    worker.join(5000)
                }
                assertFalse(worker.isAlive)
                failure.get()?.let { throw AssertionError(it) }
            }
        }
    }

    @Test fun savedRowsAndFreshIndependentModelCannotRestoreHeldIssuerIdentity() {
        CompletePreparationTestFixture().use { fixture ->
            val held = fixture.snapshot()
            val reconstructed = CompleteSubscriptionObserver(CompleteSubscriptionSource {
                CompleteSubscriptionRead(33, true, true, true, held.activeRows.map { it.copy() })
            })
            val token = reconstructed.beginRegistration()
            assertTrue(reconstructed.registrationSucceeded(token))
            assertTrue(reconstructed.initialCallback(token))
            val saved = requireNotNull(reconstructed.observeSelected(7))
            assertEquals(held.selected, saved.selected)
            assertEquals(held.activeRows, saved.activeRows)
            assertTrue(reconstructed.isCurrent(saved))
            val reads = fixture.source.reads
            assertNull(fixture.bridge.prepareHeld(7, saved))
            assertEquals(reads, fixture.source.reads)
            assertNotNull(fixture.bridge.prepareHeld(7, held))
        }
    }
}

internal class CompletePreparationTestFixture(
    selected: Int = 7,
    rows: List<ProfileSubscriptionObservation> = listOf(
        ProfileSubscriptionObservation(7, 101, false, 0, 0),
        ProfileSubscriptionObservation(8, 202, true, 1, 1))
) : AutoCloseable {
    val source = Source(rows)
    val adapter = CompleteSubscriptionObservationAdapter({ 33 }, source,
        { work -> work(); true }, Executor { work -> work.run() })
    val bridge = CompleteSelectionPreparationBridge(adapter)
    init { adapter.select(selected) }
    fun snapshot(): CompleteSelectionSnapshot = requireNotNull(adapter.observe())
    override fun close() { bridge.close(); adapter.close() }

    class Source(var rows: List<ProfileSubscriptionObservation>) : ProfileObservationSource {
        var permission = true
        var reads = 0
        @Volatile var closes = 0
        var onClose: (() -> Unit)? = null
        private var callback: (() -> Unit)? = null
        override fun permissionGranted() = permission
        override fun readComplete(): List<ProfileSubscriptionObservation> { reads++; return rows.toList() }
        override fun register(changed: () -> Unit): AutoCloseable {
            callback = changed
            changed()
            return AutoCloseable { closes++; onClose?.invoke() }
        }
        fun changed() = requireNotNull(callback).invoke()
    }
}
