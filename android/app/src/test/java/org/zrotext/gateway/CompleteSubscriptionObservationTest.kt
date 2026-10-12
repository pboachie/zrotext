// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class CompleteSubscriptionObservationTest {
    private val physical = row(7, ObservedSubscriptionKind.PHYSICAL, 20, 0, 0)
    private val embedded = row(8, ObservedSubscriptionKind.EMBEDDED, 30, 0, 1)

    @Test fun physicalAndEmbeddedEachRequireExplicitSelectionOfTheCompleteSet() {
        val fixture = ready(listOf(physical, embedded))
        val first = requireNotNull(fixture.observer.observeSelected(7))
        assertEquals(physical, first.selected)
        assertEquals(listOf(physical, embedded), first.activeRows)
        val second = requireNotNull(fixture.observer.observeSelected(8))
        assertEquals(embedded, second.selected)
        assertEquals(listOf(physical, embedded), second.activeRows)
        assertFalse(fixture.observer.isCurrent(first))
        assertTrue(fixture.observer.isCurrent(second))
    }

    @Test fun sameEuiccAndSharedSlotWithDistinctPortsAllowsEitherSelectedProfile() {
        val firstProfile = row(7, ObservedSubscriptionKind.EMBEDDED, 30, 0, 1)
        val secondProfile = row(8, ObservedSubscriptionKind.EMBEDDED, 30, 1, 1)
        val fixture = ready(listOf(firstProfile, secondProfile))
        val first = requireNotNull(fixture.observer.observeSelected(7))
        val second = requireNotNull(fixture.observer.observeSelected(8))
        assertEquals(firstProfile, first.selected)
        assertEquals(secondProfile, second.selected)
        assertEquals(2, second.activeRows.size)
        assertFalse(fixture.observer.isCurrent(first))
        assertTrue(fixture.observer.isCurrent(second))
    }

    @Test fun initialCallbackAndSuccessfulRegistrationAreBothRequiredInEitherOrder() {
        val source = Source(listOf(physical, embedded))
        val observer = CompleteSubscriptionObserver(source)
        val first = observer.beginRegistration()
        assertTrue(observer.initialCallback(first))
        assertNull(observer.observeSelected(7))
        assertEquals(0, source.calls.get())
        assertTrue(observer.registrationSucceeded(first))
        val old = requireNotNull(observer.observeSelected(7))

        val next = observer.beginRegistration()
        assertFalse(observer.isCurrent(old))
        assertTrue(observer.registrationSucceeded(next))
        assertNull(observer.observeSelected(7))
        assertTrue(observer.initialCallback(next))
        assertNotNull(observer.observeSelected(7))
    }

    @Test fun failedRegistrationAfterInitialCallbackNeverExposesAReadyObservation() {
        val source = Source(listOf(physical, embedded))
        val observer = CompleteSubscriptionObserver(source)
        val token = observer.beginRegistration()
        assertTrue(observer.initialCallback(token))
        assertTrue(observer.registrationFailed(token))
        assertFalse(observer.registrationSucceeded(token))
        assertNull(observer.observeSelected(7))
        assertEquals(0, source.calls.get())
    }

    @Test fun unknownOrAmbiguousPeerRefusesInsteadOfFilteringToTheSelectedRecord() {
        val invalidLists = listOf(
            listOf(physical, embedded.copy(cardId = null)),
            listOf(physical, embedded.copy(portIndex = null)),
            listOf(physical, embedded.copy(slotIndex = null)),
            listOf(physical, embedded.copy(subscriptionId = physical.subscriptionId)),
            listOf(physical, embedded.copy(cardId = physical.cardId, portIndex = physical.portIndex))
        )
        for (rows in invalidLists) {
            val fixture = ready(listOf(physical, embedded))
            val old = requireNotNull(fixture.observer.observeSelected(7))
            fixture.source.rows = rows
            assertNull(fixture.observer.observeSelected(7))
            assertFalse(fixture.observer.isCurrent(old))
        }
    }

    @Test fun missingSelectedRecordDoesNotSelectTheRemainingPeer() {
        val fixture = ready(listOf(physical, embedded))
        val old = requireNotNull(fixture.observer.observeSelected(7))
        fixture.source.rows = listOf(embedded)
        assertNull(fixture.observer.observeSelected(7))
        assertFalse(fixture.observer.isCurrent(old))
        assertNull(fixture.observer.observeSelected(8))
    }

    @Test fun invalidExplicitSelectionWithdrawsInsteadOfRetainingThePreviousChoice() {
        val fixture = ready(listOf(physical, embedded))
        val old = requireNotNull(fixture.observer.observeSelected(7))
        assertNull(fixture.observer.observeSelected(-1))
        assertFalse(fixture.observer.isCurrent(old))
        assertNull(fixture.observer.observeSelected(8))
    }

    @Test fun incompleteOlderApiAndUnreadableObservationsRefuseWithoutPhysicalFallback() {
        for (invalid in listOf<(Source) -> Unit>(
            { it.apiLevel = 32 }, { it.complete = false },
            { it.permission = false }, { it.readable = false }
        )) {
            val fixture = ready(listOf(physical, embedded))
            invalid(fixture.source)
            assertNull(fixture.observer.observeSelected(7))
            assertNull(fixture.observer.observeSelected(8))
        }
    }

    @Test fun sameCountPeerReplacementRetiresPhysicalAndEmbeddedObservations() {
        for (selected in listOf(7, 8)) {
            val fixture = ready(listOf(physical, embedded))
            val old = requireNotNull(fixture.observer.observeSelected(selected))
            fixture.source.rows = if (selected == 7) {
                listOf(physical, embedded.copy(subscriptionId = 9))
            } else listOf(physical.copy(subscriptionId = 9), embedded)
            assertEquals(2, fixture.source.rows.size)
            assertNull(fixture.observer.observeSelected(selected))
            assertFalse(fixture.observer.isCurrent(old))
            val fresh = requireNotNull(fixture.observer.observeSelected(selected))
            assertTrue(fixture.observer.isCurrent(fresh))
            assertFalse(fixture.observer.isCurrent(old))
        }
    }

    @Test fun callbackDuringHeldSecondReadWithdrawsBeforeTheReadCanFinish() {
        heldSecondRead { it.observer.subscriptionsChanged(it.registration) }
    }

    @Test fun permissionWithdrawalDuringHeldSecondReadCannotIssueAnObservation() {
        heldSecondRead { it.observer.permissionLost() }
    }

    @Test fun staleCallbacksCannotRetireAReplacementRegistrationAndSavedRowsCannotRestore() {
        val fixture = ready(listOf(physical, embedded))
        val old = requireNotNull(fixture.observer.observeSelected(7))
        val next = fixture.observer.beginRegistration()
        assertFalse(fixture.observer.isCurrent(old))
        assertTrue(fixture.observer.registrationSucceeded(next))
        assertTrue(fixture.observer.initialCallback(next))
        val fresh = requireNotNull(fixture.observer.observeSelected(7))
        assertFalse(fixture.observer.subscriptionsChanged(fixture.registration))
        assertFalse(fixture.observer.registrationFailed(fixture.registration))
        assertTrue(fixture.observer.isCurrent(fresh))

        fixture.observer.stop()
        val replacement = ready(old.activeRows)
        assertFalse(replacement.observer.isCurrent(old))
        assertFalse(replacement.observer.isCurrent(fresh))
        assertNotNull(replacement.observer.observeSelected(7))
        assertFalse(fixture.observer.isCurrent(old))
    }

    @Test fun permissionRegrantRequiresFreshRegistrationAndInitialCallback() {
        val fixture = ready(listOf(physical, embedded))
        val old = requireNotNull(fixture.observer.observeSelected(7))
        fixture.source.permission = false
        assertNull(fixture.observer.observeSelected(7))
        assertFalse(fixture.observer.isCurrent(old))
        fixture.source.permission = true
        assertNull(fixture.observer.observeSelected(7))
        val next = fixture.observer.beginRegistration()
        assertTrue(fixture.observer.registrationSucceeded(next))
        assertNull(fixture.observer.observeSelected(7))
        assertTrue(fixture.observer.initialCallback(next))
        assertNotNull(fixture.observer.observeSelected(7))
        assertFalse(fixture.observer.isCurrent(old))
    }

    @Test fun equalReorderedReadsRetainTheSameOpaqueObservationAndInputsCannotMutateIt() {
        val mutableRows = mutableListOf(physical, embedded)
        val fixture = ready(mutableRows)
        val old = requireNotNull(fixture.observer.observeSelected(7))
        fixture.source.rows = listOf(embedded, physical)
        assertSame(old, fixture.observer.observeSelected(7))
        mutableRows.clear()
        assertEquals(listOf(physical, embedded), old.activeRows)
        assertThrows(UnsupportedOperationException::class.java) {
            (old.activeRows as MutableList<SubscriptionObservationRow>).clear()
        }
        assertTrue(fixture.observer.isCurrent(old))
    }

    @Test fun differentCompleteReadsAndReadExceptionsCannotEstablishABaseline() {
        val fixture = ready(listOf(physical, embedded))
        fixture.source.onRead = { call ->
            if (call == 2) fixture.source.rows = listOf(physical, embedded.copy(subscriptionId = 9))
        }
        assertNull(fixture.observer.observeSelected(7))
        assertNull(fixture.observer.observeSelected(7))

        val next = fixture.observer.beginRegistration()
        fixture.observer.registrationSucceeded(next)
        fixture.observer.initialCallback(next)
        fixture.source.onRead = null
        val old = requireNotNull(fixture.observer.observeSelected(7))
        fixture.source.onRead = { throw SecurityException("synthetic permission withdrawal") }
        assertNull(fixture.observer.observeSelected(7))
        assertFalse(fixture.observer.isCurrent(old))
    }

    private fun heldSecondRead(retire: (Fixture) -> Unit) {
        val fixture = ready(listOf(physical, embedded))
        val old = requireNotNull(fixture.observer.observeSelected(7))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val retired = CountDownLatch(1)
        val result = AtomicReference<CompleteSelectionSnapshot?>()
        val failure = AtomicReference<Throwable?>()
        val holdCall = fixture.source.calls.get() + 2
        fixture.source.onRead = { call ->
            if (call == holdCall) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "synthetic read was not released" }
            }
        }
        val worker = Thread {
            try { result.set(fixture.observer.observeSelected(7)) }
            catch (error: Throwable) { failure.set(error) }
        }
        val retirementWorker = Thread {
            try { retire(fixture) }
            catch (error: Throwable) { failure.set(error) }
            finally { retired.countDown() }
        }
        worker.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            // Retirement must complete before releasing the held read, not after its timeout.
            retirementWorker.start()
            assertTrue(retired.await(2, TimeUnit.SECONDS))
            assertFalse(fixture.observer.isCurrent(old))
        } finally {
            release.countDown()
            worker.join(2000)
            if (retirementWorker.state != Thread.State.NEW) retirementWorker.join(2000)
        }
        assertFalse(worker.isAlive)
        assertFalse(retirementWorker.isAlive)
        assertNull(failure.get())
        assertNull(result.get())
    }

    private class Source(@Volatile var rows: List<SubscriptionObservationRow>) : CompleteSubscriptionSource {
        val calls = AtomicInteger()
        @Volatile var apiLevel = 33
        @Volatile var permission = true
        @Volatile var readable = true
        @Volatile var complete = true
        @Volatile var onRead: ((Int) -> Unit)? = null
        override fun read(): CompleteSubscriptionRead {
            val call = calls.incrementAndGet()
            onRead?.invoke(call)
            return CompleteSubscriptionRead(apiLevel, permission, readable, complete, rows)
        }
    }

    private data class Fixture(
        val source: Source,
        val observer: CompleteSubscriptionObserver,
        val registration: CompleteObservationRegistration
    )

    private fun ready(rows: List<SubscriptionObservationRow>): Fixture {
        val source = Source(rows)
        val observer = CompleteSubscriptionObserver(source)
        val token = observer.beginRegistration()
        assertTrue(observer.registrationSucceeded(token))
        assertTrue(observer.initialCallback(token))
        return Fixture(source, observer, token)
    }

    private fun row(sub: Int, kind: ObservedSubscriptionKind, card: Int, port: Int, slot: Int) =
        SubscriptionObservationRow(sub, kind, card, port, slot)
}
