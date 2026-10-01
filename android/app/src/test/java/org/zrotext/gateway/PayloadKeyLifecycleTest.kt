// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PayloadKeyLifecycleTest {
    private class Store : PayloadKeyRecordStore, PayloadKeyRecordAccess {
        var state: PayloadKeyRecord = PayloadKeyRecord.Absent
        var failPending = false
        var failBound = false
        override fun <T> locked(operation: (PayloadKeyRecordAccess) -> T): T =
            synchronized(this) { operation(this) }
        override fun read() = state
        override fun write(record: PayloadKeyRecord) {
            if (failPending && record is PayloadKeyRecord.Pending ||
                failBound && record is PayloadKeyRecord.Bound) error("Synthetic commit failure")
            state = record
        }
    }
    private class Key {
        var id: ByteArray? = null
        var creates = 0
        var operations = 0
        var failCreate = false
        fun create() { creates++; if (failCreate) error("Synthetic key creation failure"); id = ByteArray(32) { 7 } }
        fun load(): ByteArray = id?.copyOf() ?: error("Synthetic key missing")
        fun enroll(lifecycle: PayloadKeyLifecycle) = lifecycle.enroll({ id != null }, ::create, ::load) { it }
        fun use(lifecycle: PayloadKeyLifecycle, pin: ByteArray) = lifecycle.existing(pin, ::load, { it }) {
            operations++; "synthetic result"
        }
    }

    @Test fun newInstancesReloadTheSameIdentityAndLossNeverRegeneratesIt() {
        val store = Store(); val key = Key()
        val first = key.enroll(PayloadKeyLifecycle(store))
        assertArrayEquals(first, key.enroll(PayloadKeyLifecycle(store)))
        assertEquals(1, key.creates)
        key.id = null
        assertThrows(IllegalStateException::class.java) { key.use(PayloadKeyLifecycle(store), first) }
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertEquals(1, key.creates)
        assertEquals(0, key.operations)
    }

    @Test fun unregisteredExistingKeysAreNotAdoptedAsTrustedEnrollment() {
        val store = Store(); val key = Key().apply { id = ByteArray(32) { 9 } }
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertTrue(store.state is PayloadKeyRecord.Absent)
        assertEquals(0, key.creates)
    }

    @Test fun persistencePrecedesGenerationAndInterruptedPublicationCannotRetry() {
        val store = Store().apply { failPending = true }; val key = Key()
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertEquals(0, key.creates)
        store.failPending = false; store.failBound = true
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertTrue(store.state is PayloadKeyRecord.Pending)
        assertEquals(1, key.creates)
        store.failBound = false
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertThrows(IllegalStateException::class.java) { key.use(PayloadKeyLifecycle(store), key.load()) }
        assertEquals(1, key.creates)
        assertEquals(0, key.operations)
    }

    @Test fun keyGenerationFailureLeavesAnIrreversiblePendingFence() {
        val store = Store(); val key = Key().apply { failCreate = true }
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        key.failCreate = false
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertEquals(1, key.creates)
        assertNull(key.id)
    }

    @Test fun substitutionAndWrongPinsNeverReachThePrivateOperation() {
        val store = Store(); val key = Key(); val lifecycle = PayloadKeyLifecycle(store)
        val pin = key.enroll(lifecycle)
        assertThrows(IllegalArgumentException::class.java) { key.use(lifecycle, ByteArray(32) { 3 }) }
        key.id = ByteArray(32) { 4 }
        assertThrows(IllegalStateException::class.java) { key.use(lifecycle, pin) }
        assertThrows(IllegalStateException::class.java) { key.enroll(lifecycle) }
        assertEquals(1, key.creates)
        assertEquals(0, key.operations)
    }

    @Test fun revocationSurvivesNewInstancesAndAliasDeletionWithoutRenewal() {
        val store = Store(); val key = Key(); val pin = key.enroll(PayloadKeyLifecycle(store))
        PayloadKeyLifecycle(store).revoke(pin)
        PayloadKeyLifecycle(store).revoke(pin)
        key.id = null
        assertThrows(IllegalStateException::class.java) { key.enroll(PayloadKeyLifecycle(store)) }
        assertThrows(IllegalStateException::class.java) { key.use(PayloadKeyLifecycle(store), pin) }
        assertEquals(1, key.creates)
        assertTrue(store.state is PayloadKeyRecord.Revoked)
    }

    @Test fun concurrentEnrollmentThroughSeparateInstancesCreatesExactlyOneKey() {
        val store = Store(); val key = Key(); val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map { pool.submit<ByteArray> { start.await(); key.enroll(PayloadKeyLifecycle(store)) } }
            start.countDown()
            assertArrayEquals(results[0].get(2, TimeUnit.SECONDS), results[1].get(2, TimeUnit.SECONDS))
            assertEquals(1, key.creates)
        } finally { pool.shutdownNow() }
    }

    @Test fun revocationWaitsForTheExistingOperationThenRejectsLaterOperations() {
        val store = Store(); val key = Key(); val pin = key.enroll(PayloadKeyLifecycle(store))
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val use = pool.submit<String> { PayloadKeyLifecycle(store).existing(pin, key::load, { it }) {
                entered.countDown(); check(release.await(2, TimeUnit.SECONDS)); "completed before revocation"
            } }
            check(entered.await(2, TimeUnit.SECONDS))
            val revokeStarted = CountDownLatch(1)
            val revoke = pool.submit { revokeStarted.countDown(); PayloadKeyLifecycle(store).revoke(pin) }
            check(revokeStarted.await(2, TimeUnit.SECONDS))
            assertFalse(revoke.isDone)
            release.countDown()
            assertEquals("completed before revocation", use.get(2, TimeUnit.SECONDS))
            revoke.get(2, TimeUnit.SECONDS)
            assertThrows(IllegalStateException::class.java) { key.use(PayloadKeyLifecycle(store), pin) }
        } finally { release.countDown(); pool.shutdownNow() }
    }
}
