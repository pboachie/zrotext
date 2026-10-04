// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PayloadKeyCustodyScopeTest {
    private val pin = ByteArray(32) { 7 }
    private data class Material(val id: ByteArray, val point: ByteArray = byteArrayOf(4, 8),
                                val security: String = "software")

    private class Store(pin: ByteArray) : PayloadKeyRecordStore {
        var state: PayloadKeyRecord = PayloadKeyRecord.Bound(pin)
        val entries = AtomicInteger()
        var writes = 0
        var reads = 0
        var beforeAcquire: (Int) -> Unit = {}
        private var current: PayloadKeyRecordAccess? = null
        private var owner: Thread? = null
        val events = mutableListOf<String>()

        fun requireLocked() {
            check(owner === Thread.currentThread() && current != null)
        }

        override fun <T> locked(operation: (PayloadKeyRecordAccess) -> T): T {
            beforeAcquire(entries.incrementAndGet())
            return synchronized(this) {
                check(current == null)
                val access = object : PayloadKeyRecordAccess {
                    override fun read(): PayloadKeyRecord {
                        requireLocked(); check(current === this)
                        reads++; events.add("read")
                        return state
                    }
                    override fun write(record: PayloadKeyRecord) {
                        requireLocked(); check(current === this)
                        writes++; state = record
                    }
                }
                current = access; owner = Thread.currentThread(); events.add("enter")
                try { operation(access) }
                finally { events.add("exit"); current = null; owner = null }
            }
        }
    }

    private class Source(private val store: Store, pin: ByteArray) : PayloadKeyCustodySource<Material> {
        var material: Material? = Material(pin.copyOf())
        var loads = 0
        var onLoad: (Int) -> Unit = {}
        override fun load(): Material {
            store.requireLocked(); loads++; store.events.add("load"); onLoad(loads)
            return checkNotNull(material).let { it.copy(id = it.id.copyOf(), point = it.point.copyOf()) }
        }
        override fun keyId(material: Material) = material.id.copyOf()
        override fun requireSameIdentity(initial: Material, current: Material) {
            check(initial.id.contentEquals(current.id) && initial.point.contentEquals(current.point) &&
                initial.security == current.security)
        }
    }

    @Test fun explicitAndFinalReloadUseOneLockedAccessBeforeReturning() {
        val store = Store(pin); val source = Source(store, pin)
        val result = PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, scope ->
            store.requireLocked(); scope.revalidate(); store.events.add("operation finished")
            "local observation"
        }
        assertEquals("local observation", result)
        assertEquals(1, store.entries.get()); assertEquals(3, source.loads)
        assertEquals(6, store.reads); assertEquals(0, store.writes)
        assertEquals(listOf("operation finished", "read", "load", "read", "exit"), store.events.takeLast(5))
    }

    @Test fun finalLossPointSecurityOrRecordChangesRefuseTheResultWithoutRepair() {
        val mutations: List<(Store, Source) -> Unit> = listOf(
            { _, source -> source.material = null },
            { _, source -> source.material = source.material!!.copy(id = ByteArray(32) { 9 }) },
            { _, source -> source.material = source.material!!.copy(point = byteArrayOf(4, 9)) },
            { _, source -> source.material = source.material!!.copy(security = "unknown") },
            { store, _ -> store.state = PayloadKeyRecord.Revoked(pin) },
            { store, _ -> store.state = PayloadKeyRecord.Pending },
            { store, _ -> store.state = PayloadKeyRecord.Absent },
            { store, _ -> store.state = PayloadKeyRecord.Bound(ByteArray(32) { 9 }) }
        )
        for (mutate in mutations) {
            val store = Store(pin); val source = Source(store, pin)
            var returned = false
            assertThrows(RuntimeException::class.java) {
                PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ ->
                    mutate(store, source); "must not return"
                }
                returned = true
            }
            assertFalse(returned); assertEquals(1, store.entries.get()); assertEquals(0, store.writes)
        }
    }

    @Test fun recordChangedDuringReloadIsReadAgainBeforeCompletion() {
        val store = Store(pin); val source = Source(store, pin)
        source.onLoad = { count -> if (count == 2) store.state = PayloadKeyRecord.Revoked(pin) }
        assertThrows(IllegalStateException::class.java) {
            PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ -> "not current" }
        }
        assertEquals(2, source.loads); assertEquals(4, store.reads); assertEquals(0, store.writes)
    }

    @Test fun initialUnavailableOrWrongPinsNeverEnterTheOperation() {
        for (state in listOf(PayloadKeyRecord.Absent, PayloadKeyRecord.Pending,
            PayloadKeyRecord.Revoked(pin), PayloadKeyRecord.Bound(ByteArray(32) { 9 }))) {
            val store = Store(pin).apply { this.state = state }; val source = Source(store, pin)
            assertThrows(RuntimeException::class.java) {
                PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ -> fail("operation entered") }
            }
            assertEquals(0, source.loads); assertEquals(0, store.writes)
        }
        for (bad in listOf(ByteArray(31), ByteArray(32), ByteArray(32) { 3 })) {
            val store = Store(pin); val source = Source(store, pin)
            assertThrows(IllegalArgumentException::class.java) {
                PayloadKeyLifecycle(store).scopedExisting(bad, source) { _, _ -> fail("operation entered") }
            }
            assertEquals(0, source.loads); assertEquals(0, store.writes)
        }
    }

    @Test fun callerPinMutationCannotChangeTheExpectedIdentity() {
        val supplied = pin.copyOf(); val store = Store(pin); val source = Source(store, pin)
        PayloadKeyLifecycle(store).scopedExisting(supplied, source) { _, scope ->
            supplied.fill(3); scope.revalidate()
        }
        assertEquals(3, source.loads); assertEquals(0, store.writes)
    }

    @Test fun savedScopeExpiresAfterNormalReturnWithoutAnotherLookup() {
        val store = Store(pin); val source = Source(store, pin)
        val saved = PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, scope -> scope }
        assertThrows(IllegalStateException::class.java) { saved.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { saved.revalidate() }
        assertEquals(2, source.loads); assertEquals(1, store.entries.get())
    }

    @Test fun operationAndFinalCheckFailuresExpireScopeAndReleaseEntryToken() {
        for (failFinal in listOf(false, true)) {
            val store = Store(pin); val source = Source(store, pin); val lifecycle = PayloadKeyLifecycle(store)
            var saved: PayloadKeyCustodyScope? = null
            assertThrows(IllegalStateException::class.java) {
                lifecycle.scopedExisting(pin, source) { _, scope ->
                    saved = scope
                    if (failFinal) source.material = source.material!!.copy(security = "changed")
                    else error("Synthetic local operation failure")
                }
            }
            assertThrows(IllegalStateException::class.java) { checkNotNull(saved).revalidate() }
            assertEquals("available", lifecycle.existing(pin, source::load, source::keyId) { "available" })
            assertEquals(2, store.entries.get())
        }
    }

    @Test fun initialReloadFailureAlsoReleasesEntryToken() {
        val store = Store(pin); val source = Source(store, pin).apply { material = null }
        val lifecycle = PayloadKeyLifecycle(store)
        assertThrows(IllegalStateException::class.java) {
            lifecycle.scopedExisting(pin, source) { _, _ -> fail("operation entered") }
        }
        source.material = Material(pin)
        assertEquals("available", lifecycle.existing(pin, source::load, source::keyId) { "available" })
    }

    @Test fun anotherThreadCannotUseTheScopeOrReachTheLoader() {
        val store = Store(pin); val source = Source(store, pin); val pool = Executors.newSingleThreadExecutor()
        try {
            PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, scope ->
                pool.submit { assertThrows(IllegalStateException::class.java) { scope.revalidate() } }.get(2, TimeUnit.SECONDS)
                assertEquals(1, source.loads); scope.revalidate()
            }
            assertEquals(3, source.loads); assertEquals(1, store.entries.get())
        } finally { pool.shutdownNow() }
    }

    @Test fun nestedCallsThroughOtherInstancesRefuseBeforeAnyStoreEntry() {
        val store = Store(pin); val source = Source(store, pin)
        val otherStore = Store(pin); val other = PayloadKeyLifecycle(otherStore)
        PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, scope ->
            assertThrows(IllegalStateException::class.java) { other.existing(pin, source::load, source::keyId) { it } }
            assertThrows(IllegalStateException::class.java) { other.enroll({ false }, { fail("create") }, source::load, source::keyId) }
            assertThrows(IllegalStateException::class.java) { other.revoke(pin) }
            assertThrows(IllegalStateException::class.java) { other.scopedExisting(pin, source) { _, _ -> Unit } }
            assertThrows(IllegalStateException::class.java) { PayloadKeyCustodyEntry.withDeviceMonitor(Any()) { fail("monitor body") } }
            scope.revalidate()
        }
        assertEquals(0, otherStore.entries.get()); assertEquals(0, otherStore.writes)
        assertEquals(1, store.entries.get())
    }

    @Test fun competingRevocationWaitsThroughTheFinalReloadThenRefusesLaterUse() {
        val store = Store(pin); val source = Source(store, pin)
        val finalLoad = CountDownLatch(1); val releaseFinal = CountDownLatch(1); val revokeEntry = CountDownLatch(1)
        source.onLoad = { count -> if (count == 2) { finalLoad.countDown(); check(releaseFinal.await(3, TimeUnit.SECONDS)) } }
        store.beforeAcquire = { count -> if (count == 2) revokeEntry.countDown() }
        val pool = Executors.newFixedThreadPool(2)
        try {
            val operation = pool.submit<String> { PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ -> "completed" } }
            check(finalLoad.await(3, TimeUnit.SECONDS))
            val revoke = pool.submit { PayloadKeyLifecycle(store).revoke(pin) }
            check(revokeEntry.await(3, TimeUnit.SECONDS)); assertFalse(revoke.isDone)
            releaseFinal.countDown(); assertEquals("completed", operation.get(3, TimeUnit.SECONDS)); revoke.get(3, TimeUnit.SECONDS)
            assertTrue(store.state is PayloadKeyRecord.Revoked)
            assertThrows(IllegalStateException::class.java) { PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ -> Unit } }
        } finally { releaseFinal.countDown(); pool.shutdownNow() }
    }

    @Test fun nestedWrapperEntryRefusesBeforeAnotherMonitorWaitingForTheStore() {
        val store = Store(pin); val source = Source(store, pin); val monitorA = Any(); val monitorB = Any()
        val scopeEntered = CountDownLatch(1); val bWaiting = CountDownLatch(1)
        // A broken guard must fail the bounded assertion without trapping the test JVM.
        val pool = Executors.newFixedThreadPool(2) { task -> Thread(task).apply { isDaemon = true } }
        store.beforeAcquire = { count -> if (count == 2) bWaiting.countDown() }
        try {
            val a = pool.submit {
                PayloadKeyCustodyEntry.withDeviceMonitor(monitorA) {
                    PayloadKeyLifecycle(store).scopedExisting(pin, source) { _, _ ->
                        scopeEntered.countDown(); check(bWaiting.await(3, TimeUnit.SECONDS))
                        assertThrows(IllegalStateException::class.java) {
                            PayloadKeyCustodyEntry.withDeviceMonitor(monitorB) { fail("nested body") }
                        }
                    }
                }
            }
            check(scopeEntered.await(3, TimeUnit.SECONDS))
            val b = pool.submit<String> {
                PayloadKeyCustodyEntry.withDeviceMonitor(monitorB) {
                    PayloadKeyLifecycle(store).existing(pin, source::load, source::keyId) { "available" }
                }
            }
            a.get(3, TimeUnit.SECONDS); assertEquals("available", b.get(3, TimeUnit.SECONDS))
            assertEquals(2, store.entries.get())
        } finally { pool.shutdownNow() }
    }
}
