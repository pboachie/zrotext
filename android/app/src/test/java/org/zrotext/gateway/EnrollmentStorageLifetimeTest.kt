// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Scheduling and storage only; synthetic keys do not attest Android or SIM custody. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class EnrollmentStorageLifetimeTest {
    private class LockedStorage(private val memory: ConversationEnrollmentFixture.Memory,
        val lock: ReentrantLock = ReentrantLock(), private val entered: () -> Unit = {}) : Draft02TrustStore.Storage {
        override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T {
            check(lock.tryLock(2, TimeUnit.SECONDS))
            try { entered(); return memory.action() } finally { lock.unlock() }
        }
    }
    @Test fun twoThreadRoomAndRootStorageOrderingUsesOnlyRamGuardsUnderStorage() {
        val f = ConversationEnrollmentFixture()
        val room = ReentrantLock()
        val rootEntered = CountDownLatch(1)
        val roomHeld = CountDownLatch(1)
        val lifetime = EnrollmentStorageLifetime()
        val threads = Executors.newFixedThreadPool(2)
        val storage = LockedStorage(f.storage, entered = {
            if (Thread.currentThread().name == "synthetic-root-review") {
                rootEntered.countDown(); check(roomHeld.await(2, TimeUnit.SECONDS))
            }
        })
        fun full() = lifetime.validateOutsideStorage {
            check(room.tryLock(2, TimeUnit.SECONDS))
            try { check(f.live) } finally { room.unlock() }
        }
        val session = ConversationEnrollmentSession(f.account, ::full, lifetime::requireCurrent,
            { error("Reader forbidden") }, storage, { error("Protection forbidden") })
        try {
            val first = threads.submit<String> {
                Thread.currentThread().name = "synthetic-root-review"
                session.reviewRoot(f.pin).fingerprintHex
            }
            val second = threads.submit<Draft02TrustStore.Status> {
                check(rootEntered.await(2, TimeUnit.SECONDS)); check(room.tryLock(2, TimeUnit.SECONDS))
                try {
                    roomHeld.countDown()
                    Draft02TrustStore(storage).inspect().status
                } finally { room.unlock() }
            }
            assertEquals(Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON, second.get(5, TimeUnit.SECONDS))
            assertEquals(64, first.get(5, TimeUnit.SECONDS).length)
            assertEquals(0, f.storage.creations)
        } finally { session.close(); lifetime.close(); threads.shutdownNow() }
    }
    @Test fun callbackBetweenFullValidationAndStorageRefusesBeforeAnyProtectionCreation() {
        val f = ConversationEnrollmentFixture()
        val lifetime = EnrollmentStorageLifetime()
        val storage = LockedStorage(f.storage, entered = lifetime::changed)
        val session = ConversationEnrollmentSession(f.account,
            { lifetime.validateOutsideStorage { check(f.live) } }, lifetime::requireCurrent,
            { error("Reader forbidden") }, storage, { error("Protection forbidden") })
        try {
            assertThrows(IllegalStateException::class.java) { session.reviewRoot(f.pin) }
            assertEquals(0, f.storage.creations); assertEquals(0, f.storage.commits)
        } finally { session.close(); lifetime.close() }
    }
    @Test fun callbackOrForegroundWithdrawalDuringPrecommitNeverPublishesRootBytes() {
        for (withdrawal in 0..2) {
            val f = ConversationEnrollmentFixture()
            val lifetime = EnrollmentStorageLifetime()
            val session = ConversationEnrollmentSession(f.account,
                { lifetime.validateOutsideStorage { check(f.live) } }, { check(f.live); lifetime.requireCurrent() },
                { error("Reader forbidden") }, f.storage, { error("Protection forbidden") })
            try {
                val compared = session.reviewRoot(f.pin).fingerprintHex
                f.storage.beforeCommit = {
                    when (withdrawal) { 0 -> lifetime.changed(); 1 -> f.live = false; 2 -> session.close() }
                }
                val result = runCatching { session.enrollComparedRoot(compared, true) }
                result.getOrNull()?.let { assertNotEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, it.status) }
                assertNull(f.storage.data); assertEquals(0, f.storage.commits)
            } finally { session.close(); lifetime.close() }
        }
    }
    @Test fun otherThreadFreshValidationCannotRenewAnOlderCapturedStorageEpoch() {
        val lifetime = EnrollmentStorageLifetime()
        val ready = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val prior = executor.submit<Boolean> {
                lifetime.validateOutsideStorage {}
                ready.countDown(); check(proceed.await(2, TimeUnit.SECONDS))
                runCatching { lifetime.requireCurrent() }.isFailure
            }
            check(ready.await(2, TimeUnit.SECONDS))
            lifetime.changed()
            assertThrows(IllegalStateException::class.java) { lifetime.validateOutsideStorage {} }
            proceed.countDown()
            assertTrue(prior.get(5, TimeUnit.SECONDS))
        } finally { lifetime.close(); proceed.countDown(); executor.shutdownNow() }
    }
    @Test fun missingValidationChangeDuringValidationAndCloseCannotIssueCurrentTickets() {
        val lifetime = EnrollmentStorageLifetime()
        assertThrows(IllegalStateException::class.java) { lifetime.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { lifetime.validateOutsideStorage { lifetime.changed() } }
        assertThrows(IllegalStateException::class.java) { lifetime.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { lifetime.validateOutsideStorage {} }
        lifetime.close()
        val fresh = EnrollmentStorageLifetime()
        fresh.validateOutsideStorage {}; fresh.requireCurrent(); fresh.close()
        assertThrows(IllegalStateException::class.java) { fresh.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { lifetime.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { lifetime.validateOutsideStorage {} }
    }
}
