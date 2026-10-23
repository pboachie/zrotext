// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.*
import org.junit.Test

class Profile03BootstrapClockTest {
    private fun replacement(original: SealedDispatchExecutor.Session,
        connectionEpoch: Long = original.connectionEpoch, deploymentEpoch: Long = original.deploymentEpoch,
        sessionId: UUID = original.sessionId, originHash: String = original.originHash) =
        SealedDispatchExecutor.Session(original.accountId, original.deviceId, connectionEpoch, deploymentEpoch, sessionId, originHash)
    @Test fun metadataClockIsBoundToTheCurrentOwnerAndNeverSurvivesWithdrawalOrAReplacement() {
        val first = Any(); val second = Any()
        val origins = Profile03Origins.fromStream(UUID(0, 1), UUID(0, 2), "wss://gateway.example.test/device")
        val session = SealedDispatchExecutor.Session(UUID(0, 1), UUID(0, 2), 1, 1, UUID(0, 3), origins.routingHash)
        var now: Long? = 100
        try {
            Profile03BootstrapClock.publish(first, session, origins) { now }
            val captured = Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)
            assertEquals(100L, captured())
            assertThrows(IllegalStateException::class.java) { Profile03BootstrapClock.capture(UUID(0, 9), session.deviceId, session.originHash) }
            assertThrows(IllegalStateException::class.java) { Profile03BootstrapClock.publish(second, session, origins) { now } }
            now = null
            assertThrows(IllegalStateException::class.java) { captured() }
            Profile03BootstrapClock.withdraw(first)
            now = 101
            Profile03BootstrapClock.publish(second, session, origins) { now }
            assertThrows(IllegalStateException::class.java) { captured() }
            assertEquals(101L, Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)())
            Profile03BootstrapClock.withdraw(first) // A stale owner cannot withdraw its successor.
            assertEquals(101L, Profile03BootstrapClock.capture(session.accountId, session.deviceId, session.originHash)())
        } finally { Profile03BootstrapClock.withdraw(first); Profile03BootstrapClock.withdraw(second) }
    }

    @Test fun oneObservationRetainsItsOriginalMappingAndEpochsWithoutReadingASuccessorClock() {
        val first = Any(); val second = Any()
        val origins = Profile03Origins.fromStream(UUID(0, 1), UUID(0, 2), "wss://gateway.example.test/device")
        val nextOrigins = Profile03Origins.fromStream(UUID(0, 1), UUID(0, 2), "wss://other.example.test:9443/device")
        val original = SealedDispatchExecutor.Session(UUID(0, 1), UUID(0, 2), 7, 2, UUID(0, 3), origins.routingHash)
        val successor = replacement(original, connectionEpoch = 8, deploymentEpoch = 3, originHash = nextOrigins.routingHash)
        try {
            Profile03BootstrapClock.publish(first, original, origins) { 100 }
            val observed = Profile03BootstrapClock.observation(original.accountId, original.deviceId, original.originHash)
            assertSame(origins, observed.origins)
            assertEquals(7L, observed.connectionEpoch); assertEquals(2L, observed.deploymentEpoch)
            assertEquals(original.sessionId, observed.sessionId)
            assertEquals(100L, observed.now())
            Profile03BootstrapClock.withdraw(first)
            Profile03BootstrapClock.publish(second, successor, nextOrigins) { 200 }
            assertSame(origins, observed.origins) // Immutable public names do not become successor authority.
            assertThrows(IllegalStateException::class.java) { observed.now() }
            assertThrows(IllegalStateException::class.java) {
                Profile03BootstrapClock.observation(original.accountId, original.deviceId, original.originHash) }
            val next = Profile03BootstrapClock.observation(successor.accountId, successor.deviceId, successor.originHash)
            assertSame(nextOrigins, next.origins)
            assertEquals(8L, next.connectionEpoch); assertEquals(3L, next.deploymentEpoch)
            assertEquals(200L, next.now())
        } finally { Profile03BootstrapClock.withdraw(first); Profile03BootstrapClock.withdraw(second) }
    }

    @Test fun theSamePublisherCannotReplaceTheOriginalConnectionDeploymentOrClock() {
        val owner = Any()
        val origins = Profile03Origins.fromStream(UUID(0, 1), UUID(0, 2), "wss://gateway.example.test/device")
        val original = SealedDispatchExecutor.Session(UUID(0, 1), UUID(0, 2), 7, 2, UUID(0, 3), origins.routingHash)
        try {
            Profile03BootstrapClock.publish(owner, original, origins) { 100 }
            for (changed in listOf(replacement(original, connectionEpoch = 8), replacement(original, deploymentEpoch = 3),
                replacement(original, sessionId = UUID(0, 4))))
                assertThrows(IllegalStateException::class.java) {
                    Profile03BootstrapClock.publish(owner, changed, origins) { 200 } }
            Profile03BootstrapClock.publish(owner, original, origins) { 999 }
            val observed = Profile03BootstrapClock.observation(original.accountId, original.deviceId, original.originHash)
            assertEquals(100L, observed.now())
            assertEquals(7L, observed.connectionEpoch); assertEquals(2L, observed.deploymentEpoch)
        } finally { Profile03BootstrapClock.withdraw(owner) }
    }

    @Test fun withdrawalDuringAnActualClockWaitRefusesTheOldValueAfterANewPublication() {
        val first = Any(); val second = Any()
        val origins = Profile03Origins.fromStream(UUID(0, 1), UUID(0, 2), "wss://gateway.example.test/device")
        val session = SealedDispatchExecutor.Session(UUID(0, 1), UUID(0, 2), 1, 1, UUID(0, 3), origins.routingHash)
        val block = AtomicBoolean(false); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var worker: Thread? = null
        try {
            Profile03BootstrapClock.publish(first, session, origins) {
                if (block.get()) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
                100
            }
            val observed = Profile03BootstrapClock.observation(session.accountId, session.deviceId, session.originHash)
            block.set(true)
            val result = FutureTask { runCatching { observed.now() } }
            worker = Thread(result, "synthetic-bootstrap-clock-wait").also { it.start() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            Profile03BootstrapClock.withdraw(first)
            Profile03BootstrapClock.publish(second, replacement(session, connectionEpoch = 2), origins) { 200 }
            release.countDown()
            assertTrue(result.get(5, TimeUnit.SECONDS).exceptionOrNull() is IllegalStateException)
            assertEquals(200L, Profile03BootstrapClock.observation(session.accountId, session.deviceId, session.originHash).now())
        } finally {
            release.countDown(); worker?.join(5_000)
            Profile03BootstrapClock.withdraw(first); Profile03BootstrapClock.withdraw(second)
        }
    }
}
