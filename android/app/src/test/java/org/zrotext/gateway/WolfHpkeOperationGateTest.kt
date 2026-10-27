// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Deterministic RAM gate only, no native/provider/hardware acceptance assertion. */
class WolfHpkeOperationGateTest {
    @Test fun withdrawalWhileWaitingForAnotherNativeOperationPreventsEntry() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val waiting = CountDownLatch(1)
        val live = AtomicBoolean(true); val calls = AtomicInteger(); val outcome = AtomicReference<Throwable?>()
        val firstFailure = AtomicReference<Throwable?>()
        val first = Thread {
            try { WolfHpkeOperationGate.operation({}) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) } }
            catch (failure: Throwable) { firstFailure.set(failure) }
        }
        val second = Thread {
            try { WolfHpkeOperationGate.operation({ waiting.countDown(); check(live.get()) }) { calls.incrementAndGet() } }
            catch (failure: Throwable) { outcome.set(failure) }
        }
        try {
            first.start(); assertTrue(entered.await(5, TimeUnit.SECONDS)); second.start(); assertTrue(waiting.await(5, TimeUnit.SECONDS))
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (second.state != Thread.State.BLOCKED && System.nanoTime() < until) Thread.sleep(1)
            assertEquals("Actually waiting for the native gate after its first positive admission", Thread.State.BLOCKED, second.state)
            live.set(false); release.countDown(); first.join(5_000); second.join(5_000)
            assertFalse(first.isAlive); assertFalse(second.isAlive); assertNull(firstFailure.get()); assertNotNull(outcome.get()); assertEquals(0, calls.get())
        } finally { release.countDown(); first.join(5_000); second.join(5_000) }
    }
    @Test fun withdrawalDuringOperationRefusesOutputAndCallerClearsItsRetainedSecret() {
        val live = AtomicBoolean(true); val secret = ByteArray(32) { 9 }; var pending: ByteArray? = null
        assertThrows(Exception::class.java) {
            try {
                WolfHpkeOperationGate.operation({ check(live.get()) }) { secret.also { pending = it; live.set(false) } }
            } finally { pending?.fill(0) }
        }
        assertTrue(secret.all { it == 0.toByte() })
        assertEquals(7, WolfHpkeOperationGate.operation({}) { 7 })
    }
}
