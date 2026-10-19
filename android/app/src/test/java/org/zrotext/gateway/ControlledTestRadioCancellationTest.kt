// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Deterministic retirement at the blocking operations immediately preceding a radio call. */
class ControlledTestRadioCancellationTest {
    private fun await(latch: CountDownLatch) = assertTrue(latch.await(5, TimeUnit.SECONDS))

    @Test fun pauseDuringApprovalReadRejectsItsOtherwiseSuccessfulResult() {
        val current = AtomicBoolean(true)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = AtomicBoolean(true)
        val worker = thread {
            result.set(ControlledTestApproval.currentAfterApproval(current::get) {
                entered.countDown(); await(release); true
            })
        }
        try { await(entered); current.set(false) } finally { release.countDown() }
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertFalse(result.get())
    }

    @Test fun pauseWhileWaitingForSuppressionLockCallsNoRadio() {
        val current = AtomicBoolean(true)
        val entered = CountDownLatch(1)
        val calls = AtomicInteger()
        val result = AtomicReference<SmsAttemptAdapter.StartResult>()
        lateinit var worker: Thread
        synchronized(LocalSuppressionGate.lock) {
            worker = thread {
                entered.countDown()
                result.set(SmsAttemptAdapter.withFinalRadioGuard({ false }, { true }, current::get, { true },
                    { SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT },
                    { calls.incrementAndGet(); SmsAttemptAdapter.StartResult.CALL_RETURNED }))
            }
            await(entered)
            current.set(false)
        }
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(0, calls.get())
        assertEquals(SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT, result.get())
    }

    @Test fun selectedSimChangeDuringApprovalReadRejectsItsOtherwiseSuccessfulResult() {
        val selected = AtomicInteger(7)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = AtomicBoolean(true)
        val worker = thread {
            result.set(ControlledTestApproval.currentAfterApproval({ selected.get() == 7 }) {
                entered.countDown(); await(release); true
            })
        }
        try { await(entered); selected.set(8) } finally { release.countDown() }
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertFalse(result.get())
    }

    @Test fun pauseDuringSuppressionQueryCallsNoRadio() {
        val current = AtomicBoolean(true)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val result = AtomicReference<SmsAttemptAdapter.StartResult>()
        val worker = thread {
            result.set(SmsAttemptAdapter.withFinalRadioGuard(
                { entered.countDown(); await(release); false }, { true }, current::get, { true },
                { SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT },
                { calls.incrementAndGet(); SmsAttemptAdapter.StartResult.CALL_RETURNED }))
        }
        try { await(entered); current.set(false) } finally { release.countDown() }
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(0, calls.get())
        assertEquals(SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT, result.get())
    }

    @Test fun pauseDuringFinalSimLookupCallsNoRadio() {
        val current = AtomicBoolean(true)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val result = AtomicReference<SmsAttemptAdapter.StartResult>()
        val worker = thread {
            result.set(SmsAttemptAdapter.withFinalRadioGuard(
                { false }, { entered.countDown(); await(release); true }, current::get, { true },
                { SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT },
                { calls.incrementAndGet(); SmsAttemptAdapter.StartResult.CALL_RETURNED }))
        }
        try { await(entered); current.set(false) } finally { release.countDown() }
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(0, calls.get())
        assertEquals(SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT, result.get())
    }

    @Test fun currentUnsuppressedAuthorityCallsRadioOnceAndSuppressionRefuses() {
        val calls = AtomicInteger()
        val send = { calls.incrementAndGet(); SmsAttemptAdapter.StartResult.CALL_RETURNED }
        val denied = { SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT }
        assertEquals(SmsAttemptAdapter.StartResult.CALL_RETURNED,
            SmsAttemptAdapter.withFinalRadioGuard({ false }, { true }, { true }, { true }, denied, send))
        assertEquals(SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT,
            SmsAttemptAdapter.withFinalRadioGuard({ true }, { true }, { true }, { true }, denied, send))
        assertEquals(1, calls.get())
    }
}
