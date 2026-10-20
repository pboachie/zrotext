// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.Assert.*
import org.junit.Test

/** Isolated RAM models, never a reset API for the shipping singleton. */
class InboundProtectionEpochTest {
    @Test fun receiverClassifiesAndWithdrawsBeforeItsFailingTokenOrStorageWait() {
        for ((body, expected) in listOf("STOP" to OptOutParser.OPT_OUT, "Please stop sending" to OptOutParser.OPT_OUT_REVIEW)) {
            val epochs = InboundProtectionEpochs()
            val lease = epochs.checked(epochs.snapshot())
            val order = mutableListOf<String>()
            var debt: String? = null
            val result = InboundProtectionIngress.prepare(body, { action ->
                assertEquals(expected, action); order += "withdraw"
                epochs.beforeProtectionWait(action)
            }, { receipt ->
                order += "key"
                assertNotNull(receipt)
                assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { lease.requireCurrent() }
                error("Synthetic original key/storage unavailable")
            }, { action, _ -> order += "debt"; debt = action; epochs.revoke() })
            assertNull(result); assertEquals(expected, debt)
            assertEquals(listOf("withdraw", "key", "debt"), order)
            assertFalse(epochs.available())
        }
    }
    @Test fun markerFailureStillRetainsClassifiedNegativeActionAndNeverCallsTokenProvider() {
        var tokens = 0; var action: String? = null
        val result = InboundProtectionIngress.prepare("STOP", { error("Synthetic crash latch failure") },
            { tokens++; "not reached" }, { value, _ -> action = value })
        assertNull(result); assertEquals(0, tokens); assertEquals(OptOutParser.OPT_OUT, action)
    }
    @Test fun successfulKnownRecipientWithdrawalDoesNotReviveAnyOldLease() {
        val epochs = InboundProtectionEpochs(); val old = epochs.checked(epochs.snapshot())
        val receipt = checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT))
        receipt.requireReading()
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { epochs.snapshot() }
        receipt.completeKnownWithdrawal()
        assertTrue(epochs.available())
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { old.requireCurrent() }
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { receipt.requireReading() }
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { receipt.completeKnownWithdrawal() }
        epochs.checked(epochs.snapshot()).requireCurrent()
    }
    @Test fun twoPendingWithdrawalsCannotReleaseEachOthersHold() {
        val epochs = InboundProtectionEpochs()
        val first = checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT))
        val second = checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT_REVIEW))
        first.requireReading(); second.requireReading(); first.completeKnownWithdrawal()
        assertFalse(epochs.available()); second.requireReading(); second.completeKnownWithdrawal()
        assertTrue(epochs.available())
    }
    @Test fun permanentFailureCannotBeClearedByAnOldHoldSuccessfulReadOrOptIn() {
        val epochs = InboundProtectionEpochs()
        val receipt = checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT))
        epochs.revoke(); epochs.revoke()
        assertNull(epochs.beforeProtectionWait(OptOutParser.OPT_IN))
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { epochs.beforeProtectionWait(OptOutParser.OPT_OUT) }
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { receipt.completeKnownWithdrawal() }
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { receipt.requireReading() }
        assertThrows(InboundProtectionEpochs.Withdrawn::class.java) { epochs.checked(0) }
        assertFalse(epochs.available())
    }
    @Test fun blockedFinalAlphaLookupCannotUseAnOtherwiseHealthyEpochAfterStopAndResume() {
        val epochs = InboundProtectionEpochs(); val lease = epochs.checked(epochs.snapshot())
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val called = AtomicBoolean(); val refused = AtomicBoolean()
        val worker = thread {
            try {
                SmsAttemptAdapter.withFinalRadioGuard({
                    entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); false
                }, { true }, { true }, { true }, { SmsAttemptAdapter.StartResult.RESERVED_NOT_SENT }, {
                    lease.requireCurrent(); called.set(true); SmsAttemptAdapter.StartResult.CALL_RETURNED
                })
            } catch (_: InboundProtectionEpochs.Withdrawn) { refused.set(true) }
        }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            checkNotNull(epochs.beforeProtectionWait(OptOutParser.OPT_OUT)).completeKnownWithdrawal()
            assertTrue(epochs.available()) // The old epoch still cannot be used.
        } finally { release.countDown() }
        worker.join(5_000); assertFalse(worker.isAlive); assertFalse(called.get()); assertTrue(refused.get())
    }
    @Test fun ordinaryAndOptInClassificationNeverInventsAWithdrawalOrClearsFailure() {
        for ((body, expected) in listOf("Synthetic inbound" to null, "START" to OptOutParser.OPT_IN)) {
            val epochs = InboundProtectionEpochs()
            val result = checkNotNull(InboundProtectionIngress.prepare(body, epochs::beforeProtectionWait,
                { assertNull(it); "synthetic tokens" }, { _, _ -> fail("Unexpected failure") }))
            assertEquals(expected, result.optAction); assertTrue(epochs.available())
            epochs.revoke()
            assertNull(epochs.beforeProtectionWait(expected)); assertFalse(epochs.available())
        }
    }
}
