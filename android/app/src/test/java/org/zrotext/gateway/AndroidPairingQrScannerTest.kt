// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class AndroidPairingQrScannerTest {
    private class Fixture {
        var origin = "https://owner.invalid"
        var at = 1_000L
        val id = "11111111-1111-4111-8111-111111111111"
        val token = "ztp_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
        val scanCallbacks = mutableListOf<(AndroidPairingQrScanResult) -> Unit>()
        val inputs = mutableListOf<AndroidPairingQrClaimInputs>()
        val claimCallbacks = mutableListOf<(AndroidPairingQrClaimOutcome) -> Unit>()
        val verified = mutableListOf<VerifiedPairing>()
        val result = VerifiedPairing("12345678", "ab".repeat(32), SigningKeySecurity.SOFTWARE, null)
        var immediateClaimFailure = false
        val scanner = AndroidPairingQrScanner(
            AndroidPairingQrScanSource { scanCallbacks.add(it) }, { origin }, { at },
            { value, complete ->
                if (immediateClaimFailure) throw IllegalStateException("synthetic transport failure")
                inputs.add(value); claimCallbacks.add(complete)
            }, { value, _, _ -> verified.add(value) })
        fun raw(server: String = origin) = "{\"type\":\"zrotext-pairing\",\"v\":1,\"origin\":\"$server\",\"pairing_id\":\"$id\",\"token\":\"$token\"}"
        fun review() { assertTrue(scanner.scan()); scanCallbacks.last()(AndroidPairingQrScanResult.Scanned(raw())) }
        fun claim() { review(); assertTrue(scanner.confirmOrigin(true)) }
    }

    @Test fun constructionAndUnconfirmedReviewNeverInvokeClaimOrProvisionAnything() {
        val f = Fixture(); assertTrue(f.scanCallbacks.isEmpty()); assertTrue(f.inputs.isEmpty())
        f.review(); assertEquals(AndroidPairingQrScanner.Phase.REVIEW, f.scanner.snapshot().phase)
        assertEquals(f.origin, f.scanner.snapshot().scannedOrigin)
        assertFalse(f.scanner.confirmOrigin(false)); assertTrue(f.inputs.isEmpty())
        assertFalse(f.scanner.snapshot().toString().contains(f.token)); f.scanner.close()
    }

    @Test fun explicitConfirmationHandsOnlyExactInputsToOneExistingClaim() {
        val f = Fixture(); f.claim(); assertEquals(1, f.inputs.size)
        f.inputs.single().use { origin, id, token -> assertEquals(f.origin, origin); assertEquals(f.id, id); assertEquals(f.token, token) }
        assertFalse(f.scanner.confirmOrigin(true)); assertFalse(f.scanner.scan())
        assertFalse(f.scanner.claimManual(f.origin, f.id, f.token, true))
        f.claimCallbacks.single()(AndroidPairingQrClaimOutcome.Verified(f.result))
        assertEquals(listOf(f.result), f.verified); assertEquals(AndroidPairingQrScanner.Phase.VERIFIED, f.scanner.snapshot().phase)
        assertTrue(f.scanner.snapshot().status.contains("explicitly approve")); f.scanner.close()
    }

    @Test fun scannedOriginCannotReplaceIndependentlyKnownServer() {
        val f = Fixture(); f.scanner.scan()
        f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw("https://other.invalid")))
        assertEquals(AndroidPairingQrScanner.Phase.IDLE, f.scanner.snapshot().phase)
        assertFalse(f.scanner.confirmOrigin(true)); assertTrue(f.inputs.isEmpty()); assertNull(f.scanner.snapshot().scannedOrigin)
    }

    @Test fun changedKnownServerBeforeReviewOrConfirmationRevokesTheToken() {
        for (afterReview in listOf(false, true)) {
            val f = Fixture(); f.scanner.scan()
            if (afterReview) f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
            f.origin = "https://other.invalid"
            if (!afterReview) f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw("https://owner.invalid")))
            assertFalse(f.scanner.confirmOrigin(true)); assertTrue(f.inputs.isEmpty()); assertEquals(AndroidPairingQrScanner.Phase.IDLE, f.scanner.snapshot().phase)
        }
    }

    @Test fun malformedScanRevokesStateWithoutAClaimOrTokenInErrors() {
        val f = Fixture(); f.scanner.scan(); f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw() + " "))
        assertEquals(AndroidPairingQrScanner.Phase.IDLE, f.scanner.snapshot().phase)
        assertTrue(f.scanner.snapshot().canUseManual); assertFalse(f.scanner.snapshot().status.contains(f.token)); assertTrue(f.inputs.isEmpty())
    }

    @Test fun cancelKeepsPhysicalScanInFlightAndRejectsItsLateResult() {
        val f = Fixture(); f.scanner.scan(); f.scanner.cancel()
        assertFalse(f.scanner.scan()); assertFalse(f.scanner.snapshot().canUseManual)
        f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
        assertEquals(AndroidPairingQrScanner.Phase.IDLE, f.scanner.snapshot().phase)
        assertTrue(f.scanner.snapshot().canUseManual); assertTrue(f.inputs.isEmpty()); assertNull(f.scanner.snapshot().scannedOrigin)
        assertTrue(f.scanner.scan()); assertEquals(2, f.scanCallbacks.size)
        f.scanCallbacks.first()(AndroidPairingQrScanResult.Scanned(f.raw()))
        assertEquals(AndroidPairingQrScanner.Phase.SCANNING, f.scanner.snapshot().phase); f.scanner.close()
    }

    @Test fun unavailableAndCanceledScannerOfferManualFallbackWithoutAutomaticRetry() {
        for (result in listOf(AndroidPairingQrScanResult.Canceled, AndroidPairingQrScanResult.Unavailable)) {
            val f = Fixture(); f.scanner.scan(); f.scanCallbacks.single()(result)
            assertEquals(1, f.scanCallbacks.size); assertTrue(f.scanner.snapshot().canUseManual); assertTrue(f.inputs.isEmpty())
        }
    }

    @Test fun invalidIndependentOriginAndClockPreventEvenOpeningScanner() {
        val f = Fixture(); f.origin = "http://owner.invalid"; assertFalse(f.scanner.scan()); assertTrue(f.scanCallbacks.isEmpty())
        f.origin = "https://owner.invalid"; f.at = -1; assertFalse(f.scanner.scan()); assertTrue(f.scanCallbacks.isEmpty())
    }

    @Test fun scannerActivityExcursionCannotClaimBeforeTheHostResumes() {
        val f = Fixture(); f.scanner.scan(); f.scanner.pause()
        f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
        assertFalse(f.scanner.snapshot().canConfirm); assertFalse(f.scanner.confirmOrigin(true)); assertTrue(f.inputs.isEmpty())
        f.scanner.resume(); assertTrue(f.scanner.confirmOrigin(true)); f.scanner.cancel()
        assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, f.scanner.snapshot().phase)
    }

    @Test fun reviewPauseCancelAndCloseClearInputsAndFenceLateCallbacks() {
        for (loss in listOf("pause", "cancel", "close")) {
            val f = Fixture(); f.review()
            when (loss) { "pause" -> f.scanner.pause(); "cancel" -> f.scanner.cancel(); else -> f.scanner.close() }
            f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
            assertNull(f.scanner.snapshot().scannedOrigin); assertFalse(f.scanner.confirmOrigin(true)); assertTrue(f.inputs.isEmpty())
        }
    }

    @Test fun expiryAndClockRegressionRejectReviewAndLateScan() {
        for (at in listOf(301_000L, 999L, Long.MIN_VALUE)) for (reviewed in listOf(false, true)) {
            val f = Fixture(); f.scanner.scan()
            if (reviewed) f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
            f.at = at
            if (!reviewed) f.scanCallbacks.single()(AndroidPairingQrScanResult.Scanned(f.raw()))
            assertFalse(f.scanner.confirmOrigin(true)); assertTrue(f.inputs.isEmpty()); assertEquals(AndroidPairingQrScanner.Phase.IDLE, f.scanner.snapshot().phase)
        }
    }

    @Test fun verifiedComparisonStateExpiresAtOriginalDeadlineOrServerChange() {
        for (serverChanges in listOf(false, true)) {
            val f = Fixture(); f.claim(); f.claimCallbacks.single()(AndroidPairingQrClaimOutcome.Verified(f.result))
            val accepted = f.scanner.snapshot(); assertEquals(AndroidPairingQrScanner.Phase.VERIFIED, accepted.phase)
            if (serverChanges) f.origin = "https://other.invalid" else f.at = 301_000L
            val current = f.scanner.snapshot()
            assertEquals(AndroidPairingQrScanner.Phase.IDLE, current.phase); assertTrue(current.generation > accepted.generation)
            assertNull(current.expectedOrigin); assertNull(current.scannedOrigin)
        }
    }

    @Test fun cancelOrPauseDuringClaimWipesHeldTokenAndSuppressesLateSuccessWithoutRetry() {
        for (loss in listOf("cancel", "pause", "close")) {
            val f = Fixture(); f.claim(); val inputs = f.inputs.single()
            when (loss) { "cancel" -> f.scanner.cancel(); "pause" -> f.scanner.pause(); else -> f.scanner.close() }
            assertThrows(IllegalStateException::class.java) { inputs.use { _, _, _ -> fail("canceled worker must not send") } }
            f.claimCallbacks.single()(AndroidPairingQrClaimOutcome.Verified(f.result))
            assertTrue(f.verified.isEmpty()); assertFalse(f.scanner.scan()); assertFalse(f.scanner.snapshot().canUseManual)
        }
    }

    @Test fun delayedWorkerRechecksIndependentOriginAndExpiryBeforeCredentialUse() {
        for (changeOrigin in listOf(false, true)) {
            val f = Fixture(); f.claim()
            if (changeOrigin) f.origin = "https://other.invalid" else f.at = 301_000L
            assertThrows(IllegalStateException::class.java) { f.inputs.single().use { _, _, _ -> fail("changed context must not send") } }
            assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, f.scanner.snapshot().phase); assertFalse(f.scanner.snapshot().canUseManual)
        }
    }

    @Test fun changedOriginOrExpiredCompletionNeverPublishesProof() {
        for (changeOrigin in listOf(false, true)) {
            val f = Fixture(); f.claim()
            if (changeOrigin) f.origin = "https://other.invalid" else f.at = 301_000L
            f.claimCallbacks.single()(AndroidPairingQrClaimOutcome.Verified(f.result))
            assertTrue(f.verified.isEmpty()); assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, f.scanner.snapshot().phase)
        }
    }

    @Test fun transportFailureLatchesUnknownAndCannotBeClearedIntoRetry() {
        val f = Fixture(); f.immediateClaimFailure = true; f.review(); assertTrue(f.scanner.confirmOrigin(true))
        assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, f.scanner.snapshot().phase)
        f.scanner.cancel(); f.scanner.pause(); f.scanner.resume(); f.at += 600_000L
        assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, f.scanner.snapshot().phase)
        assertFalse(f.scanner.scan()); assertFalse(f.scanner.claimManual(f.origin, f.id, f.token, true)); assertFalse(f.scanner.snapshot().canUseManual)
    }

    @Test fun manualClaimUsesTheSameConsentAndOneInflightState() {
        val f = Fixture(); assertFalse(f.scanner.claimManual(f.origin, f.id, f.token, false)); assertTrue(f.inputs.isEmpty())
        assertTrue(f.scanner.claimManual(f.origin, f.id, f.token, true)); assertEquals(1, f.inputs.size)
        f.inputs.single().use { origin, id, token -> assertEquals(f.origin, origin); assertEquals(f.id, id); assertEquals(f.token, token) }
        assertFalse(f.scanner.scan()); assertFalse(f.scanner.claimManual(f.origin, f.id, f.token, true)); assertEquals(1, f.inputs.size)
        f.claimCallbacks.single()(AndroidPairingQrClaimOutcome.Unknown); assertFalse(f.scanner.snapshot().canUseManual)
    }

    @Test fun manualMalformedForeignOrBusyInputsNeverReachTransport() {
        val f = Fixture()
        assertFalse(f.scanner.claimManual("https://other.invalid", f.id, f.token, true))
        assertFalse(f.scanner.claimManual(f.origin, "1-1-1-1-1", f.token, true))
        assertFalse(f.scanner.claimManual(f.origin, f.id, f.token + "=", true)); assertTrue(f.inputs.isEmpty())
        f.scanner.scan(); assertFalse(f.scanner.claimManual(f.origin, f.id, f.token, true)); assertTrue(f.inputs.isEmpty()); f.scanner.close()
    }

    @Test fun reentrantCancelBeforeTransportSchedulingRevokesTheOperation() {
        lateinit var scanner: AndroidPairingQrScanner
        var delivered = 0
        val f = Fixture()
        scanner = AndroidPairingQrScanner(AndroidPairingQrScanSource {}, { f.origin }, { f.at },
            { _, _ -> delivered++ }, changed = { if (scanner.snapshot().phase == AndroidPairingQrScanner.Phase.CLAIMING) scanner.cancel() })
        assertFalse(scanner.claimManual(f.origin, f.id, f.token, true)); assertEquals(0, delivered)
        assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, scanner.snapshot().phase)
    }
}
