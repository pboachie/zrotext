// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class AndroidPairingQrScannerAdapterTest {
    @Test fun uninitializedScannerConstructionAndFailedGesturesKeepManualPairingAvailable() {
        // No manifest startup provider initializes MlKitContext in this real SDK failure fixture.
        val source = AndroidPairingQrGoogleScanner(RuntimeEnvironment.getApplication())
        val origin = "https://owner.invalid"
        val id = "11111111-1111-4111-8111-111111111111"
        val token = "ztp_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
        var claims = 0
        val scanner = AndroidPairingQrScanner(source, { origin }, { 1_000L }, { inputs, complete ->
            inputs.use { actualOrigin, actualId, actualToken ->
                assertEquals(origin, actualOrigin); assertEquals(id, actualId); assertEquals(token, actualToken)
                claims++
            }
            complete(AndroidPairingQrClaimOutcome.Unknown)
        })
        try {
            assertTrue(scanner.snapshot().canUseManual)
            repeat(2) {
                assertTrue(scanner.scan())
                val current = scanner.snapshot()
                assertEquals(AndroidPairingQrScanner.Phase.IDLE, current.phase)
                assertTrue(current.canUseManual)
                assertTrue(current.status.contains("unavailable"))
                assertEquals(0, claims)
            }
            assertTrue(scanner.claimManual(origin, id, token, confirmed = true))
            assertEquals(1, claims)
            assertEquals(AndroidPairingQrScanner.Phase.UNKNOWN, scanner.snapshot().phase)
        } finally { scanner.close() }
    }
}
