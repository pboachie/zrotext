// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.UUID

/**
 * No-radio activation check on a phone whose active line is an eSIM. It reads real telephony
 * state, never signs, never sends an SMS and leaves the app's keys and settings untouched.
 */
@RunWith(AndroidJUnit4::class)
class SmsLineActivationEsimDeviceTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun activationDeclinesBeforeSigningWhenOnlyAnEsimIsActive() {
        val observed = SimCardContinuity.observe(context)
        // Log only coarse shape: no subscription or card identifiers.
        Log.i("ZTSimCheck", "observed=${observed?.size} embedded=${observed?.map { it.isEmbedded }}")
        assumeTrue("needs readable telephony state with only eSIM lines active",
            observed != null && observed.isNotEmpty() && observed.all { it.isEmbedded })
        assertNull(SimCardContinuity.activationCandidate(observed))

        var signed = false
        val device = SmsLineActivationDevice(
            apiLevel = { android.os.Build.VERSION.SDK_INT },
            selectedSubscriptionId = { observed!!.first().subscriptionId },
            observe = { SimCardContinuity.observe(context) },
            sign = { _, _, _ -> signed = true; ByteArray(70) },
            nowMs = System::currentTimeMillis
        )
        val account = UUID.fromString("00000000-0000-4000-8000-00000000000a")
        val deviceId = UUID.fromString("00000000-0000-4000-8000-00000000000d")
        // A challenge parsed by the platform JSON implementation, as the gateway would receive it.
        val frame = JSONObject().put("v", 1).put("type", "sms_line_challenge")
            .put("challenge_id", "00000000-0000-4000-8000-00000000000e")
            .put("account_id", account.toString())
            .put("line_id", "00000000-0000-4000-8000-00000000000b")
            .put("device_id", deviceId.toString()).put("generation", 1)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 }))
            .put("expires_at_ms", System.currentTimeMillis() + 240_000)
        val challenge = SmsLineActivationFrames.challenge(frame)
        assertEquals(1L, challenge.generation)
        assertNull(device.prepare(challenge, account, deviceId))
        assertFalse("an eSIM line must be refused before any signature", signed)
    }
}
