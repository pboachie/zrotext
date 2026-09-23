// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Opt-in loopback probe. Only a public key is exported; no alpha send is armed. */
@RunWith(AndroidJUnit4::class)
class M1LocalAuthenticatedWssTest {
    @Test fun exportPublicKeyForDisposableLocalEnrollment() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires a private local M1 fixture", args.getString("m1LocalWss") == "true")
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val public = DeviceSigningKeyStore(app).getOrCreate()
        File(app.filesDir, PUBLIC_KEY_FILE).writeBytes(public.spkiDer)
        assertTrue(public.spkiDer.size in 80..160)
    }

    @Test fun authenticatedHeartbeatOverPrivateLoopbackTls() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires a private local M1 fixture", args.getString("m1LocalWss") == "true")
        val deviceId = args.getString("m1DeviceId")
        assumeTrue("requires an enrolled device ID", !deviceId.isNullOrBlank())
        UUID.fromString(deviceId)
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
        try {
            ContextCompat.startForegroundService(app, start)
            val deadline = System.currentTimeMillis() + 105_000L
            while (System.currentTimeMillis() < deadline && AuthenticatedGatewayStatus.heartbeats < 3) {
                Thread.sleep(500)
            }
            assertTrue(
                "expected 3 authenticated heartbeats; ${AuthenticatedGatewayStatus.value}: ${AuthenticatedGatewayStatus.heartbeats}",
                AuthenticatedGatewayStatus.heartbeats >= 3
            )
        } finally {
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }

    companion object { private const val PUBLIC_KEY_FILE = "m1-local-auth-public.spki" }
}
