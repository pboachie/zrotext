// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
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

    /**
     * Opt-in host coordination: close/restart only the loopback TLS proxy after
     * first_authenticated, then revoke the disposable DB device after reconnected.
     * Dispatch must be disabled. No alpha or inbound extras are passed to the service.
     */
    @Test fun reconnectsAfterTransportCloseThenStopsAfterRevocation() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires a private reconnect fixture", args.getString("m1Reconnect") == "true")
        val deviceId = args.getString("m1DeviceId")
        assumeTrue("requires a disposable enrolled device ID", !deviceId.isNullOrBlank())
        UUID.fromString(deviceId)
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val marker = File(app.filesDir, RECONNECT_MARKER)
        marker.delete()
        val priorAlphaUse = app.getSharedPreferences("alpha_pilot", 0)
            .getBoolean("attempt_used", false)
        AuthenticatedGatewayStatus.authenticatedSessions = 0
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
        try {
            ContextCompat.startForegroundService(app, start)
            awaitPhase(75_000, "first authenticated heartbeat") {
                AuthenticatedGatewayStatus.authenticatedSessions == 1 &&
                    AuthenticatedGatewayStatus.heartbeats >= 1
            }
            marker.writeText("first_authenticated")
            awaitPhase(90_000, "fresh proof and heartbeat after transport close") {
                AuthenticatedGatewayStatus.authenticatedSessions >= 2 &&
                    AuthenticatedGatewayStatus.heartbeats >= 1
            }
            marker.writeText("reconnected")
            awaitPhase(75_000, "terminal stop after device revocation") {
                AuthenticatedGatewayStatus.value ==
                    "Device proof or protocol rejected; restart manually"
            }
            assertEquals(2, AuthenticatedGatewayStatus.authenticatedSessions)
            assertEquals(priorAlphaUse, app.getSharedPreferences("alpha_pilot", 0)
                .getBoolean("attempt_used", false))
            marker.writeText("revoked_stopped")
        } finally {
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }

    private fun awaitPhase(timeoutMs: Long, phase: String, complete: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline && !complete()) {
            if (AuthenticatedGatewayStatus.value.contains("restart manually")) break
            Thread.sleep(250)
        }
        assertTrue("expected $phase; ${AuthenticatedGatewayStatus.value}; " +
            "sessions=${AuthenticatedGatewayStatus.authenticatedSessions}; " +
            "heartbeats=${AuthenticatedGatewayStatus.heartbeats}", complete())
    }

    companion object {
        private const val PUBLIC_KEY_FILE = "m1-local-auth-public.spki"
        private const val RECONNECT_MARKER = "m1-reconnect-phase.txt"
    }
}
