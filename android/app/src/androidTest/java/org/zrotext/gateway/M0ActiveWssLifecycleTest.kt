// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Explicitly gated, heartbeat-only lifecycle fixture. The host terminates the service. */
@RunWith(AndroidJUnit4::class)
class M0ActiveWssLifecycleTest {
    @Test fun startOneAuthenticatedHeartbeatAndLeaveRunning() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("m0ActiveWss") == "true")
        val deviceId = args.getString("m1DeviceId")
        assumeTrue(!deviceId.isNullOrBlank())
        UUID.fromString(deviceId)
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
            .putExtra(AuthenticatedGatewayService.EXTRA_REBOOT_RESUME,
                args.getString("m0BootOptIn") == "true")
        ContextCompat.startForegroundService(app, start)
        val deadline = System.currentTimeMillis() + 45_000L
        while (System.currentTimeMillis() < deadline && AuthenticatedGatewayStatus.heartbeats < 1) {
            Thread.sleep(200)
        }
        assertTrue("expected authenticated heartbeat: ${AuthenticatedGatewayStatus.value}",
            AuthenticatedGatewayStatus.heartbeats >= 1)
        if (args.getString("m0HoldOpen") == "true") {
            Thread.sleep(120_000L)
        }
    }

    @Test fun pauseClearsRebootResume() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("m0BootOptIn") == "true")
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        app.startService(Intent(app, AuthenticatedGatewayService::class.java)
            .setAction(AuthenticatedGatewayService.ACTION_PAUSE))
        val deadline = System.currentTimeMillis() + 5_000L
        while (System.currentTimeMillis() < deadline && HeartbeatResumeStore.read(app) != null) {
            Thread.sleep(100)
        }
        assertNull(HeartbeatResumeStore.read(app))
    }
}
