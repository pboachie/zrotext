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
import java.io.File
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
        if (args.getString("m0BootOptIn") == "true") {
            assertTrue("expected committed reboot choice", HeartbeatResumeStore.read(app) != null)
        }
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

    @Test fun switchingToVisibleTestSessionClearsRebootResume() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("m0BootOptIn") == "true")
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val deviceId = UUID.randomUUID()
        assertTrue(HeartbeatResumeStore.save(app, HeartbeatResumeStore.Config(
            "wss://localhost:8443/v1/device-stream", deviceId)))
        try {
            assertTrue(GatewaySessionSelection.startVisibleTestSession(app,
                "wss://localhost:8443/v1/device-stream", "synthetic-test-token"))
            assertNull(HeartbeatResumeStore.read(app))
        } finally {
            app.stopService(Intent(app, GatewayService::class.java))
            HeartbeatResumeStore.clear(app)
        }
    }

    @Test fun terminalRejectionClearsRebootResume() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("m0ActiveWss") == "true" &&
            args.getString("m0BootOptIn") == "true")
        val deviceId = requireNotNull(args.getString("m1DeviceId"))
        UUID.fromString(deviceId)
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val marker = File(app.filesDir, "m0-terminal-phase.txt")
        marker.delete()
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
            .putExtra(AuthenticatedGatewayService.EXTRA_REBOOT_RESUME, true)
        try {
            ContextCompat.startForegroundService(app, start)
            val authDeadline = System.currentTimeMillis() + 45_000L
            while (System.currentTimeMillis() < authDeadline && AuthenticatedGatewayStatus.heartbeats < 1) {
                Thread.sleep(200)
            }
            assertTrue("expected authenticated heartbeat", AuthenticatedGatewayStatus.heartbeats >= 1)
            assertTrue("expected saved reboot choice", HeartbeatResumeStore.read(app) != null)
            marker.writeText("authenticated")
            val rejectionDeadline = System.currentTimeMillis() + 90_000L
            while (System.currentTimeMillis() < rejectionDeadline &&
                AuthenticatedGatewayStatus.value != "Device proof or protocol rejected; restart manually") {
                Thread.sleep(200)
            }
            assertTrue("expected terminal rejection: ${AuthenticatedGatewayStatus.value}",
                AuthenticatedGatewayStatus.value == "Device proof or protocol rejected; restart manually")
            assertNull(HeartbeatResumeStore.read(app))
            marker.writeText("terminal_cleared")
        } finally {
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }

}
