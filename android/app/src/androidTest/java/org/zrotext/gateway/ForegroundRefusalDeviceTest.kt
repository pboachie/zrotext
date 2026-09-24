// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Virtual-device only: every launch below must refuse before opening a socket or using SMS. */
@RunWith(AndroidJUnit4::class)
class ForegroundRefusalDeviceTest {
    private val app get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val url = "wss://localhost:8443/v1/device-stream"
    private val id = UUID.randomUUID().toString()

    @Before fun virtualOnly() {
        assumeTrue(InstrumentationRegistry.getArguments()
            .getString("virtualForegroundRefusal") == "true")
        assertTrue(HeartbeatResumeStore.clear(app))
    }

    @After fun cleanup() {
        if (InstrumentationRegistry.getArguments()
                .getString("virtualForegroundRefusal") != "true") return
        app.stopService(Intent(app, GatewayService::class.java))
        app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        HeartbeatResumeStore.clear(app)
    }

    @Test fun testTokenServiceRefusesMissingUrl() = testTokenRefusal(
        Intent(app, GatewayService::class.java).putExtra(GatewayService.EXTRA_TOKEN, "synthetic"))

    @Test fun testTokenServiceRefusesMissingToken() = testTokenRefusal(
        Intent(app, GatewayService::class.java).putExtra(GatewayService.EXTRA_URL, url))

    @Test fun testTokenServiceRefusesMalformedWssUrl() = testTokenRefusal(
        Intent(app, GatewayService::class.java)
            .putExtra(GatewayService.EXTRA_URL, "wss://%")
            .putExtra(GatewayService.EXTRA_TOKEN, "synthetic"))

    @Test fun testTokenServiceRefusesNonWssUrl() = testTokenRefusal(
        Intent(app, GatewayService::class.java)
            .putExtra(GatewayService.EXTRA_URL, "https://localhost:8443/m0/device-test")
            .putExtra(GatewayService.EXTRA_TOKEN, "synthetic"))

    @Test fun authenticatedServiceRefusesMissingUrl() = authenticatedRefusal(
        authStart().apply { removeExtra(AuthenticatedGatewayService.EXTRA_URL) },
        "Set a WSS device stream and approved device ID")

    @Test fun authenticatedServiceRefusesMalformedUrl() = authenticatedRefusal(
        authStart().putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://%"),
        "Set a WSS device stream and approved device ID")

    @Test fun authenticatedServiceRefusesNonCanonicalDeviceId() = authenticatedRefusal(
        authStart().putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID,
            "00000000-0000-0000-0000-00000000000A"),
        "Set a WSS device stream and approved device ID")

    @Test fun authenticatedServiceRefusesConflictingPilotModes() = authenticatedRefusal(
        authStart().putExtra(AuthenticatedGatewayService.EXTRA_INBOUND_UPLOAD, true)
            .putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_RECIPIENT, "+12025550123"),
        "Choose one pilot mode at a time")

    @Test fun authenticatedServiceRefusesBootOptInWithInboundPilot() = authenticatedRefusal(
        authStart().putExtra(AuthenticatedGatewayService.EXTRA_INBOUND_UPLOAD, true)
            .putExtra(AuthenticatedGatewayService.EXTRA_REBOOT_RESUME, true),
        "Choose one pilot mode at a time")

    @Test fun authenticatedServiceRefusesUsedAlphaAttempt() {
        val prefs = app.getSharedPreferences("alpha_pilot", Context.MODE_PRIVATE)
        val prior = prefs.getBoolean("attempt_used", false)
        assertTrue(prefs.edit().putBoolean("attempt_used", true).commit())
        try {
            authenticatedRefusal(
                authStart().putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_RECIPIENT,
                    "+12025550123"),
                "Alpha arm refused: one test attempt already used")
        } finally {
            assertTrue(prefs.edit().putBoolean("attempt_used", prior).commit())
        }
    }

    @Test fun authenticatedServiceRefusesInvalidAlphaRecipientOrSim() = authenticatedRefusal(
        authStart().putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_RECIPIENT, "invalid"),
        "Alpha arm refused: check recipient, SIM and unused test attempt")

    @Test fun authenticatedServiceRefusesMissingBootConfig() = authenticatedRefusal(
        Intent(app, AuthenticatedGatewayService::class.java)
            .setAction(AuthenticatedGatewayService.ACTION_BOOT_RESUME),
        "Set a WSS device stream and approved device ID")

    private fun authStart() = Intent(app, AuthenticatedGatewayService::class.java)
        .putExtra(AuthenticatedGatewayService.EXTRA_URL, url)
        .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, id)

    private fun testTokenRefusal(intent: Intent) {
        GatewayStatus.value = "Starting virtual refusal test"
        ContextCompat.startForegroundService(app, intent)
        awaitStopped(1001, "Set a WSS endpoint and test token", { GatewayStatus.value }) {
            !GatewayService.processActive
        }
        assertEquals("Set a WSS endpoint and test token", GatewayStatus.value)
        // A missed startForeground promotion terminates the process after the
        // platform timeout; keep the instrumented process alive beyond it.
        Thread.sleep(6_000)
        assertEquals("Set a WSS endpoint and test token", GatewayStatus.value)
        assertNoNotification(1001)
    }

    private fun authenticatedRefusal(intent: Intent, status: String) {
        AuthenticatedGatewayStatus.value = "Starting virtual refusal test"
        ContextCompat.startForegroundService(app, intent)
        awaitStopped(1002, status, { AuthenticatedGatewayStatus.value }) {
            !AuthenticatedGatewayService.processActive
        }
        assertEquals(status, AuthenticatedGatewayStatus.value)
        Thread.sleep(6_000)
        assertEquals(status, AuthenticatedGatewayStatus.value)
        assertNoNotification(1002)
        assertEquals(null, HeartbeatResumeStore.read(app))
    }

    private fun awaitStopped(notificationId: Int, expected: String,
                             status: () -> String, stopped: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000L
        while (System.currentTimeMillis() < deadline) {
            if (status() == expected && stopped() && !hasNotification(notificationId)) return
            Thread.sleep(50)
        }
        assertEquals("refusal message missing", expected, status())
        assertTrue("service did not stop", stopped())
        assertNoNotification(notificationId)
    }

    private fun hasNotification(id: Int): Boolean = app.getSystemService(NotificationManager::class.java)
        .activeNotifications.any { it.id == id }

    private fun assertNoNotification(id: Int) {
        assertFalse("foreground notification $id lingered", hasNotification(id))
    }
}
