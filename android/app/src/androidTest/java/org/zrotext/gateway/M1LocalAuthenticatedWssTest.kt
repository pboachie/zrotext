// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.PowerManager
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
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

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

    /** Opt-in external WSS probe. No alpha, inbound, or radio extras are armed. */
    @Test fun authenticatedHeartbeatOverExternalTlsWithoutRadio() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires an external WSS fixture", args.getString("m1ExternalWss") == "true")
        val deviceId = args.getString("m1DeviceId")
        require(!deviceId.isNullOrBlank()) { "disposable enrolled device ID required" }
        UUID.fromString(deviceId)
        val url = args.getString("m1ExternalWssUrl")
        require(!url.isNullOrBlank()) { "external WSS URL required" }
        val endpoint = URI(url)
        require(endpoint.scheme == "wss" && !endpoint.host.isNullOrBlank() &&
            endpoint.host.lowercase() !in setOf("localhost", "127.0.0.1", "::1") &&
            endpoint.rawPath == "/v1/device-stream" && endpoint.rawQuery == null &&
            endpoint.rawFragment == null && endpoint.rawUserInfo == null) {
            "external WSS URL must be a secure device-stream endpoint"
        }
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val priorAlphaUse = app.getSharedPreferences("alpha_pilot", 0)
            .getBoolean("attempt_used", false)
        AuthenticatedGatewayStatus.authenticatedSessions = 0
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, url)
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
        try {
            ContextCompat.startForegroundService(app, start)
            awaitPhase(105_000, "three authenticated external WSS heartbeats") {
                AuthenticatedGatewayStatus.authenticatedSessions == 1 &&
                    AuthenticatedGatewayStatus.heartbeats >= 3
            }
            assertEquals(priorAlphaUse, app.getSharedPreferences("alpha_pilot", 0)
                .getBoolean("attempt_used", false))
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

    /** Opt-in battery probe: no pilot extras, radio action, or network toggle. */
    @Test fun screenOffBatteryHeartbeatAndTransportRecovery() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires a private battery fixture", args.getString("m1BatteryIdle") == "true")
        val deviceId = args.getString("m1DeviceId")
        assumeTrue("requires a disposable enrolled device ID", !deviceId.isNullOrBlank())
        UUID.fromString(deviceId)
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val power = app.getSystemService(PowerManager::class.java)
        val marker = File(app.filesDir, BATTERY_MARKER)
        val evidence = File(app.filesDir, BATTERY_EVIDENCE)
        marker.delete()
        evidence.delete()
        val samples = JSONArray()
        val startedAt = SystemClock.elapsedRealtime()
        val initialBattery = batteryState(app)
        assertTrue("battery must be discharging and unplugged: $initialBattery",
            initialBattery.second == 0 && initialBattery.third == BatteryManager.BATTERY_STATUS_DISCHARGING)
        AuthenticatedGatewayStatus.authenticatedSessions = 0
        AuthenticatedGatewayStatus.heartbeats = 0
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
            .putExtra(AuthenticatedGatewayService.EXTRA_HEARTBEAT_TIMING_TRACE, true)
        var sampledSession = 0
        var sampledAck = 0
        var screenOffStartedAt = 0L
        fun sample() {
            val battery = batteryState(app)
            check(battery.second == 0 && battery.third == BatteryManager.BATTERY_STATUS_DISCHARGING) {
                "battery power changed: $battery"
            }
            check(!power.isInteractive) { "display became interactive" }
            check(battery.first >= initialBattery.first - 5) { "battery level dropped unexpectedly: $battery" }
            val session = AuthenticatedGatewayStatus.authenticatedSessions
            val ack = AuthenticatedGatewayStatus.heartbeats
            if (session != sampledSession) {
                sampledSession = session
                sampledAck = 0
            }
            if (ack > sampledAck) {
                samples.put(JSONObject()
                    .put("elapsed_ms", SystemClock.elapsedRealtime() - startedAt)
                    .put("session", session).put("session_heartbeat", ack)
                    .put("battery_percent", battery.first)
                    .put("plugged", battery.second).put("screen_off", true))
                sampledAck = ack
            }
        }
        fun awaitIdle(durationMs: Long, phase: String, complete: () -> Boolean) {
            val deadline = SystemClock.elapsedRealtime() + durationMs
            while (SystemClock.elapsedRealtime() < deadline) {
                sample()
                if (complete()) return
                check(!AuthenticatedGatewayStatus.value.contains("restart manually")) {
                    "terminal service state during $phase: ${AuthenticatedGatewayStatus.value}"
                }
                Thread.sleep(250)
            }
            sample()
            assertTrue("timed out during $phase: ${AuthenticatedGatewayStatus.value}", complete())
        }
        try {
            ContextCompat.startForegroundService(app, start)
            val firstAckDeadline = SystemClock.elapsedRealtime() + 75_000
            while (SystemClock.elapsedRealtime() < firstAckDeadline &&
                !(AuthenticatedGatewayStatus.authenticatedSessions == 1 &&
                    AuthenticatedGatewayStatus.heartbeats >= 1)) {
                Thread.sleep(250)
            }
            assertTrue("initial authenticated heartbeat missing: ${AuthenticatedGatewayStatus.value}",
                AuthenticatedGatewayStatus.authenticatedSessions == 1 &&
                    AuthenticatedGatewayStatus.heartbeats >= 1)
            marker.writeText("ready_for_screen_off")
            val offDeadline = SystemClock.elapsedRealtime() + 30_000
            while (power.isInteractive && SystemClock.elapsedRealtime() < offDeadline) Thread.sleep(250)
            assertTrue("display did not become non-interactive", !power.isInteractive)
            screenOffStartedAt = SystemClock.elapsedRealtime()
            sampledSession = AuthenticatedGatewayStatus.authenticatedSessions
            sampledAck = AuthenticatedGatewayStatus.heartbeats
            val firstWindow = SystemClock.elapsedRealtime() + 120_000
            while (SystemClock.elapsedRealtime() < firstWindow) {
                sample()
                Thread.sleep(250)
            }
            sample()
            val firstSession = AuthenticatedGatewayStatus.authenticatedSessions
            assertEquals("unexpected reauthentication during first idle window", 1, firstSession)
            val firstAcks = (0 until samples.length()).count {
                samples.getJSONObject(it).getInt("session") == firstSession
            }
            // The authenticated stream requests one heartbeat every 30 seconds.
            // Three new acks allow one delayed/missed sample in this 120-second window.
            assertTrue("too few first-window heartbeat acknowledgments: $firstAcks", firstAcks >= 3)
            marker.writeText("close_proxy")
            awaitIdle(90_000, "fresh proof and heartbeat after proxy close") {
                AuthenticatedGatewayStatus.authenticatedSessions > firstSession &&
                    samples.length() > 0 &&
                    samples.getJSONObject(samples.length() - 1).getInt("session") > firstSession
            }
            val secondWindow = SystemClock.elapsedRealtime() + 120_000
            while (SystemClock.elapsedRealtime() < secondWindow) {
                sample()
                Thread.sleep(250)
            }
            val secondAcks = (0 until samples.length()).count {
                samples.getJSONObject(it).getInt("session") == firstSession + 1
            }
            // Includes the first post-reconnect ack plus at least three more.
            assertTrue("too few recovery-window heartbeat acknowledgments: $secondAcks", secondAcks >= 4)
            assertEquals("unexpected reauthentication during recovery idle window",
                firstSession + 1, AuthenticatedGatewayStatus.authenticatedSessions)
            marker.writeText("complete")
        } finally {
            evidence.writeText(JSONObject()
                .put("elapsed_ms", SystemClock.elapsedRealtime() - startedAt)
                .put("screen_off_started_ms", screenOffStartedAt - startedAt)
                .put("initial_battery_percent", initialBattery.first)
                .put("final_battery_percent", batteryState(app).first)
                .put("final_plugged", batteryState(app).second)
                .put("final_screen_off", !power.isInteractive)
                .put("sessions", AuthenticatedGatewayStatus.authenticatedSessions)
                .put("status", AuthenticatedGatewayStatus.value)
                .put("samples", samples).toString())
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }

    private fun batteryState(app: android.content.Context): Triple<Int, Int, Int> {
        val state = app.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?: error("battery state unavailable")
        return Triple(state.getIntExtra(BatteryManager.EXTRA_LEVEL, -1),
            state.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1),
            state.getIntExtra(BatteryManager.EXTRA_STATUS, -1))
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
        private const val BATTERY_MARKER = "m1-battery-probe-phase.txt"
        private const val BATTERY_EVIDENCE = "m1-battery-probe-evidence.json"
    }
}
