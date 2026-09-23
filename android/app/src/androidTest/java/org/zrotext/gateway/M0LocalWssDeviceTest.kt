// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.PowerManager
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in hardware probe. Pass m0TestToken only while a private loopback writer is running. */
@RunWith(AndroidJUnit4::class)
class M0LocalWssDeviceTest {
    @Test fun threeHeartbeatsOverPrivateLoopbackTls() {
        val token = InstrumentationRegistry.getArguments().getString("m0TestToken")
        assumeTrue("requires a private local M0 server", !token.isNullOrBlank())
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val requireScreenOff = InstrumentationRegistry.getArguments()
            .getString("m0RequireScreenOff") == "true"
        val power = app.getSystemService(PowerManager::class.java)
        GatewayStatus.heartbeats = 0
        val start = Intent(app, GatewayService::class.java)
            .putExtra(GatewayService.EXTRA_URL, "wss://localhost:8443/m0/device-test")
            .putExtra(GatewayService.EXTRA_TOKEN, token)
        try {
            ContextCompat.startForegroundService(app, start)
            val deadline = System.currentTimeMillis() + 75_000
            var sampledAcks = 0
            var screenOffAcks = 0
            while (System.currentTimeMillis() < deadline && GatewayStatus.heartbeats < 3) {
                val current = GatewayStatus.heartbeats
                if (current > sampledAcks) {
                    if (!power.isInteractive) screenOffAcks += current - sampledAcks
                    sampledAcks = current
                }
                Thread.sleep(500)
            }
            if (GatewayStatus.heartbeats > sampledAcks && !power.isInteractive) {
                screenOffAcks += GatewayStatus.heartbeats - sampledAcks
            }
            assertTrue(
                "expected 3 M0 heartbeat acknowledgments; ${GatewayStatus.value}: ${GatewayStatus.heartbeats}",
                GatewayStatus.heartbeats >= 3
            )
            if (requireScreenOff) {
                assertTrue("expected 3 heartbeat acks while the display was non-interactive; got $screenOffAcks",
                    screenOffAcks >= 3)
            }
        } finally {
            app.stopService(Intent(app, GatewayService::class.java))
        }
    }
}
