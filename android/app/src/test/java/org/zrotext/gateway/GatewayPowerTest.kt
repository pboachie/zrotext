// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.BroadcastReceiver
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Handler
import androidx.core.content.ContextCompat
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GatewayPowerTest {
    private fun battery(level: Int, status: Int) = Intent(Intent.ACTION_BATTERY_CHANGED)
        .putExtra(BatteryManager.EXTRA_LEVEL, level)
        .putExtra(BatteryManager.EXTRA_SCALE, 100)
        .putExtra(BatteryManager.EXTRA_STATUS, status)

    @Test fun missingMalformedAndAbsentBatteryNeverBecomeZeroOrCharging() {
        assertEquals("Unavailable", GatewayPowerObservation.from(null).label)
        for ((level, scale) in listOf(-1 to 100, 101 to 100, 1 to 0, 1 to -1)) {
            assertEquals("Unavailable", GatewayPowerObservation.from(level, scale, -1).label)
        }
        assertEquals("Unavailable", GatewayPowerObservation.from(100, 100,
            BatteryManager.BATTERY_STATUS_FULL, present = false).label)
        assertEquals("Unavailable", GatewayPowerObservation.from(Intent("unrelated")).label)
    }

    @Test fun trueZeroScaledLevelsAndChargingTransitionsRemainDistinct() {
        assertEquals("0% · Not charging", GatewayPowerObservation.from(0, 100,
            BatteryManager.BATTERY_STATUS_DISCHARGING).label)
        assertEquals("50% · Charging or full", GatewayPowerObservation.from(1, 2,
            BatteryManager.BATTERY_STATUS_CHARGING).label)
        assertEquals(true, GatewayPowerObservation.from(100, 100,
            BatteryManager.BATTERY_STATUS_FULL).charging)
        assertEquals(false, GatewayPowerObservation.from(80, 100,
            BatteryManager.BATTERY_STATUS_NOT_CHARGING).charging)
        assertEquals(100, GatewayPowerObservation.from(Int.MAX_VALUE, Int.MAX_VALUE, -1).percentage)
    }

    @Test fun partialObservationsDiscloseWhichValueIsUnavailable() {
        assertEquals("80% · Charging state unavailable", GatewayPowerObservation.from(80, 100, -1).label)
        assertEquals("Charge level unavailable · Charging or full", GatewayPowerObservation.from(-1, -1,
            BatteryManager.BATTERY_STATUS_CHARGING).label)
    }

    private class PowerContext : ContextWrapper(RuntimeEnvironment.getApplication()) {
        var current: Intent? = null
        var receiver: BroadcastReceiver? = null
        var registrations = 0
        var removals = 0
        var flags = 0
        var refuse = false
        override fun registerReceiver(receiver: BroadcastReceiver?, filter: IntentFilter, flags: Int): Intent? {
            assertTrue(filter.hasAction(Intent.ACTION_BATTERY_CHANGED))
            if (refuse) throw SecurityException("synthetic refusal")
            this.receiver = receiver
            this.flags = flags
            registrations++
            return current
        }
        override fun registerReceiver(receiver: BroadcastReceiver?, filter: IntentFilter,
            broadcastPermission: String?, scheduler: Handler?, flags: Int): Intent? =
            registerReceiver(receiver, filter, flags)
        override fun unregisterReceiver(receiver: BroadcastReceiver) {
            assertSame(this.receiver, receiver)
            this.receiver = null
            removals++
        }
        override fun startService(service: Intent) = error("Power observation cannot start services")
        override fun startForegroundService(service: Intent) = error("Power observation cannot start services")
    }

    @Test fun resumedHomeRegistersOnceRefreshesAndUnregistersWithoutServiceEffects() {
        val context = PowerContext()
        val observations = mutableListOf<GatewayPowerObservation>()
        val monitor = GatewayPowerMonitor(context, observations::add)
        context.current = battery(80, BatteryManager.BATTERY_STATUS_CHARGING)
        monitor.resume(); monitor.resume()
        assertEquals(1, context.registrations)
        assertEquals(ContextCompat.RECEIVER_NOT_EXPORTED, context.flags)
        assertEquals("80% · Charging or full", observations.last().label)
        val delayed = requireNotNull(context.receiver)
        delayed.onReceive(context, battery(70, BatteryManager.BATTERY_STATUS_DISCHARGING))
        assertEquals("70% · Not charging", observations.last().label)
        monitor.pause(); monitor.pause()
        assertEquals(1, context.removals)
        assertEquals("Unavailable", observations.last().label)
        delayed.onReceive(context, battery(99, BatteryManager.BATTERY_STATUS_FULL))
        assertEquals("Unavailable", observations.last().label)
        context.current = battery(60, BatteryManager.BATTERY_STATUS_NOT_CHARGING)
        monitor.resume()
        assertEquals(2, context.registrations)
        assertEquals("60% · Not charging", observations.last().label)
        monitor.pause(); assertEquals(2, context.removals)
    }

    @Test fun registrationRefusalAndMissingStickyReportStayUnavailableAndCanRefresh() {
        val context = PowerContext()
        val observations = mutableListOf<GatewayPowerObservation>()
        val monitor = GatewayPowerMonitor(context, observations::add)
        context.refuse = true; monitor.resume()
        assertEquals("Unavailable", observations.last().label)
        monitor.pause(); assertEquals(0, context.removals)
        context.refuse = false; monitor.resume()
        assertEquals("Unavailable", observations.last().label)
        requireNotNull(context.receiver).onReceive(context, battery(25, BatteryManager.BATTERY_STATUS_CHARGING))
        assertEquals("25% · Charging or full", observations.last().label)
        monitor.pause()
    }
}
