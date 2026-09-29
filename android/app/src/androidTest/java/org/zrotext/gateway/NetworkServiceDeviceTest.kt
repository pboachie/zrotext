// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Explicit disposable-emulator opt-in. No SMS, radio mutation or stored SIM selection. */
@RunWith(AndroidJUnit4::class)
class NetworkServiceDeviceTest {
    @Test fun selectedSubscriptionGetsAnActualCallbackWithoutLocationPermission() {
        assertEquals("true", InstrumentationRegistry.getArguments().getString("networkServiceIsolatedEmulator"))
        assertTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        assertTrue(Build.VERSION.SDK_INT >= 33)
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(PackageManager.PERMISSION_DENIED,context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION))
        assertEquals(PackageManager.PERMISSION_DENIED,context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION))
        assertEquals(PackageManager.PERMISSION_DENIED,context.checkSelfPermission(Manifest.permission.SEND_SMS))
        assertEquals(PackageManager.PERMISSION_GRANTED,context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE))
        val active=checkNotNull(context.getSystemService(SubscriptionManager::class.java).activeSubscriptionInfoList)
        assertEquals(1,active.size)
        val selected=active.single().subscriptionId
        assertTrue(selected>=0)
        val sampler=NetworkServiceSampler(context, selectedId = { selected })
        val completed=CountDownLatch(1)
        val received=AtomicReference<NetworkService>()
        try {
            sampler.sample({true}) { value, activeIds -> received.set(value);
                // The one resolved lookup must still carry the selected subscription.
                assertTrue(checkNotNull(activeIds).contains(selected)); completed.countDown() }
            assertTrue("Actual callback deadline",completed.await(8,TimeUnit.SECONDS))
            assertTrue("Unknown-only output is not platform proof",received.get() in setOf(
                NetworkService.IN_SERVICE,NetworkService.OUT_OF_SERVICE,NetworkService.EMERGENCY_ONLY,NetworkService.POWER_OFF))
        } finally { sampler.cancel(); sampler.shutdown() }
    }
}
