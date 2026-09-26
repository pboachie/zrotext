// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Read-only platform sampling and wire serialization. Never sends or receives SMS. */
@RunWith(AndroidJUnit4::class)
class DevicePreconditionsDeviceTest {
    @Test fun platformObservationContainsOnlyPublicPreconditionEnums() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val publisher=DeviceStatusPublisher()
        assertNull(publisher.nextFrame(7,0) { error("Old hub must not sample") })
        publisher.selectProtocol(DeviceStatusPublisher.PROTOCOL)
        val serialized=checkNotNull(publisher.nextFrame(7,0) { DevicePreconditions.observe(context) })
        val frame=JSONObject(serialized)
        assertEquals(setOf("v","type","connection_epoch","selected_sim","sms_permission","airplane_mode"), frame.keys().asSequence().toSet())
        assertEquals("device_status",frame.getString("type"))
        assertTrue(frame.getString("selected_sim") in setOf("not_selected","active","inactive","unavailable"))
        assertTrue(frame.getString("sms_permission") in setOf("granted","denied","unavailable"))
        assertTrue(frame.getString("airplane_mode") in setOf("enabled","disabled","unavailable"))
        assertTrue(serialized.toByteArray().size<256)
        assertNull(publisher.nextFrame(7,1) { error("Fast repeats must not sample") })
    }
}
