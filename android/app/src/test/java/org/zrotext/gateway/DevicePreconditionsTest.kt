// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class DevicePreconditionsTest {
    private val snapshot = DevicePreconditions(DevicePreconditions.SelectedSim.ACTIVE,
        DevicePreconditions.SmsPermission.GRANTED, DevicePreconditions.AirplaneMode.DISABLED)

    @Test fun unavailableSubscriptionObservationCannotClaimAnInactiveOrActiveSim() {
        assertEquals(DevicePreconditions.SelectedSim.NOT_SELECTED, DevicePreconditions.selectedSim(-1, null))
        assertEquals(DevicePreconditions.SelectedSim.UNAVAILABLE, DevicePreconditions.selectedSim(7, null))
        assertEquals(DevicePreconditions.SelectedSim.INACTIVE, DevicePreconditions.selectedSim(7, emptyList()))
        assertEquals(DevicePreconditions.SelectedSim.INACTIVE, DevicePreconditions.selectedSim(7, listOf(8)))
        assertEquals(DevicePreconditions.SelectedSim.ACTIVE, DevicePreconditions.selectedSim(7, listOf(7, 8)))
    }

    @Test fun anOldOrUnrecognizedHubNeverReceivesTelemetryOrTriggersSampling() {
        for (protocol in listOf(null, "", "other", DeviceStatusPublisher.PROTOCOL + ",other")) {
            val publisher = DeviceStatusPublisher()
            publisher.selectProtocol(protocol)
            assertNull(publisher.nextFrame(1, 0) { error("An unnegotiated connection must not sample") })
        }
    }

    @Test fun negotiatedReportsAreBoundedAndContainNoLocalIdentifiersOrClock() {
        val publisher = DeviceStatusPublisher()
        publisher.selectProtocol(DeviceStatusPublisher.PROTOCOL)
        val expected = """{"v":1,"type":"device_status","connection_epoch":4,"selected_sim":"active","sms_permission":"granted","airplane_mode":"disabled"}"""
        assertEquals(expected, publisher.nextFrame(4, 100) { snapshot })
        assertNull(publisher.nextFrame(4, 25_099) { error("Must throttle before sampling") })
        assertNull(publisher.nextFrame(4, 99) { error("Monotonic time reversal must not bypass throttle") })
        assertEquals(expected, publisher.nextFrame(4, 25_100) { snapshot })
        assertTrue(expected.toByteArray().size < 256)
    }

    @Test fun invalidSessionCannotReportAndNewConnectionDoesNotReuseThrottleState() {
        val publisher = DeviceStatusPublisher()
        publisher.selectProtocol(DeviceStatusPublisher.PROTOCOL)
        assertNull(publisher.nextFrame(0, 0) { error("No authenticated epoch") })
        assertNull(publisher.nextFrame(1, -1) { error("Invalid elapsed time") })
        assertNotNull(publisher.nextFrame(1, 0) { snapshot })
        val replacement = DeviceStatusPublisher()
        replacement.selectProtocol(DeviceStatusPublisher.PROTOCOL)
        assertNotNull(replacement.nextFrame(2, 0) { snapshot })
    }
}
