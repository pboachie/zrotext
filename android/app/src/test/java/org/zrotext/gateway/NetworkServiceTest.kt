// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class NetworkServiceTest {
    @Test fun onlyKnownPlatformStatesBecomeNamedObservations() {
        assertEquals(listOf(NetworkService.IN_SERVICE, NetworkService.OUT_OF_SERVICE,
            NetworkService.EMERGENCY_ONLY, NetworkService.POWER_OFF), (0..3).map(NetworkService::fromPlatform))
        for (invalid in listOf(-1, 4, Int.MAX_VALUE)) assertEquals(NetworkService.UNAVAILABLE, NetworkService.fromPlatform(invalid))
    }
    @Test fun selectionPermissionAndMonotonicDeadlineInvalidateObservation() {
        for ((selection, time) in listOf(null to 100L, 8 to 100L, 7 to 99L, 7 to 5101L)) {
            assertEquals(NetworkService.UNAVAILABLE, NetworkServiceCapture(7,100).complete(selection,time,NetworkService.IN_SERVICE))
        }
        assertEquals(NetworkService.IN_SERVICE, NetworkServiceCapture(7,100).complete(7,5100,NetworkService.IN_SERVICE))
    }
    @Test fun cancellationAndDuplicateCallbacksCannotPublish() {
        val cancelled=NetworkServiceCapture(7,0)
        cancelled.cancel()
        assertNull(cancelled.complete(7,1,NetworkService.IN_SERVICE))
        val once=NetworkServiceCapture(7,0)
        assertEquals(NetworkService.UNAVAILABLE,once.complete(7,1,NetworkService.UNAVAILABLE))
        assertNull(once.complete(7,2,NetworkService.IN_SERVICE))
    }
    @Test fun negotiatedVersionsShareOneBudgetAndV1ShapeRemainsExact() {
        val publisher=DeviceStatusPublisher()
        publisher.selectProtocol(DeviceStatusPublisher.PROTOCOL_V2)
        assertEquals(DeviceStatusPublisher.Version.V2,publisher.nextVersion(7,0))
        publisher.selectProtocol(DeviceStatusPublisher.PROTOCOL)
        assertNull(publisher.nextVersion(7,1))
        assertEquals(DeviceStatusPublisher.Version.V1,publisher.nextVersion(7,30000))
        publisher.selectProtocol("unsupported")
        assertNull(publisher.nextVersion(7,60000))
    }
    @Test fun metadataV2HasOnlyFixedPublicEnums() {
        val observed=DevicePreconditions(DevicePreconditions.SelectedSim.ACTIVE,
            DevicePreconditions.SmsPermission.GRANTED,DevicePreconditions.AirplaneMode.DISABLED)
        assertFalse(observed.frame(7).contains("network_service"))
        for (value in NetworkService.entries) {
            assertEquals("""{"v":1,"type":"device_status_v2","connection_epoch":7,"selected_sim":"active","sms_permission":"granted","airplane_mode":"disabled","network_service":"${value.wire}"}""",observed.frameV2(7,value))
        }
    }
    @Test fun finalUnavailableSelectionCannotRetainAnEarlierServiceResult() {
        for (selection in DevicePreconditions.SelectedSim.entries.filter { it != DevicePreconditions.SelectedSim.ACTIVE }) {
            val observed=DevicePreconditions(selection,DevicePreconditions.SmsPermission.GRANTED,DevicePreconditions.AirplaneMode.DISABLED)
            assertTrue(observed.frameV2(7,NetworkService.IN_SERVICE).contains("\"network_service\":\"unavailable\""))
        }
    }

}
