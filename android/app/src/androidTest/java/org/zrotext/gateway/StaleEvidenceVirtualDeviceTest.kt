// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Virtual-only journal and reconnect checks. No service, socket, SIM, or radio is used. */
@RunWith(AndroidJUnit4::class)
class StaleEvidenceVirtualDeviceTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var dao: SmsAttemptDao
    private val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val oldDevice = UUID.fromString("22222222-2222-4222-8222-222222222222")
    private val newDevice = UUID.fromString("33333333-3333-4333-8333-333333333333")
    private val oldIdentity = EvidenceIdentity.fromStream(account, oldDevice,
        "wss://old.example:443/v1/device-stream")
    private val newIdentity = EvidenceIdentity.fromStream(account, newDevice,
        "wss://new.example/v1/device-stream")

    @Before fun setUp() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("virtualEvidenceOnly") == "true")
        db = Room.inMemoryDatabaseBuilder(InstrumentationRegistry.getInstrumentation().targetContext,
            SmsJournalDatabase::class.java).build()
        dao = db.attempts()
    }

    @After fun tearDown() {
        if (::db.isInitialized) db.close()
    }

    @Test fun rePairQuarantinesOldRadioAndInboundWithoutBlockingFreshEvent() {
        val oldAttempt = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        val oldMessage = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        val oldRadio = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        val oldInbound = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        dao.reserveAlpha(oldAttempt, oldMessage, 1, 1, oldRadio, 1000,
            identity = oldIdentity)
        dao.insertInboundWindow(InboundWindow(oldAttempt, oldMessage, "a".repeat(64),
            1, 1000, 5000))
        dao.insertInboundEvent(InboundEvent(oldInbound, oldAttempt, oldMessage,
            "b".repeat(64), 1, 2000, 1, InboundClassification.CAPTURED_LOCAL,
            ByteArray(24), ByteArray(12)))
        dao.insertInboundUpload(InboundUpload(eventId = oldInbound,
            accountId = oldIdentity.accountId, deviceId = oldIdentity.deviceId,
            originHash = oldIdentity.originHash))

        assertEquals(1, dao.quarantineForeignAlpha(newIdentity.accountId,
            newIdentity.deviceId, newIdentity.originHash, 3000))
        assertEquals(1, dao.quarantineForeignInbound(newIdentity.accountId,
            newIdentity.deviceId, newIdentity.originHash, 3000))
        assertEquals("identity_changed", dao.getAlphaEvent(oldRadio)?.quarantineReason)
        assertEquals("identity_changed", dao.inboundUpload(oldInbound)?.quarantineReason)
        assertFalse(dao.acknowledgeAlphaIntent(oldRadio, true, 3001))
        assertNull(dao.nextInboundUpload(0, newIdentity.accountId,
            newIdentity.deviceId, newIdentity.originHash))

        val freshRadio = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        dao.reserveAlpha("ffffffff-ffff-4fff-8fff-ffffffffffff",
            "12345678-1234-4234-8234-123456789abc", 1, 1, freshRadio, 4000,
            identity = newIdentity)
        assertEquals(freshRadio, dao.nextAlphaEvent(newIdentity.accountId,
            newIdentity.deviceId, newIdentity.originHash)?.eventId)
        assertEquals(1, dao.acknowledgeAlphaEvent(freshRadio, 4001))
        assertNull(dao.nextAlphaEvent(newIdentity.accountId,
            newIdentity.deviceId, newIdentity.originHash))
    }

    @Test fun repeatedOldWriterCloseQuarantinesOneRowAndHeartbeatCanRetry() {
        val event = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        dao.reserveAlpha("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 1, 1, event, 1000,
            identity = oldIdentity)
        val policy = DeviceReconnectPolicy { 0.5 }
        assertEquals(DeviceReconnectPolicy.Action.Connect(
            DeviceReconnectPolicy.PilotMode.ALPHA_ONCE),
            policy.start(true, DeviceReconnectPolicy.PilotMode.ALPHA_ONCE))
        repeat(3) { index ->
            policy.authenticated(100L + index)
            val quarantine = policy.recordEvidenceClose("radio:$event", false)
            assertEquals(index == 2, quarantine)
            if (quarantine) assertEquals(1,
                dao.quarantineAlphaEvent(event, "server_rejected", 2000))
            val action = policy.lost(if (quarantine)
                DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED
                else DeviceReconnectPolicy.Loss.ACTIVE_CLOSE, 100L + index)
            assertTrue(action is DeviceReconnectPolicy.Action.RetryAfter)
            assertEquals(DeviceReconnectPolicy.Action.Connect(
                DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY), policy.retryDue())
        }
        assertNull(dao.nextAlphaEvent(oldIdentity.accountId,
            oldIdentity.deviceId, oldIdentity.originHash))
        assertEquals("server_rejected", dao.getAlphaEvent(event)?.quarantineReason)
    }

    @Test fun normalizedOriginUsesSameHashAndDifferentServerChangesIt() {
        assertEquals(oldIdentity.originHash, EvidenceIdentity.fromStream(account, oldDevice,
            "wss://OLD.EXAMPLE/v1/device-stream").originHash)
        assertTrue(oldIdentity.originHash != EvidenceIdentity.fromStream(account, oldDevice,
            "wss://other.example/v1/device-stream").originHash)
    }
}
