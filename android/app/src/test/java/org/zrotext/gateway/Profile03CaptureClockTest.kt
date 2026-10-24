// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03CaptureClockTest {
    private val account = UUID(0, 1)
    private val device = UUID(0, 2)
    private val session = UUID(0, 3)
    private var elapsed = 0L
    private var reads = 0
    private var current = true
    private val requests = mutableListOf<JSONObject>()
    private val clock = Profile03SessionTime(account, device, 7, "ab".repeat(32),
        { reads++; elapsed }, { current }, { 2 }, { requests.add(JSONObject(it)); true })

    private fun sample(sent: Long) {
        clock.accept(JSONObject().put("v", 1).put("type", "payload_profile_session03")
            .put("challenge", requests.last().getString("challenge"))
            .put("account_id", account.toString()).put("device_id", device.toString())
            .put("connection_epoch", 7).put("deployment_epoch", 9)
            .put("session_id", session.toString()).put("server_time_ms", sent)
            .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
            .put("line_activation_version", 2).toString().toByteArray())
    }

    @Test fun firstBoundsUseOneElapsedReadAndDoNotReplaceConservativeExpiry() {
        assertNull(clock.captureBounds()); assertEquals(0, reads)
        assertTrue(clock.request()); elapsed = 2_000; sample(102_000)
        assertNull(clock.captureBounds()) // The anchor instant itself remains unusable.
        elapsed++
        val before = reads
        val first = checkNotNull(clock.captureBounds())
        assertEquals(before + 1, reads)
        assertEquals(102_001L, first.lowerMs)
        assertEquals(104_001L, first.upperMs)
        assertEquals(elapsed, first.elapsedMs)
        assertSame(clock.snapshot()!!.first, first.identity)
        assertEquals(first.upperMs, clock.nowMs())
        val expiry = 103_000L
        assertTrue(first.lowerMs < expiry)
        assertTrue(checkNotNull(clock.nowMs()) >= expiry) // The lower cannot extend an effect deadline.
    }

    @Test fun opposingAsymmetricSamplesCarryTheStrongestLowerInsteadOfDoublingUncertainty() {
        assertTrue(clock.request()); elapsed = 2_000; sample(102_000)
        elapsed = 27_000; assertTrue(clock.request()); elapsed = 29_000; sample(127_000)
        elapsed++
        val second = checkNotNull(clock.captureBounds())
        assertEquals(129_001L, second.lowerMs)
        assertEquals(131_001L, second.upperMs)
        assertEquals(2_000L, second.upperMs - second.lowerMs)
        // Latest send alone would be127001, falsely widening to4000ms.
        assertTrue(second.lowerMs > 127_001)
        assertSame(second.identity.session, clock.snapshot()!!.first.session)
    }

    @Test fun retainedFirstStampNeverChangesOnANewerSample() {
        assertTrue(clock.request()); elapsed = 50; sample(100_000); elapsed++
        val original = checkNotNull(clock.captureBounds())
        elapsed = 25_001; assertTrue(clock.request()); elapsed = 25_021; sample(124_971); elapsed++
        val next = checkNotNull(clock.captureBounds())
        assertTrue(next.lowerMs > original.lowerMs)
        assertEquals(100_001L, original.lowerMs)
        assertEquals(100_051L, original.upperMs)
        assertEquals(51L, original.elapsedMs)
        assertSame(original.identity.session, next.identity.session)
    }

    @Test fun lostSessionRebootAndAgedAnchorNeverYieldAReceiptClockOrRecoverItCold() {
        for (change in listOf<() -> Unit>({ current = false }, { elapsed = -1 }, { elapsed += 60_001 })) {
            val start = UUID.randomUUID()
            var at = 10L
            var alive = true
            val raw = mutableListOf<JSONObject>()
            val bounded = SealedSocketTime(account, device, 7, "ab".repeat(32), { at }, { alive }, { raw.add(it); true })
            assertTrue(bounded.request())
            bounded.accept(JSONObject().put("v", 1).put("type", "sealed_session")
                .put("challenge", raw.last().getString("challenge")).put("account_id", account.toString())
                .put("device_id", device.toString()).put("connection_epoch", 7).put("deployment_epoch", 9)
                .put("session_id", start.toString()).put("server_time_ms", 100_000))
            at++
            assertNotNull(bounded.captureBounds())
            change()
            if (!current) alive = false else if (elapsed < 0) at = 9 else at += 60_001
            assertNull(bounded.captureBounds())
            bounded.close(); at = 12; alive = true
            assertNull(bounded.captureBounds()); assertFalse(bounded.request())
            current = true; elapsed = 0
        }
    }
}
