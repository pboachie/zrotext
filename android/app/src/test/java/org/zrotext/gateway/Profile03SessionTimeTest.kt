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
class Profile03SessionTimeTest {
    private val account = UUID(0, 1)
    private val device = UUID(0, 2)
    private val session = UUID(0, 3)
    private var elapsed = 100L
    private var current = true
    private var lineVersion: Int? = 2
    private val sent = mutableListOf<JSONObject>()
    private fun clock() = Profile03SessionTime(account, device, 7, "ab".repeat(32), { elapsed }, { current },
        { lineVersion }, { sent.add(JSONObject(it)); true })
    private fun reply(time: Long = 100_000) = JSONObject().put("v", 1).put("type", "payload_profile_session03")
        .put("challenge", sent.last().getString("challenge")).put("account_id", account.toString())
        .put("device_id", device.toString()).put("connection_epoch", 7).put("deployment_epoch", 9)
        .put("session_id", session.toString()).put("server_time_ms", time)
        .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance").put("line_activation_version", 2)
    private fun JSONObject.bytes() = toString().toByteArray(Charsets.UTF_8)

    @Test fun exactAdditiveMetadataKeepsNonceRttAndCurrentLineClaim() {
        val clock = clock()
        assertTrue(clock.request())
        assertEquals(setOf("v", "type", "challenge", "connection_epoch"), sent.single().keys().asSequence().toSet())
        assertEquals("payload_profile_session03_request", sent.single().getString("type"))
        elapsed += 40; clock.accept(reply().bytes()); elapsed++
        assertEquals(100_041L, clock.nowMs())
        val identity = clock.snapshot()!!.first
        assertEquals(account, identity.session.accountId)
        assertEquals(device, identity.session.deviceId)
        assertEquals(session, identity.session.sessionId)
        assertEquals("synthetic-site", identity.site)
        lineVersion = 1
        assertNull(clock.nowMs()); assertNull(clock.snapshot()); assertFalse(clock.request())
    }
    @Test fun unsupportedLineConsumerNeverRequestsATimeAnchor() {
        for (version in listOf(null, 1, 3)) {
            lineVersion = version
            val clock = clock()
            assertFalse(clock.request()); assertNull(clock.snapshot()); assertTrue(sent.isEmpty())
        }
    }
    @Test fun missingUnknownCoercedDuplicateOldProfileOrForeignRepliesClosePermanently() {
        val cases = listOf<(JSONObject) -> ByteArray>(
            { it.remove("site_id"); it.bytes() }, { it.put("extra", 1).bytes() },
            { it.put("line_activation_version", 1).bytes() }, { it.put("line_activation_version", "2").bytes() },
            { it.put("type", "sealed_session").bytes() }, { it.put("server_time_ms", "100000").bytes() },
            { it.put("connection_epoch", 8).bytes() }, { it.put("account_id", device.toString()).bytes() },
            { it.put("challenge", session.toString()).bytes() },
            { (it.toString().dropLast(1) + ",\"site_id\":\"synthetic-site\"}").toByteArray() },
        )
        for (change in cases) {
            elapsed = 100; sent.clear()
            val clock = clock(); assertTrue(clock.request())
            assertTrue(runCatching { clock.accept(change(reply())) }.isFailure)
            assertNull(clock.snapshot()); assertFalse(clock.request())
        }
    }
    @Test fun refreshCannotSubstituteConfiguredSiteInstanceOrDeploymentAndSlowOrRebootedTimeRefuses() {
        for (change in listOf<(JSONObject) -> Unit>(
            { it.put("site_id", "different-site") }, { it.put("instance_id", "different-instance") },
            { it.put("deployment_epoch", 10) }, { it.put("session_id", device.toString()) },
            { elapsed += 2_001 }, { elapsed = 99 },
        )) {
            elapsed = 100; sent.clear()
            val clock = clock(); assertTrue(clock.request()); clock.accept(reply().bytes())
            elapsed = 25_101; assertTrue(clock.request())
            val frame = reply(125_001); change(frame)
            assertTrue(runCatching { clock.accept(frame.bytes()) }.isFailure)
            assertNull(clock.snapshot()); assertFalse(clock.request())
        }
    }
    @Test fun validResamplingKeepsOriginalIdentityAndNeverRestoresLostAuthority() {
        val clock = clock(); assertTrue(clock.request()); elapsed += 100; clock.accept(reply().bytes()); elapsed++
        val original = clock.snapshot()!!.first.session
        elapsed = 25_200; assertTrue(clock.request()); elapsed += 50; clock.accept(reply(125_050).bytes()); elapsed++
        assertSame(original, clock.snapshot()!!.first.session)
        assertEquals(125_151L, clock.nowMs())
        current = false; assertNull(clock.nowMs()); current = true
        assertNull(clock.snapshot()); assertFalse(clock.request())
    }
}
