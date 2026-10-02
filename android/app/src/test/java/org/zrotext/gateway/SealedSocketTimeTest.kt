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
@Config(sdk = [28], application = android.app.Application::class)
class SealedSocketTimeTest {
    private val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val device = UUID.fromString("22222222-2222-4222-8222-222222222222")
    private val identity = UUID.fromString("33333333-3333-4333-8333-333333333333")
    private var elapsed = 100L
    private var current = true
    private val sent = mutableListOf<JSONObject>()
    private fun clock() = SealedSocketTime(account, device, 7, "ab".repeat(32),
        { elapsed }, { current }, { sent.add(it); true })
    private fun reply(time: Long = 100_000L) = JSONObject().put("v", 1).put("type", "sealed_session")
        .put("challenge", sent.last().getString("challenge")).put("account_id", account.toString())
        .put("device_id", device.toString()).put("connection_epoch", 7).put("deployment_epoch", 9)
        .put("session_id", identity.toString()).put("server_time_ms", time)

    @Test fun authenticatedNonceSampleUsesConservativeTimeAndStableSession() {
        val clock = clock()
        assertTrue(clock.request()); elapsed += 40; clock.accept(reply())
        elapsed++
        assertEquals(100_041L, clock.trustedNow())
        assertEquals(identity, clock.currentSession()!!.sessionId)
        elapsed = 25_101; assertTrue(clock.request())
        elapsed += 20; clock.accept(reply(125_010))
        elapsed++; assertEquals(125_031L, clock.trustedNow())
        assertEquals(identity, clock.currentSession()!!.sessionId)
        assertEquals(2, sent.size)
    }

    @Test fun foreignReplayUnexpectedAndSlowSamplesPermanentlyClose() {
        for (mutate in listOf<(JSONObject) -> Unit>(
            { it.put("account_id", device.toString()) },
            { it.put("connection_epoch", 8) },
            { it.put("challenge", identity.toString()) },
            { it.put("unexpected", true) },
            { elapsed += 2_001 },
        )) {
            elapsed = 100; sent.clear()
            val clock = clock(); assertTrue(clock.request())
            val frame = reply(); mutate(frame)
            assertTrue(runCatching { clock.accept(frame) }.isFailure)
            assertNull(clock.currentSession()); assertFalse(clock.request())
        }
        elapsed = 100; sent.clear()
        val clock = clock(); assertTrue(clock.request()); val frame = reply()
        clock.accept(frame)
        assertTrue(runCatching { clock.accept(frame) }.isFailure)
        assertNull(clock.currentSession())
    }

    @Test fun rebootAgeAndSessionLossNeverUseWallClockFallback() {
        for (change in listOf<() -> Unit>({ elapsed = 99 }, { elapsed += 60_001 }, { current = false })) {
            elapsed = 100; current = true; sent.clear()
            val clock = clock(); assertTrue(clock.request()); clock.accept(reply()); elapsed++
            assertNotNull(clock.trustedNow()); change(); assertNull(clock.trustedNow())
        }
    }

    @Test fun resampleCannotChangeIdentityOrRollTimeBack() {
        for (mutate in listOf<(JSONObject) -> Unit>(
            { it.put("session_id", device.toString()) },
            { it.put("deployment_epoch", 10) },
            { it.put("server_time_ms", 100_000) },
        )) {
            elapsed = 100; current = true; sent.clear()
            val clock = clock(); assertTrue(clock.request()); clock.accept(reply())
            elapsed = 25_101; assertTrue(clock.request())
            val frame = reply(125_001); mutate(frame)
            assertTrue(runCatching { clock.accept(frame) }.isFailure)
            assertNull(clock.currentSession())
        }
    }

    @Test fun missingReplyAndFiniteSampleBudgetRequireANewSocket() {
        val missing = clock(); assertTrue(missing.request()); elapsed += 2_001
        assertFalse(missing.request()); assertNull(missing.currentSession())
        elapsed = 100; sent.clear()
        val bounded = clock()
        repeat(SealedSocketTime.MAX_SAMPLES) {
            assertTrue(bounded.request()); bounded.accept(reply(100_000 + elapsed))
            elapsed += SealedSocketTime.REQUEST_INTERVAL_MS
        }
        assertEquals(64, sent.size)
        assertFalse(bounded.request()); assertNull(bounded.currentSession())
    }
}
