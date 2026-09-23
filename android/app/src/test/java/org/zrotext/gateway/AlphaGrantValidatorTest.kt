// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class AlphaGrantValidatorTest {
    private val device = UUID.randomUUID()
    private val recipient = "+15551234567"
    private val now = 1_000_000L

    private fun frame(): JSONObject = JSONObject().apply {
        put("v", 1)
        put("type", "synthetic_grant")
        put("message_id", UUID.randomUUID().toString())
        put("attempt_id", UUID.randomUUID().toString())
        put("device_id", device.toString())
        put("generation", 1)
        put("connection_epoch", 8)
        put("deployment_epoch", 3)
        put("recipient_digest", Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(recipient.toByteArray())))
        put("expires_at_ms", now + 20_000)
        put("recipient_e164", recipient)
        put("body", "ZROtext synthetic test: case_1")
    }

    private fun valid(frame: JSONObject) = AlphaGrantValidator.validate(
        frame, device, 8, recipient, 4, listOf(4), now)

    @Test fun exactArmedGrantPasses() {
        assertEquals(4, valid(frame()).subscriptionId)
    }

    @Test fun identityRecipientEpochAndClockChangesFailClosed() {
        assertThrows(IllegalStateException::class.java) { valid(frame().put("device_id", UUID.randomUUID())) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("connection_epoch", 9)) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("recipient_digest", "wrong")) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("expires_at_ms", now - 1)) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("expires_at_ms", now + 60_000)) }
        assertThrows(IllegalStateException::class.java) {
            AlphaGrantValidator.validate(frame(), device, 8, "+15557654321", 4, listOf(4), now)
        }
        assertThrows(IllegalStateException::class.java) {
            AlphaGrantValidator.validate(frame(), device, 8, recipient, 4, listOf(5), now)
        }
    }

    @Test fun shapeAndFixedBodyFailClosed() {
        assertThrows(IllegalStateException::class.java) { valid(frame().put("extra", true)) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("body", "user content")) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("body", "ZROtext synthetic test: !")) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("generation", 0)) }
        assertThrows(IllegalStateException::class.java) { valid(frame().put("generation", 1.5)) }
    }
}
