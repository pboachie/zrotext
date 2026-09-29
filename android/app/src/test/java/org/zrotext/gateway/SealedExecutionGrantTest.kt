// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Roadmap #539: a sealed execution grant is bound to one device, line, session, envelope and moment. */
class SealedExecutionGrantTest {
    private val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val device = UUID.fromString("22222222-2222-4222-8222-222222222222")
    private val line = UUID.fromString("33333333-3333-4333-8333-333333333333")
    private val message = UUID.fromString("44444444-4444-4444-8444-444444444444")
    private val attempt = UUID.fromString("55555555-5555-4555-8555-555555555555")
    private val envelope = ByteArray(600) { (it % 251).toByte() }
    private val digest = SealedExecutionGrantValidator.sha256(envelope)
    private val now = 1_800_000_000_000L
    private val expires = now + 20_000L

    private fun fields(
        deviceId: UUID = device,
        accountId: UUID = account,
        lineId: UUID = line,
        messageId: UUID = message,
        attemptId: UUID = attempt,
        epoch: Long = 77L,
        envelopeDigest: ByteArray = digest,
        expiresAtMs: Long = expires,
        segmentCount: Int = 1,
    ) = SealedExecutionGrantValidator.Fields(
        accountId, deviceId, lineId, messageId, attemptId, epoch,
        envelopeDigest, expiresAtMs, segmentCount
    )

    @Test
    fun matchingGrantIsValid() {
        val result = SealedExecutionGrantValidator.validate(
            fields(), envelope, account, device, line, 77L, now
        )
        assertTrue(result is SealedExecutionGrantValidator.Verdict.Valid)
    }

    @Test
    fun refusalTableCoversEveryBindingAndTimingFailure() {
        fun refusal(
            f: SealedExecutionGrantValidator.Fields,
            authDevice: UUID = device,
            authAccount: UUID = account,
            activeLine: UUID = line,
            epoch: Long = 77L,
            bytes: ByteArray = envelope,
            nowMs: Long = now
        ) = SealedExecutionGrantValidator.validate(f, bytes, authAccount, authDevice, activeLine, epoch, nowMs)

        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.DEVICE_MISMATCH,
            refusal(fields(deviceId = UUID.randomUUID()))
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.DEVICE_MISMATCH,
            refusal(fields(), authAccount = UUID.randomUUID())
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.LINE_MISMATCH,
            refusal(fields(), activeLine = UUID.randomUUID())
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.SESSION_MISMATCH,
            refusal(fields(), epoch = 76L)
        )
        // A one-byte envelope substitution must refuse even with a plausible shape.
        val substituted = envelope.copyOf().also { it[100] = (it[100] + 1).toByte() }
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH,
            refusal(fields(), bytes = substituted)
        )
        // The same envelope under a different digest claim refuses too.
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH,
            refusal(fields(envelopeDigest = SealedExecutionGrantValidator.sha256(ByteArray(600))))
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_OR_ATTEMPT_MISMATCH,
            refusal(fields(attemptId = UUID(0, 0)))
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.EXPIRED,
            refusal(fields(expiresAtMs = now), nowMs = now)
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.IMPLAUSIBLE_EXPIRY,
            refusal(fields(expiresAtMs = now + SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS + 1))
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_OUT_OF_RANGE,
            refusal(fields(segmentCount = 7))
        )
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_OUT_OF_RANGE,
            refusal(fields(segmentCount = 0))
        )
    }

    @Test
    fun expiryAtTheExactBoundaryIsRefusedAndJustInsideItIsValid() {
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.EXPIRED,
            SealedExecutionGrantValidator.validate(
                fields(expiresAtMs = now), envelope, account, device, line, 77L, now
            )
        )
        assertTrue(
            SealedExecutionGrantValidator.validate(
                fields(expiresAtMs = now + 1), envelope, account, device, line, 77L, now
            ) is SealedExecutionGrantValidator.Verdict.Valid
        )
        // The plausibility ceiling itself is acceptable; one millisecond past it is not.
        assertTrue(
            SealedExecutionGrantValidator.validate(
                fields(expiresAtMs = now + SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS),
                envelope, account, device, line, 77L, now
            ) is SealedExecutionGrantValidator.Verdict.Valid
        )
    }

    @Test
    fun validGrantCarriesNoEnvelopeBytesAndRedactsItself() {
        val valid = SealedExecutionGrantValidator.validate(
            fields(), envelope, account, device, line, 77L, now
        ) as SealedExecutionGrantValidator.Verdict.Valid
        // The digest binds execution to these exact bytes without carrying them.
        assertTrue(MessageDigestRef.equal(valid.grant.envelopeDigest, digest))
        assertEquals("SealedExecutionGrant(redacted)", valid.grant.toString())
    }

    @Test
    fun plaintextRulesAcceptStrictUtf8AndRefuseTheContractViolations() {
        assertTrue(SealedPlaintextRules.acceptBody("hello".toByteArray(Charsets.UTF_8)))
        assertFalse(SealedPlaintextRules.acceptBody(ByteArray(0)))
        assertFalse(
            SealedPlaintextRules.acceptBody(ByteArray(SealedPlaintextRules.MAX_BODY_BYTES + 1) { 'a'.code.toByte() })
        )
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte(), 'h'.code.toByte())))
                // A NUL inside the body refuses.
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf('a'.code.toByte(), 0, 'b'.code.toByte())))
        // Overlong or invalid UTF-8 must refuse rather than replace.
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xC0.toByte(), 0xAF.toByte())))
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xFF.toByte())))
        // A NUL inside the body refuses.
        assertFalse(SealedPlaintextRules.acceptBody("a\u0000b".toByteArray(Charsets.UTF_8)))
    }

    private object MessageDigestRef {
        fun equal(a: ByteArray, b: ByteArray) = java.security.MessageDigest.isEqual(a, b)
    }
}
