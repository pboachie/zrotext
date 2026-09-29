// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Roadmap #539: a sealed execution grant is bound to one account, device, line,
 * message, reader, session, envelope and moment. One test per binding field, so a
 * mutation that drops any single fence fails exactly that field's test.
 */
class SealedExecutionGrantTest {
    private val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val device = UUID.fromString("22222222-2222-4222-8222-222222222222")
    private val line = UUID.fromString("33333333-3333-4333-8333-333333333333")
    private val message = UUID.fromString("44444444-4444-4444-8444-444444444444")
    private val attempt = UUID.fromString("55555555-5555-4555-8555-555555555555")
    private val other = UUID.fromString("66666666-6666-4666-8666-666666666666")
    private val readerKey = ByteArray(32) { 7 }
    private val archiveKey = ByteArray(32) { 8 }
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
        readerRole: Int = 1,
        readerKeyId: ByteArray = readerKey,
        deploymentEpoch: Long = 3L,
        bindingGeneration: Long = 9L,
    ) = SealedExecutionGrantValidator.Fields(
        accountId, deviceId, lineId, messageId, attemptId, epoch,
        envelopeDigest, expiresAtMs, segmentCount, readerRole, readerKeyId,
        deploymentEpoch, bindingGeneration, 1L, ByteArray(32) { 5 },
    )

    private fun claims(
        accountId: UUID = account,
        messageId: UUID = message,
        deviceId: UUID = device,
        lineId: UUID = line,
        reader: ByteArray = readerKey,
    ) = SealedExecutionGrantValidator.EnvelopeClaims(accountId, messageId, deviceId, lineId, reader)

    private fun verdict(
        f: SealedExecutionGrantValidator.Fields = fields(),
        c: SealedExecutionGrantValidator.EnvelopeClaims = claims(),
        authAccount: UUID = account,
        authDevice: UUID = device,
        activeLine: UUID = line,
        epoch: Long = 77L,
        deployment: Long = 3L,
        bindingGeneration: Long = 9L,
        pinnedReader: ByteArray = readerKey,
        bytes: ByteArray = envelope,
        nowMs: Long = now,
    ) = SealedExecutionGrantValidator.validate(
        f, bytes, c, authAccount, authDevice, activeLine, epoch, deployment, bindingGeneration, pinnedReader, nowMs,
    )

    private fun assertRefused(expected: SealedExecutionGrantValidator.Verdict.Refused, actual: Any) =
        assertEquals(expected, actual)

    @Test
    fun matchingGrantIsValid() {
        assertTrue(verdict() is SealedExecutionGrantValidator.Verdict.Valid)
    }

    @Test
    fun accountBindsSessionGrantAndEnvelope() {
        val refused = SealedExecutionGrantValidator.Verdict.Refused.ACCOUNT_MISMATCH
        assertRefused(refused, verdict(fields(accountId = other)))
        assertRefused(refused, verdict(authAccount = other))
        assertRefused(refused, verdict(c = claims(accountId = other)))
    }

    @Test
    fun deviceBindsSessionGrantAndEnvelope() {
        val refused = SealedExecutionGrantValidator.Verdict.Refused.DEVICE_MISMATCH
        assertRefused(refused, verdict(fields(deviceId = other)))
        assertRefused(refused, verdict(authDevice = other))
        assertRefused(refused, verdict(c = claims(deviceId = other)))
    }

    @Test
    fun lineBindsActiveLineGrantEnvelopeAndBindingGeneration() {
        val refused = SealedExecutionGrantValidator.Verdict.Refused.LINE_MISMATCH
        assertRefused(refused, verdict(fields(lineId = other)))
        assertRefused(refused, verdict(activeLine = other))
        assertRefused(refused, verdict(c = claims(lineId = other)))
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.BINDING_GENERATION_MISMATCH,
            verdict(bindingGeneration = 10L)
        )
    }

    @Test
    fun messageBindsTheEnvelopeClaimAndAttemptMustBeNonZero() {
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_MISMATCH,
            verdict(fields(messageId = other))
        )
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_MISMATCH,
            verdict(c = claims(messageId = other))
        )
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_OR_ATTEMPT_MISMATCH,
            verdict(fields(attemptId = UUID(0, 0)))
        )
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_OR_ATTEMPT_MISMATCH,
            verdict(fields(messageId = UUID(0, 0)), c = claims(messageId = UUID(0, 0)))
        )
    }

    @Test
    fun onlyTheDevicePayloadReaderRoleMayDecrypt() {
        for (role in listOf(0, 2, 3, 4)) {
            assertRefused(
                SealedExecutionGrantValidator.Verdict.Refused.READER_ROLE_MISMATCH,
                verdict(fields(readerRole = role))
            )
        }
    }

    @Test
    fun readerKeyBindsThisDevicesKeystoreKeyAndTheEnvelopeWrap() {
        val refused = SealedExecutionGrantValidator.Verdict.Refused.READER_KEY_MISMATCH
        assertRefused(refused, verdict(fields(readerKeyId = archiveKey)))
        assertRefused(refused, verdict(pinnedReader = archiveKey))
        assertRefused(refused, verdict(c = claims(reader = archiveKey)))
        // The grant and the device may agree and still be refused when the envelope's device wrap differs.
        assertRefused(refused, verdict(fields(readerKeyId = archiveKey), pinnedReader = archiveKey))
    }

    @Test
    fun sessionAndDeploymentEpochsMustBeCurrent() {
        assertRefused(SealedExecutionGrantValidator.Verdict.Refused.SESSION_MISMATCH, verdict(epoch = 76L))
        assertRefused(SealedExecutionGrantValidator.Verdict.Refused.SESSION_MISMATCH, verdict(fields(epoch = 78L)))
        assertRefused(SealedExecutionGrantValidator.Verdict.Refused.DEPLOYMENT_MISMATCH, verdict(deployment = 4L))
    }

    @Test
    fun envelopeDigestBindsTheExactBytes() {
        // A one-byte envelope substitution must refuse even with a plausible shape.
        val substituted = envelope.copyOf().also { it[100] = (it[100] + 1).toByte() }
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH,
            verdict(bytes = substituted)
        )
        // The same envelope under a different digest claim refuses too.
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH,
            verdict(fields(envelopeDigest = SealedExecutionGrantValidator.sha256(ByteArray(600))))
        )
    }

    @Test
    fun expiryAtTheExactBoundaryIsRefusedAndJustInsideItIsValid() {
        assertRefused(SealedExecutionGrantValidator.Verdict.Refused.EXPIRED, verdict(fields(expiresAtMs = now)))
        assertRefused(SealedExecutionGrantValidator.Verdict.Refused.EXPIRED, verdict(nowMs = expires + 1))
        assertTrue(verdict(fields(expiresAtMs = now + 1)) is SealedExecutionGrantValidator.Verdict.Valid)
        // The plausibility ceiling itself is acceptable; one millisecond past it is not.
        assertTrue(
            verdict(fields(expiresAtMs = now + SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS))
                is SealedExecutionGrantValidator.Verdict.Valid
        )
        assertRefused(
            SealedExecutionGrantValidator.Verdict.Refused.IMPLAUSIBLE_EXPIRY,
            verdict(fields(expiresAtMs = now + SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS + 1))
        )
    }

    @Test
    fun segmentCountMustBeOneToSix() {
        for (count in listOf(0, 7)) {
            assertRefused(
                SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_OUT_OF_RANGE,
                verdict(fields(segmentCount = count))
            )
        }
        assertTrue(verdict(fields(segmentCount = 6)) is SealedExecutionGrantValidator.Verdict.Valid)
    }

    @Test
    fun validGrantCarriesNoEnvelopeBytesAndRedactsItself() {
        val valid = verdict() as SealedExecutionGrantValidator.Verdict.Valid
        // The digest binds execution to these exact bytes without carrying them.
        assertTrue(java.security.MessageDigest.isEqual(valid.grant.envelopeDigest, digest))
        assertEquals("SealedExecutionGrant(redacted)", valid.grant.toString())
        assertEquals("SealedExecutionGrantFields(redacted)", fields().toString())
        assertEquals("SealedEnvelopeClaims(unauthenticated)", claims().toString())
    }

    @Test
    fun plaintextRulesAcceptStrictUtf8AndRefuseTheContractViolations() {
        assertTrue(SealedPlaintextRules.acceptBody("hello".toByteArray(Charsets.UTF_8)))
        assertFalse(SealedPlaintextRules.acceptBody(ByteArray(0)))
        assertTrue(SealedPlaintextRules.acceptBody(ByteArray(SealedPlaintextRules.MAX_BODY_BYTES) { 'a'.code.toByte() }))
        assertFalse(
            SealedPlaintextRules.acceptBody(ByteArray(SealedPlaintextRules.MAX_BODY_BYTES + 1) { 'a'.code.toByte() })
        )
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte(), 'h'.code.toByte())))
        // Overlong or invalid UTF-8 must refuse rather than replace.
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xC0.toByte(), 0xAF.toByte())))
        assertFalse(SealedPlaintextRules.acceptBody(byteArrayOf(0xFF.toByte())))
        // A NUL inside the body refuses.
        assertFalse(SealedPlaintextRules.acceptBody("a\u0000b".toByteArray(Charsets.UTF_8)))
    }
}
