// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/**
 * Binding rules for a sealed execution grant (roadmap #539). A grant
 * authorizes exactly one decrypt-and-submit of exactly one sealed envelope
 * on exactly one device session: identity bindings, session epoch, envelope
 * digest and bounded expiry must all hold before any HPKE open, so a stale,
 * substituted or ambiguous grant never yields plaintext.
 *
 * Expected refusals are [Verdict.Refused] values for the refusal table;
 * structural malformation of the frame still throws, because the caller
 * treats that as a protocol rejection of the whole frame. The table also
 * names the refusals [SealedDispatchExecutor] adds around this check
 * (malformed envelope, more segments than the grant authorizes).
 */
internal object SealedExecutionGrantValidator {

    data class Grant(
        val accountId: UUID,
        val deviceId: UUID,
        val lineId: UUID,
        val messageId: UUID,
        val attemptId: UUID,
        val connectionEpoch: Long,
        val envelopeDigest: ByteArray,
        val expiresAtMs: Long,
        val segmentCount: Int,
    ) {
        override fun toString() = "SealedExecutionGrant(redacted)"
        override fun equals(other: Any?) = this === other
        override fun hashCode() = System.identityHashCode(this)
    }

    sealed interface Verdict {
        data class Valid(val grant: Grant) : Verdict

        /** Every value is a distinct, testable refusal reason; none decrypts. */
        enum class Refused : Verdict {
            ACCOUNT_MISMATCH,
            DEVICE_MISMATCH,
            LINE_MISMATCH,
            MESSAGE_MISMATCH,
            MESSAGE_OR_ATTEMPT_MISMATCH,
            READER_ROLE_MISMATCH,
            READER_KEY_MISMATCH,
            SESSION_MISMATCH,
            DEPLOYMENT_MISMATCH,
            BINDING_GENERATION_MISMATCH,
            ENVELOPE_MALFORMED,
            ENVELOPE_DIGEST_MISMATCH,
            EXPIRED,
            IMPLAUSIBLE_EXPIRY,
            SEGMENT_COUNT_OUT_OF_RANGE,
            SEGMENT_COUNT_EXCEEDS_GRANT,
        }
    }

    /**
     * The routing identity the envelope itself claims. These claims are read
     * structurally before the signature is checked, so they only narrow what a
     * grant may name: the later envelope verification still authenticates them.
     */
    class EnvelopeClaims(
        val accountId: UUID,
        val messageId: UUID,
        val deviceId: UUID,
        val lineId: UUID,
        deviceReaderKeyId: ByteArray,
    ) {
        private val readerKey = deviceReaderKeyId.copyOf()
        val deviceReaderKeyId: ByteArray get() = readerKey.copyOf()
        override fun toString() = "SealedEnvelopeClaims(unauthenticated)"
    }

    /**
     * @param grantFields the grant exactly as framed by the hub.
     * @param envelopeBytes the exact envelope bytes the dispatch delivered;
     *   the grant is compared against their SHA-256, binding the grant to
     *   those bytes and no others.
     * @param claims the routing identity the same envelope bytes claim.
     * @param pinnedReaderKeyId the key ID of this device's own Keystore payload
     *   key; the grant must name it as the device-payload reader (role 1).
     */
    fun validate(
        grantFields: Fields,
        envelopeBytes: ByteArray,
        claims: EnvelopeClaims,
        authenticatedAccountId: UUID,
        authenticatedDeviceId: UUID,
        activeLineId: UUID,
        sessionEpoch: Long,
        sessionDeploymentEpoch: Long,
        activeBindingGeneration: Long,
        pinnedReaderKeyId: ByteArray,
        nowMs: Long,
    ): Verdict {
        if (grantFields.accountId != authenticatedAccountId || claims.accountId != grantFields.accountId) {
            return Verdict.Refused.ACCOUNT_MISMATCH
        }
        if (grantFields.deviceId != authenticatedDeviceId || claims.deviceId != grantFields.deviceId) {
            return Verdict.Refused.DEVICE_MISMATCH
        }
        if (grantFields.lineId != activeLineId || claims.lineId != grantFields.lineId) {
            return Verdict.Refused.LINE_MISMATCH
        }
        if (grantFields.messageId == ZERO_UUID || grantFields.attemptId == ZERO_UUID) {
            return Verdict.Refused.MESSAGE_OR_ATTEMPT_MISMATCH
        }
        if (claims.messageId != grantFields.messageId) return Verdict.Refused.MESSAGE_MISMATCH
        if (grantFields.readerRole != DEVICE_PAYLOAD_READER_ROLE) return Verdict.Refused.READER_ROLE_MISMATCH
        if (!MessageDigest.isEqual(grantFields.readerKeyId, pinnedReaderKeyId) ||
            !MessageDigest.isEqual(claims.deviceReaderKeyId, grantFields.readerKeyId)
        ) return Verdict.Refused.READER_KEY_MISMATCH
        if (grantFields.connectionEpoch != sessionEpoch) return Verdict.Refused.SESSION_MISMATCH
        if (grantFields.deploymentEpoch != sessionDeploymentEpoch) return Verdict.Refused.DEPLOYMENT_MISMATCH
        if (grantFields.bindingGeneration != activeBindingGeneration) {
            return Verdict.Refused.BINDING_GENERATION_MISMATCH
        }
        if (!MessageDigest.isEqual(
                grantFields.envelopeDigest,
                sha256(envelopeBytes)
            )
        ) return Verdict.Refused.ENVELOPE_DIGEST_MISMATCH
        if (nowMs >= grantFields.expiresAtMs) return Verdict.Refused.EXPIRED
        if (grantFields.expiresAtMs - nowMs > MAX_GRANT_FUTURE_MS) {
            return Verdict.Refused.IMPLAUSIBLE_EXPIRY
        }
        if (grantFields.segmentCount !in 1..MAX_SEGMENTS) {
            return Verdict.Refused.SEGMENT_COUNT_OUT_OF_RANGE
        }
        return Verdict.Valid(
            Grant(
                grantFields.accountId,
                grantFields.deviceId,
                grantFields.lineId,
                grantFields.messageId,
                grantFields.attemptId,
                grantFields.connectionEpoch,
                grantFields.envelopeDigest.copyOf(),
                grantFields.expiresAtMs,
                grantFields.segmentCount,
            )
        )
    }

    /** The grant as framed by the hub, already structurally checked by the frame parser. */
    data class Fields(
        val accountId: UUID,
        val deviceId: UUID,
        val lineId: UUID,
        val messageId: UUID,
        val attemptId: UUID,
        val connectionEpoch: Long,
        val envelopeDigest: ByteArray,
        val expiresAtMs: Long,
        val segmentCount: Int,
        val readerRole: Int,
        val readerKeyId: ByteArray,
        val deploymentEpoch: Long,
        val bindingGeneration: Long,
        val attemptGeneration: Long,
        val unsignedDigest: ByteArray,
    ) {
        override fun toString() = "SealedExecutionGrantFields(redacted)"
    }

    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    /** Matches the alpha grant bound: a grant may never reach far past "now". */
    const val MAX_GRANT_FUTURE_MS = 35_000L
    const val MAX_SEGMENTS = 6

    /** Profile-02 wrap role 01: the one selected device's payload key. */
    const val DEVICE_PAYLOAD_READER_ROLE = 1
    private val ZERO_UUID = UUID(0, 0)
}
