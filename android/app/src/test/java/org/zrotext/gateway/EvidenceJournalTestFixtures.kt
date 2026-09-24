// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Synthetic identity shared by Room tests; production calls must supply a real session. */
internal val testEvidenceIdentity = EvidenceIdentity(
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "a".repeat(64)
)

internal fun SmsAttemptDao.reserveAlpha(
    attemptId: String, messageId: String, subscriptionId: Int,
    segmentCount: Int, intentEventId: String, now: Long,
    approvedSenderToken: String? = null
) = reserveAlpha(attemptId, messageId, subscriptionId, segmentCount, intentEventId,
    now, approvedSenderToken, testEvidenceIdentity)

internal fun SmsAttemptDao.nextAlphaEvent(): AlphaRadioEvent? =
    nextAlphaEvent(testEvidenceIdentity.accountId, testEvidenceIdentity.deviceId,
        testEvidenceIdentity.originHash)

internal fun SmsAttemptDao.nextInboundUpload(minimumObservedAtMs: Long): InboundUpload? =
    nextInboundUpload(minimumObservedAtMs, testEvidenceIdentity.accountId,
        testEvidenceIdentity.deviceId, testEvidenceIdentity.originHash)

internal fun SmsAttemptDao.signInboundUpload(eventId: String, accountId: String,
                                            deviceId: String, signature: ByteArray): Int =
    signInboundUpload(eventId, accountId, deviceId, testEvidenceIdentity.originHash, signature)
