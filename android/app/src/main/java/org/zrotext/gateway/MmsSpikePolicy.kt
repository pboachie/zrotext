// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/**
 * A server-issued permission for the one MMS spike attempt. It is bound to the
 * authenticated device stream, the exact recipient the operator confirmed,
 * and a short expiry, like the SMS [AlphaGrantValidator.Grant].
 */
internal data class MmsSpikeGrant(
    val grantId: UUID,
    val deviceId: UUID,
    val connectionEpoch: Long,
    val recipientE164: String,
    val expiresAtMs: Long
)

/**
 * Validates an `mms_spike_grant` frame. The frame mirrors `synthetic_grant`:
 * exact field set, authenticated device and connection epoch, an expiry no more
 * than 35 seconds ahead, and a recipient digest bound to the recipient that the
 * operator confirmed and that the build allowlist contains.
 */
internal object MmsSpikeGrantValidator {
    const val FRAME_TYPE = "mms_spike_grant"

    fun validate(
        frame: JSONObject,
        authenticatedDeviceId: UUID,
        authenticatedEpoch: Long,
        confirmedRecipient: String,
        allowlist: Set<String>,
        nowMs: Long
    ): MmsSpikeGrant {
        check(frame.keys().asSequence().toSet() == setOf(
            "v", "type", "grant_id", "device_id", "connection_epoch", "recipient_digest",
            "expires_at_ms", "recipient_e164"
        ))
        check(integer(frame, "v") == 1L)
        check(frame.getString("type") == FRAME_TYPE)
        val grantId = uuid(frame, "grant_id")
        val deviceId = uuid(frame, "device_id")
        check(grantId != ZERO_UUID && deviceId == authenticatedDeviceId)
        val connectionEpoch = integer(frame, "connection_epoch")
        check(connectionEpoch == authenticatedEpoch)
        val expiresAtMs = integer(frame, "expires_at_ms")
        check(expiresAtMs > nowMs && expiresAtMs - nowMs <= MAX_GRANT_FUTURE_MS)
        val recipient = frame.getString("recipient_e164")
        check(recipient.matches(MmsSpikePolicy.E164) && recipient == confirmedRecipient)
        check(recipient in allowlist)
        check(frame.getString("recipient_digest") == recipientDigest(recipient))
        return MmsSpikeGrant(grantId, deviceId, connectionEpoch, recipient, expiresAtMs)
    }

    /** Wire binding only, as in `synthetic_grant`; it is never stored on the phone. */
    fun recipientDigest(recipient: String): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(recipient.toByteArray(Charsets.UTF_8)))

    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = frame.getString(key)
        check(value.length == 36)
        return UUID.fromString(value).also { check(it.toString() == value) }
    }

    private fun integer(frame: JSONObject, key: String): Long {
        val value = frame.opt(key)
        check(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private const val MAX_GRANT_FUTURE_MS = 35_000L
    private val ZERO_UUID = UUID(0, 0)
}

/** Pure preflight for the spike. Every check must pass before the one-use gate is spent. */
internal object MmsSpikePolicy {
    enum class Refusal {
        NOT_DEBUG_BUILD, INVALID_RECIPIENT, NOT_ALLOWLISTED, NOT_CONFIRMED, ATTEMPT_USED,
        NO_GRANT, GRANT_EXPIRED, GRANT_RECIPIENT_MISMATCH, SUPPRESSED
    }

    val E164 = Regex("^\\+[1-9][0-9]{1,14}$")

    /**
     * Parses the build-time allowlist (comma-separated +E.164). Any malformed
     * entry empties the whole list, so a typo refuses every recipient.
     */
    fun parseAllowlist(raw: String): Set<String> {
        val entries = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (entries.any { !it.matches(E164) }) return emptySet()
        return entries.toSet()
    }

    /**
     * Returns the first refusal, or null when the attempt may spend its one-use
     * gate. The suppression lookup runs last and a throw counts as suppressed.
     */
    fun preflight(
        debugBuild: Boolean,
        allowlist: Set<String>,
        recipient: String,
        confirmedRecipient: String?,
        attemptUsed: Boolean,
        grant: MmsSpikeGrant?,
        nowMs: Long,
        isSuppressed: () -> Boolean
    ): Refusal? = when {
        !debugBuild -> Refusal.NOT_DEBUG_BUILD
        !recipient.matches(E164) -> Refusal.INVALID_RECIPIENT
        recipient !in allowlist -> Refusal.NOT_ALLOWLISTED
        confirmedRecipient != recipient -> Refusal.NOT_CONFIRMED
        attemptUsed -> Refusal.ATTEMPT_USED
        grant == null -> Refusal.NO_GRANT
        nowMs >= grant.expiresAtMs -> Refusal.GRANT_EXPIRED
        grant.recipientE164 != recipient -> Refusal.GRANT_RECIPIENT_MISMATCH
        (try { isSuppressed() } catch (_: Exception) { true }) -> Refusal.SUPPRESSED
        else -> null
    }
}

/**
 * The composed PDU carries the plaintext recipient and subject, so it lives
 * only while the platform may still read it. It is deleted on the sent
 * callback, the timeout, a throw, and every pre-radio exit; [sweep] removes
 * any file a dead process left behind.
 */
internal object MmsSpikePdu {
    const val DIR = "mms_spike"
    private val NAME = Regex("^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\.pdu$")

    fun file(dir: File, attemptId: String): File = File(dir, "$attemptId.pdu")

    /** Returns true when no PDU file remains for the attempt. */
    fun delete(dir: File, attemptId: String): Boolean {
        val file = file(dir, attemptId)
        return !file.exists() || file.delete() || !file.exists()
    }

    /**
     * Deletes every PDU except one whose attempt is still awaiting its platform
     * callback inside [windowMs]. Returns the number of files that remain.
     */
    fun sweep(dir: File, events: List<MmsSpikeEvent>, nowMs: Long, windowMs: Long): Int {
        val files = dir.listFiles { file -> file.name.endsWith(".pdu") } ?: return 0
        var remaining = 0
        for (file in files) {
            val attemptId = NAME.matchEntire(file.name)?.groupValues?.get(1)
            val state = attemptId?.let { id -> MmsSpikeJournal.attemptState(events.filter { it.attemptId == id }) }
            val inFlight = state in setOf("pending", "submitting") &&
                nowMs - file.lastModified() in 0 until windowMs
            if (inFlight || (!file.delete() && file.exists())) remaining++
        }
        return remaining
    }
}
