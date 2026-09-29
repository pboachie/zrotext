// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.UUID

// Robolectric supplies the real org.json implementation used by the grant frame.
@RunWith(RobolectricTestRunner::class)
class MmsSpikePolicyTest {
    @get:Rule val folder = TemporaryFolder()

    private val recipient = "+15555550123"
    private val other = "+15555550124"
    private val device = UUID.fromString("00000000-0000-4000-8000-000000000001")
    private val grantId = UUID.fromString("00000000-0000-4000-8000-000000000002")
    private val now = 1_700_000_000_000L
    private val allowlist = setOf(recipient)

    private fun frame(recipientE164: String = recipient) = JSONObject()
        .put("v", 1).put("type", "mms_spike_grant")
        .put("grant_id", grantId.toString()).put("device_id", device.toString())
        .put("connection_epoch", 8).put("expires_at_ms", now + 30_000)
        .put("recipient_digest", MmsSpikeGrantValidator.recipientDigest(recipientE164))
        .put("recipient_e164", recipientE164)

    private fun rejects(frame: JSONObject, confirmed: String = recipient, list: Set<String> = allowlist,
        deviceId: UUID = device, epoch: Long = 8) {
        try {
            MmsSpikeGrantValidator.validate(frame, deviceId, epoch, confirmed, list, now)
            fail("grant should be rejected: $frame")
        } catch (_: RuntimeException) {
        }
    }

    private fun grant(expiresAtMs: Long = now + 30_000, to: String = recipient) =
        MmsSpikeGrant(grantId, device, 8, to, expiresAtMs)

    private fun preflight(
        debugBuild: Boolean = true,
        list: Set<String> = allowlist,
        confirmed: String? = recipient,
        attemptUsed: Boolean = false,
        grant: MmsSpikeGrant? = grant(),
        suppressed: () -> Boolean = { false }
    ) = MmsSpikePolicy.preflight(debugBuild, list, recipient, confirmed, attemptUsed, grant, now, suppressed)

    @Test fun validServerGrantIsBoundToDeviceEpochAndConfirmedRecipient() {
        val grant = MmsSpikeGrantValidator.validate(frame(), device, 8, recipient, allowlist, now)
        assertEquals(grantId, grant.grantId)
        assertEquals(recipient, grant.recipientE164)
        assertEquals(now + 30_000, grant.expiresAtMs)
    }

    @Test fun serverGrantIsRejectedForAnyMismatch() {
        rejects(frame(), deviceId = UUID.fromString("00000000-0000-4000-8000-000000000009"))
        rejects(frame(), epoch = 9)
        rejects(frame(), confirmed = other)
        rejects(frame(), list = emptySet())
        rejects(frame(other), confirmed = other)
        rejects(frame().put("recipient_digest", MmsSpikeGrantValidator.recipientDigest(other)))
        rejects(frame().put("expires_at_ms", now))
        rejects(frame().put("expires_at_ms", now + 36_000))
        rejects(frame().put("type", "synthetic_grant"))
        rejects(frame().put("grant_id", "00000000-0000-0000-0000-000000000000"))
        rejects(frame().put("body", "extra field"))
        rejects(frame().put("v", 2))
    }

    @Test fun preflightPassesOnlyWithEveryGate() {
        assertNull(preflight())
    }

    @Test fun releaseBuildsAreRefused() {
        assertEquals(MmsSpikePolicy.Refusal.NOT_DEBUG_BUILD, preflight(debugBuild = false))
    }

    @Test fun recipientsOutsideTheAllowlistAreRefused() {
        assertEquals(MmsSpikePolicy.Refusal.NOT_ALLOWLISTED, preflight(list = emptySet()))
        assertEquals(MmsSpikePolicy.Refusal.NOT_ALLOWLISTED, preflight(list = setOf(other)))
    }

    @Test fun anUnconfirmedOrDifferentlyConfirmedRecipientIsRefused() {
        assertEquals(MmsSpikePolicy.Refusal.NOT_CONFIRMED, preflight(confirmed = null))
        assertEquals(MmsSpikePolicy.Refusal.NOT_CONFIRMED, preflight(confirmed = other))
    }

    @Test fun aSecondAttemptIsRefused() {
        assertEquals(MmsSpikePolicy.Refusal.ATTEMPT_USED, preflight(attemptUsed = true))
    }

    @Test fun noSendWithoutAValidUnexpiredServerGrantForTheRecipient() {
        assertEquals(MmsSpikePolicy.Refusal.NO_GRANT, preflight(grant = null))
        assertEquals(MmsSpikePolicy.Refusal.GRANT_EXPIRED, preflight(grant = grant(expiresAtMs = now)))
        assertEquals(MmsSpikePolicy.Refusal.GRANT_RECIPIENT_MISMATCH, preflight(grant = grant(to = other)))
    }

    @Test fun suppressedRecipientsAreRefusedAndALookupFailureFailsClosed() {
        assertEquals(MmsSpikePolicy.Refusal.SUPPRESSED, preflight(suppressed = { true }))
        assertEquals(MmsSpikePolicy.Refusal.SUPPRESSED,
            preflight(suppressed = { throw IllegalStateException("store unavailable") }))
    }

    @Test fun allowlistParsingFailsClosedOnAnyMalformedEntry() {
        assertEquals(setOf(recipient, other), MmsSpikePolicy.parseAllowlist("$recipient, $other"))
        assertEquals(emptySet<String>(), MmsSpikePolicy.parseAllowlist(""))
        assertEquals(emptySet<String>(), MmsSpikePolicy.parseAllowlist("$recipient,15555550124"))
        assertEquals(emptySet<String>(), MmsSpikePolicy.parseAllowlist("+0555,$recipient"))
    }

    @Test fun pduDeleteRemovesTheFile() {
        val dir = folder.newFolder("mms_spike")
        val attempt = "0f0a0b0c-1111-2222-3333-444455556666"
        MmsSpikePdu.file(dir, attempt).writeBytes(byteArrayOf(1, 2, 3))
        assertTrue(MmsSpikePdu.delete(dir, attempt))
        assertFalse(MmsSpikePdu.file(dir, attempt).exists())
        assertTrue(MmsSpikePdu.delete(dir, attempt))
    }

    @Test fun sweepKeepsOnlyAnInFlightAttemptInsideItsWindow() {
        val dir = folder.newFolder("mms_spike")
        val inFlight = "0f0a0b0c-1111-2222-3333-444455556666"
        val finished = "0f0a0b0c-1111-2222-3333-444455557777"
        val stale = "0f0a0b0c-1111-2222-3333-444455558888"
        val unjournaled = "0f0a0b0c-1111-2222-3333-444455559999"
        val clock = System.currentTimeMillis()
        listOf(inFlight, finished, stale, unjournaled).forEach {
            MmsSpikePdu.file(dir, it).apply { writeBytes(byteArrayOf(1)); setLastModified(clock) }
        }
        MmsSpikePdu.file(dir, stale).setLastModified(clock - 6 * 60_000)
        java.io.File(dir, "not-an-attempt.pdu").writeBytes(byteArrayOf(1))
        fun ev(id: String, kind: String) = MmsSpikeEvent(id, "txn1", kind, 1L, "")
        val events = listOf(
            ev(inFlight, MmsSpikeJournal.COMPOSED), ev(inFlight, MmsSpikeJournal.CALL_RETURNED),
            ev(finished, MmsSpikeJournal.COMPOSED), ev(finished, MmsSpikeJournal.SENT_OK),
            ev(stale, MmsSpikeJournal.COMPOSED), ev(stale, MmsSpikeJournal.CALL_RETURNED))
        assertEquals(1, MmsSpikePdu.sweep(dir, events, clock + 1_000, 5 * 60_000))
        assertEquals(listOf("$inFlight.pdu"), dir.list()!!.toList())
    }
}
