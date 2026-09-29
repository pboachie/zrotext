// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.net.Uri
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** JVM tests for the debug-only MMS spike radio boundary. No radio is ever called. */
@RunWith(RobolectricTestRunner::class)
class MmsSpikeSendTest {
    private lateinit var app: Application
    private val recipient = "+15555550123"
    private val subject = "Synthetic spike subject"
    private val allowlist = setOf(recipient)
    private val device = UUID.fromString("00000000-0000-4000-8000-000000000001")

    @Before fun setUp() {
        app = RuntimeEnvironment.getApplication()
        shadowOf(app).grantPermissions(Manifest.permission.SEND_SMS, Manifest.permission.READ_PHONE_STATE)
        app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit()
            .putInt("subscription_id", 4).commit()
        MmsSpikeArm.clear()
    }

    private fun armed(confirmed: String? = recipient) =
        MmsSpikeArmed(recipient, confirmed ?: "", subject, 4, System.currentTimeMillis())

    private fun grant() = MmsSpikeGrant(UUID.randomUUID(), device, 8, recipient,
        System.currentTimeMillis() + 30_000)

    private fun pdus(): List<File> =
        MmsSpikeSend.spikeDir(app).listFiles { f -> f.name.endsWith(".pdu") }.orEmpty().toList()

    private fun attemptId(): String = MmsSpikeJournal.replay(MmsSpikeSend.journalFile(app)).first().attemptId

    private fun send(
        grant: MmsSpikeGrant? = grant(),
        armed: MmsSpikeArmed = armed(),
        suppressed: (String) -> Boolean = { false },
        radio: (Uri, PendingIntent) -> Unit
    ) = MmsSpikeSend.sendOnJournalThread(app, armed, grant, allowlist, suppressed, radio, ::testUri)

    // Robolectric on a Windows host cannot resolve FileProvider roots (it joins with
    // a forward slash), so tests hand the radio a plain file URI instead.
    private fun testUri(file: File): Uri = Uri.fromFile(file)

    /** Nothing under the app's data directory may hold the recipient, its SHA-256 or the subject. */
    private fun assertNoPlaintextPersisted() {
        val sha = MessageDigest.getInstance("SHA-256").digest(recipient.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it) }
        val needles = listOf(recipient, recipient.removePrefix("+"), sha, subject)
        val root = app.filesDir.parentFile!!
        root.walkTopDown().filter { it.isFile }.forEach { file ->
            val text = String(file.readBytes(), Charsets.ISO_8859_1)
            needles.forEach { assertFalse("${file.name} holds '$it'", text.contains(it)) }
        }
        for (prefs in listOf("mms_spike", "gateway_selection")) {
            app.getSharedPreferences(prefs, Context.MODE_PRIVATE).all.values.forEach { value ->
                needles.forEach { assertFalse("$prefs holds '$it'", value.toString().contains(it)) }
            }
        }
    }

    @Test fun aThrowingRadioCallLeavesNoPduAndStaysUnknown() {
        var calls = 0
        val result = send { _, _ -> calls++; throw IllegalStateException("radio threw") }
        assertEquals(MmsSpikeSend.StartResult.UNKNOWN, result)
        assertEquals(1, calls)
        assertEquals(emptyList<File>(), pdus())
        assertEquals("unknown", MmsSpikeJournal.attemptState(MmsSpikeJournal.replay(MmsSpikeSend.journalFile(app))))
        assertNoPlaintextPersisted()
    }

    @Test fun thePduLivesOnlyUntilTheSentCallback() {
        var seen: Uri? = null
        val result = send { uri, _ -> seen = uri }
        assertEquals(MmsSpikeSend.StartResult.CALL_RETURNED, result)
        assertEquals("the platform still needs the PDU after the call returns", 1, pdus().size)
        assertTrue(seen.toString().endsWith(".pdu"))
        MmsSpikeSend.recordSentCallback(app, attemptId(), true, -1)
        assertEquals(emptyList<File>(), pdus())
        assertEquals("submitted",
            MmsSpikeJournal.attemptState(MmsSpikeJournal.replay(MmsSpikeSend.journalFile(app))))
        assertNoPlaintextPersisted()
    }

    @Test fun theTimeoutDeletesThePduAndRecordsUnknown() {
        assertEquals(MmsSpikeSend.StartResult.CALL_RETURNED, send { _, _ -> })
        val events = MmsSpikeJournal.replay(MmsSpikeSend.journalFile(app))
        MmsSpikeSend.onTimeout(app, events.first().attemptId, events.first().transactionId)
        assertEquals(emptyList<File>(), pdus())
        assertEquals("unknown",
            MmsSpikeJournal.attemptState(MmsSpikeJournal.replay(MmsSpikeSend.journalFile(app))))
        assertNoPlaintextPersisted()
    }

    @Test fun anOrphanPduFromADeadProcessIsSweptAfterItsWindow() {
        assertEquals(MmsSpikeSend.StartResult.CALL_RETURNED, send { _, _ -> })
        assertEquals(1, MmsSpikeSend.sweepOrphans(app))
        pdus().single().setLastModified(System.currentTimeMillis() - 6 * 60_000)
        assertEquals(0, MmsSpikeSend.sweepOrphans(app))
        assertEquals(emptyList<File>(), pdus())
    }

    @Test fun aSuppressedRecipientNeverReachesTheRadioOrSpendsTheGate() {
        var calls = 0
        val result = send(suppressed = { true }) { _, _ -> calls++ }
        assertEquals(MmsSpikeSend.StartResult.NOT_STARTED, result)
        assertEquals(MmsSpikePolicy.Refusal.SUPPRESSED, MmsSpikeSend.lastRefusal)
        assertEquals(0, calls)
        assertNull(app.getSharedPreferences("mms_spike", Context.MODE_PRIVATE).getString("attempt_id", null))
        assertEquals(emptyList<File>(), pdus())
    }

    @Test fun aStopArrivingAfterTheGateIsHonouredAtTheRadioBoundary() {
        var lookups = 0
        var calls = 0
        val result = send(suppressed = { lookups++ > 0 }) { _, _ -> calls++ }
        assertEquals(MmsSpikeSend.StartResult.RESERVED_NOT_SENT, result)
        assertEquals(0, calls)
        assertEquals(emptyList<File>(), pdus())
        assertNoPlaintextPersisted()
    }

    @Test fun noServerGrantMeansNoRadioCall() {
        var calls = 0
        assertEquals(MmsSpikeSend.StartResult.NOT_STARTED, send(grant = null) { _, _ -> calls++ })
        assertEquals(MmsSpikePolicy.Refusal.NO_GRANT, MmsSpikeSend.lastRefusal)
        assertEquals(0, calls)
    }

    @Test fun anUnconfirmedRecipientMeansNoRadioCall() {
        var calls = 0
        assertEquals(MmsSpikeSend.StartResult.NOT_STARTED,
            send(armed = armed(confirmed = "+15555550199")) { _, _ -> calls++ })
        assertEquals(MmsSpikePolicy.Refusal.NOT_CONFIRMED, MmsSpikeSend.lastRefusal)
        assertEquals(0, calls)
    }

    @Test fun aRecipientOutsideTheAllowlistMeansNoRadioCall() {
        var calls = 0
        val result = MmsSpikeSend.sendOnJournalThread(app, armed(), grant(), emptySet(), { false },
            { _, _ -> calls++ }, ::testUri)
        assertEquals(MmsSpikeSend.StartResult.NOT_STARTED, result)
        assertEquals(MmsSpikePolicy.Refusal.NOT_ALLOWLISTED, MmsSpikeSend.lastRefusal)
        assertEquals(0, calls)
    }

    @Test fun onlyOneAttemptPerInstallation() {
        var calls = 0
        send { _, _ -> calls++ }
        assertEquals(MmsSpikeSend.StartResult.NOT_STARTED, send { _, _ -> calls++ })
        assertEquals(MmsSpikePolicy.Refusal.ATTEMPT_USED, MmsSpikeSend.lastRefusal)
        assertEquals(1, calls)
    }

    @Test fun aGrantFrameWithoutAConfirmedArmIsRejected() {
        val frame = JSONObject().put("v", 1).put("type", "mms_spike_grant")
        try {
            MmsSpikeGrants.onGrantFrame(app, frame, device, 8)
            fail("an unarmed grant must be rejected")
        } catch (_: IllegalStateException) {
        }
    }

    @Test fun anArmExpiresAndIsConsumedOnce() {
        val now = System.currentTimeMillis()
        MmsSpikeArm.arm(armed().copy(armedAtMs = now))
        assertEquals(recipient, MmsSpikeArm.take(now + 1_000)?.recipientE164)
        assertNull(MmsSpikeArm.take(now + 1_000))
        MmsSpikeArm.arm(armed().copy(armedAtMs = now))
        assertNull(MmsSpikeArm.take(now + MmsSpikeArm.ARM_WINDOW_MS))
    }
}
