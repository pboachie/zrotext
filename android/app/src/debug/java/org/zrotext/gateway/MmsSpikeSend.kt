// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.telephony.SmsManager
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * What the operator confirmed in the spike dialog. It is held in memory only
 * and expires after [MmsSpikeArm.ARM_WINDOW_MS]; the recipient and subject are
 * never written to preferences, the journal or a log.
 */
internal data class MmsSpikeArmed(
    val recipientE164: String,
    val confirmedRecipient: String,
    val subject: String,
    val subscriptionId: Int,
    val armedAtMs: Long
)

/** One armed request at a time; a server grant consumes it. */
internal object MmsSpikeArm {
    const val ARM_WINDOW_MS = 5 * 60_000L
    private var armed: MmsSpikeArmed? = null

    @Synchronized fun arm(value: MmsSpikeArmed) { armed = value }

    @Synchronized fun take(nowMs: Long): MmsSpikeArmed? {
        val value = armed
        armed = null
        return value?.takeIf { nowMs - it.armedAtMs in 0 until ARM_WINDOW_MS }
    }

    @Synchronized fun clear() { armed = null }
}

/**
 * Debug-build entry for the `mms_spike_grant` frame on the authenticated device
 * stream. An unarmed or invalid grant throws, which fails the session exactly
 * like an invalid `synthetic_grant`.
 */
internal object MmsSpikeGrants {
    fun onGrantFrame(context: Context, frame: JSONObject, deviceId: UUID, connectionEpoch: Long) {
        val now = System.currentTimeMillis()
        val armed = checkNotNull(MmsSpikeArm.take(now)) { "MMS spike is not armed" }
        val grant = MmsSpikeGrantValidator.validate(frame, deviceId, connectionEpoch,
            armed.confirmedRecipient, MmsSpikeSend.buildAllowlist(), now)
        MmsSpikeStatus.post("Server grant accepted; submitting once")
        MmsSpikeSend.sendAuthorized(context, armed, grant) { result ->
            MmsSpikeStatus.post("Spike: ${result.name}")
        }
    }
}

/**
 * Local radio boundary for the outbound MMS spike (issue #438, stage one). It
 * exists only in debug builds. A server grant, the build allowlist, the
 * operator's confirmation and the STOP suppression list must all pass before a
 * single durable one-use gate; then one radio call, no retry, and a throw after
 * the call stays unknown. The carrier's default MMSC is used via a null
 * location URL.
 */
internal object MmsSpikeSend {
    enum class StartResult { NOT_STARTED, JOURNAL_ERROR, RESERVED_NOT_SENT, CALL_RETURNED, UNKNOWN }

    @Volatile var lastRefusal: MmsSpikePolicy.Refusal? = null
        private set

    fun buildAllowlist(): Set<String> = MmsSpikePolicy.parseAllowlist(BuildConfig.MMS_SPIKE_ALLOWLIST)

    fun sendAuthorized(
        context: Context,
        armed: MmsSpikeArmed,
        grant: MmsSpikeGrant,
        finished: (StartResult) -> Unit
    ) {
        val app = context.applicationContext
        JournalRuntime.io.execute {
            val result = try {
                sendOnJournalThread(app, armed, grant)
            } catch (_: RuntimeException) {
                StartResult.UNKNOWN
            }
            finished(result)
        }
    }

    fun spikeDir(context: Context): File = File(context.filesDir, MmsSpikePdu.DIR)

    fun journalFile(context: Context): File = File(spikeDir(context), "journal.log")

    /**
     * [isSuppressed], [radio] and [contentUri] default to the production STOP
     * lookup, `SmsManager.sendMultimediaMessage` and the spike FileProvider;
     * JVM tests replace them.
     */
    internal fun sendOnJournalThread(
        context: Context,
        armed: MmsSpikeArmed,
        grant: MmsSpikeGrant?,
        allowlist: Set<String> = buildAllowlist(),
        isSuppressed: ((String) -> Boolean)? = null,
        radio: ((Uri, PendingIntent) -> Unit)? = null,
        contentUri: ((File) -> Uri)? = null
    ): StartResult {
        lastRefusal = null
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) !=
            PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) !=
            PackageManager.PERMISSION_GRANTED) return StartResult.NOT_STARTED
        if (!selectionMatches(context, armed.subscriptionId)) return StartResult.NOT_STARTED

        val suppressed = isSuppressed ?: { recipient -> isSuppressedLocally(context, recipient) }
        val gate = context.getSharedPreferences("mms_spike", Context.MODE_PRIVATE)
        val refusal = MmsSpikePolicy.preflight(BuildConfig.DEBUG, allowlist, armed.recipientE164,
            armed.confirmedRecipient, gate.getString("attempt_id", null) != null, grant,
            System.currentTimeMillis()) { suppressed(armed.recipientE164) }
        if (refusal != null || grant == null) {
            lastRefusal = refusal
            return StartResult.NOT_STARTED
        }

        val attemptId = UUID.randomUUID().toString()
        val transactionId = attemptId.replace("-", "").take(20)
        val request = MmsSpikeRequest(armed.recipientE164, armed.subject.trim(), transactionId,
            "zrotext-spike.png", SyntheticSpikeImage.png())
        if (MmsSendComposer.validationError(request) != null) return StartResult.NOT_STARTED
        val send = radio ?: platformRadio(context, armed.subscriptionId) ?: return StartResult.NOT_STARTED

        // The one-use spike gate is committed before any possible radio call, so
        // a crashed attempt can never be re-armed by relaunching the app.
        val journal = journalFile(context)
        try {
            MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                MmsSpikeJournal.COMPOSED, System.currentTimeMillis(), ""))
        } catch (_: Exception) {
            return StartResult.JOURNAL_ERROR
        }
        if (!gate.edit().putString("attempt_id", attemptId)
                .putString("grant_id", grant.grantId.toString()).commit()) return StartResult.JOURNAL_ERROR

        val dir = spikeDir(context)
        // The PDU holds the plaintext recipient and subject. It survives this
        // function only when the radio call returned and the platform may still
        // read it; the sent callback or the timeout then deletes it.
        var awaitingPlatform = false
        try {
            val pdu = MmsSendComposer.compose(request)
            if (!dir.exists() && !dir.mkdirs()) return StartResult.RESERVED_NOT_SENT
            val pduFile = MmsSpikePdu.file(dir, attemptId)
            try {
                FileOutputStream(pduFile).channel.use { channel ->
                    channel.write(ByteBuffer.wrap(pdu))
                    channel.force(true)
                }
            } catch (_: Exception) {
                return StartResult.RESERVED_NOT_SENT
            }
            if (!selectionMatches(context, armed.subscriptionId)) return StartResult.RESERVED_NOT_SENT
            val sent = try {
                PendingIntent.getBroadcast(
                    context, 0,
                    Intent(context, MmsSpikeReceiver::class.java).apply {
                        action = MmsSpikeReceiver.ACTION_SENT
                        data = Uri.Builder().scheme("zrotext").authority("mms-spike-callback")
                            .appendPath(attemptId).appendPath("sent").build()
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            } catch (_: RuntimeException) {
                return StartResult.RESERVED_NOT_SENT
            }
            val uri = try {
                contentUri?.invoke(pduFile)
                    ?: FileProvider.getUriForFile(context, context.packageName + ".mms-spike-files", pduFile)
            } catch (_: IllegalArgumentException) {
                return StartResult.RESERVED_NOT_SENT
            }

            // One call, no retry. A throw here may follow a partial radio action.
            synchronized(LocalSuppressionGate.lock) {
                val stillSuppressed = try { suppressed(armed.recipientE164) } catch (_: Exception) { true }
                if (stillSuppressed || System.currentTimeMillis() >= grant.expiresAtMs) {
                    return StartResult.RESERVED_NOT_SENT
                }
                try {
                    send(uri, sent)
                } catch (_: RuntimeException) {
                    appendQuietly(journal, MmsSpikeEvent(attemptId, transactionId,
                        MmsSpikeJournal.UNKNOWN_RESULT, System.currentTimeMillis(), "send_threw"))
                    return StartResult.UNKNOWN
                }
                awaitingPlatform = true
            }
            appendQuietly(journal, MmsSpikeEvent(attemptId, transactionId,
                MmsSpikeJournal.CALL_RETURNED, System.currentTimeMillis(), ""))
            scheduleTimeout(context, attemptId, transactionId)
            return StartResult.CALL_RETURNED
        } finally {
            if (!awaitingPlatform) MmsSpikePdu.delete(dir, attemptId)
        }
    }

    /** The one platform callback: journal the result, then delete the PDU. */
    internal fun recordSentCallback(context: Context, attemptId: String, ok: Boolean, resultCode: Int) {
        val journal = journalFile(context)
        try {
            // The transaction id is read from the journal; a callback cannot invent one.
            val recorded = try {
                MmsSpikeJournal.replay(journal)
            } catch (_: Exception) {
                emptyList()
            }
            val transactionId = recorded.firstOrNull { it.attemptId == attemptId }?.transactionId
            if (transactionId != null) {
                appendQuietly(journal, MmsSpikeEvent(attemptId, transactionId,
                    if (ok) MmsSpikeJournal.SENT_OK else MmsSpikeJournal.SENT_ERROR,
                    System.currentTimeMillis(), "result_$resultCode"))
            }
        } finally {
            MmsSpikePdu.delete(spikeDir(context), attemptId)
        }
    }

    /** No callback in time: record unknown (never resend) and delete the PDU. */
    internal fun onTimeout(context: Context, attemptId: String, transactionId: String) {
        val journal = journalFile(context)
        try {
            val events = try {
                MmsSpikeJournal.replay(journal).filter { it.attemptId == attemptId }
            } catch (_: Exception) {
                emptyList()
            }
            if (MmsSpikeJournal.attemptState(events) in setOf("pending", "submitting")) {
                appendQuietly(journal, MmsSpikeEvent(attemptId, transactionId,
                    MmsSpikeJournal.TIMEOUT_UNKNOWN, System.currentTimeMillis(), ""))
            }
        } finally {
            MmsSpikePdu.delete(spikeDir(context), attemptId)
        }
    }

    /** Removes any PDU a dead process left behind once its callback window has passed. */
    internal fun sweepOrphans(context: Context): Int {
        val events = try {
            MmsSpikeJournal.replay(journalFile(context))
        } catch (_: Exception) {
            emptyList()
        }
        return MmsSpikePdu.sweep(spikeDir(context), events, System.currentTimeMillis(),
            TimeUnit.MINUTES.toMillis(SENT_CALLBACK_TIMEOUT_MINUTES))
    }

    private fun scheduleTimeout(context: Context, attemptId: String, transactionId: String) {
        JournalRuntime.timeouts.schedule({
            JournalRuntime.io.execute { onTimeout(context, attemptId, transactionId) }
        }, SENT_CALLBACK_TIMEOUT_MINUTES, TimeUnit.MINUTES)
    }

    private fun selectionMatches(context: Context, subscriptionId: Int): Boolean =
        context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .getInt("subscription_id", -1) == subscriptionId

    /** The same keyed STOP lookup as the SMS adapter; the token is only held in memory. */
    private fun isSuppressedLocally(context: Context, recipientE164: String): Boolean {
        val senderToken = InboundVault.token("sender-v1", recipientE164.toByteArray(Charsets.US_ASCII))
        return SmsJournalDatabase.get(context).attempts().isRecipientSuppressed(senderToken)
    }

    private fun platformRadio(context: Context, subscriptionId: Int): ((Uri, PendingIntent) -> Unit)? {
        val manager = try {
            if (Build.VERSION.SDK_INT >= 31) context.getSystemService(SmsManager::class.java)
                .createForSubscriptionId(subscriptionId)
            else SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        } catch (_: RuntimeException) {
            return null
        }
        return { uri, sent -> manager.sendMultimediaMessage(context, uri, null, null, sent) }
    }

    private fun appendQuietly(journal: File, event: MmsSpikeEvent) {
        try {
            MmsSpikeJournal.append(journal, event)
        } catch (_: Exception) {
        }
    }

    private const val SENT_CALLBACK_TIMEOUT_MINUTES = 5L
}

/** Records the one platform send callback for the spike attempt. Debug builds only. */
class MmsSpikeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_SENT) return
        val uri = intent.data ?: return
        if (uri.scheme != "zrotext" || uri.authority != "mms-spike-callback" ||
            uri.pathSegments.size != 2 || uri.pathSegments[1] != "sent") return
        val attemptId = uri.pathSegments[0]
        if (!attemptId.matches(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) return
        val code = resultCode
        val ok = code == android.app.Activity.RESULT_OK
        val pending = goAsync()
        val app = context.applicationContext
        JournalRuntime.io.execute {
            try {
                MmsSpikeSend.recordSentCallback(app, attemptId, ok, code)
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_SENT = "org.zrotext.gateway.MMS_SPIKE_SENT"
    }
}
