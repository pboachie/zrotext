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
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Local radio boundary for the outbound MMS spike (issue #438, stage one).
 * Like the SMS adapter, a single durable one-use gate precedes one radio call,
 * there is no retry, and a throw after the call stays unknown. The carrier's
 * default MMSC is used by passing a null location URL.
 */
internal object MmsSpikeSend {
    enum class StartResult { NOT_STARTED, JOURNAL_ERROR, RESERVED_NOT_SENT, CALL_RETURNED, UNKNOWN }

    fun sendAuthorized(
        context: Context,
        recipientE164: String,
        subject: String,
        subscriptionId: Int,
        finished: (StartResult) -> Unit
    ) {
        val app = context.applicationContext
        JournalRuntime.io.execute {
            val result = try {
                sendOnJournalThread(app, recipientE164, subject, subscriptionId)
            } catch (_: RuntimeException) {
                StartResult.UNKNOWN
            }
            finished(result)
        }
    }

    fun journalFile(context: Context): File = File(context.filesDir, "mms_spike/journal.log")

    private fun sendOnJournalThread(
        context: Context, recipientE164: String, subject: String, subscriptionId: Int
    ): StartResult {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) !=
            PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) !=
            PackageManager.PERMISSION_GRANTED) return StartResult.NOT_STARTED
        if (context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", -1) != subscriptionId) return StartResult.NOT_STARTED

        val attemptId = UUID.randomUUID().toString()
        val transactionId = attemptId.replace("-", "").take(20)
        val request = MmsSpikeRequest(recipientE164, subject.trim(), transactionId,
            "zrotext-spike.png", SyntheticSpikeImage.png())
        if (MmsSendComposer.validationError(request) != null) return StartResult.NOT_STARTED
        val manager = try {
            if (Build.VERSION.SDK_INT >= 31) context.getSystemService(SmsManager::class.java)
                .createForSubscriptionId(subscriptionId)
            else @Suppress("DEPRECATION") SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        } catch (_: RuntimeException) {
            return StartResult.NOT_STARTED
        }

        // The one-use spike gate is committed before any possible radio call, so
        // a crashed attempt can never be re-armed by relaunching the app.
        val gate = context.getSharedPreferences("mms_spike", Context.MODE_PRIVATE)
        if (gate.getString("attempt_id", null) != null) return StartResult.NOT_STARTED
        val journal = journalFile(context)
        try {
            MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                MmsSpikeJournal.COMPOSED, System.currentTimeMillis(), recipientToken(recipientE164)))
        } catch (_: Exception) {
            return StartResult.JOURNAL_ERROR
        }
        if (!gate.edit().putString("attempt_id", attemptId).commit()) return StartResult.JOURNAL_ERROR

        val pdu = MmsSendComposer.compose(request)
        val dir = File(context.filesDir, "mms_spike")
        if (!dir.exists() && !dir.mkdirs()) return StartResult.RESERVED_NOT_SENT
        val pduFile = File(dir, "$attemptId.pdu")
        try {
            FileOutputStream(pduFile).channel.use { channel ->
                channel.write(ByteBuffer.wrap(pdu))
                channel.force(true)
            }
        } catch (_: Exception) {
            return StartResult.RESERVED_NOT_SENT
        }
        if (context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", -1) != subscriptionId) {
            return StartResult.RESERVED_NOT_SENT
        }

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
            return StartResult.NOT_STARTED
        }
        val contentUri = try {
            FileProvider.getUriForFile(context, context.packageName + ".mms-spike-files", pduFile)
        } catch (_: IllegalArgumentException) {
            return StartResult.RESERVED_NOT_SENT
        }

        // One call, no retry. A throw here may follow a partial radio action.
        return try {
            manager.sendMultimediaMessage(context, contentUri, null, null, sent)
            MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                MmsSpikeJournal.CALL_RETURNED, System.currentTimeMillis(), ""))
            scheduleTimeout(journal, attemptId, transactionId)
            StartResult.CALL_RETURNED
        } catch (_: RuntimeException) {
            MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                MmsSpikeJournal.UNKNOWN_RESULT, System.currentTimeMillis(), "send_threw"))
            StartResult.UNKNOWN
        }
    }

    private fun scheduleTimeout(journal: File, attemptId: String, transactionId: String) {
        JournalRuntime.timeouts.schedule({
            JournalRuntime.io.execute {
                val events = try {
                    MmsSpikeJournal.replay(journal).filter { it.attemptId == attemptId }
                } catch (_: Exception) {
                    emptyList()
                }
                if (MmsSpikeJournal.attemptState(events) in setOf("pending", "submitting")) {
                    try {
                        MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                            MmsSpikeJournal.TIMEOUT_UNKNOWN, System.currentTimeMillis(), ""))
                    } catch (_: Exception) {
                    }
                }
            }
        }, SENT_CALLBACK_TIMEOUT_MINUTES, TimeUnit.MINUTES)
    }

    /** The journal stores only this unkeyed hash of the recipient, like the SMS token domains. */
    private fun recipientToken(recipientE164: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(recipientE164.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it) }

    private const val SENT_CALLBACK_TIMEOUT_MINUTES = 5L
}

/** Records the one platform send callback for the spike attempt. */
class MmsSpikeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_SENT) return
        val uri = intent.data ?: return
        if (uri.scheme != "zrotext" || uri.authority != "mms-spike-callback" ||
            uri.pathSegments.size != 2 || uri.pathSegments[1] != "sent") return
        val attemptId = uri.pathSegments[0]
        if (!attemptId.matches(Regex("^[0-9a-f-]{36}$"))) return
        val ok = resultCode == android.app.Activity.RESULT_OK
        val pending = goAsync()
        val app = context.applicationContext
        val journal = MmsSpikeSend.journalFile(app)
        JournalRuntime.io.execute {
            try {
                // The transaction id is read from the journal; a callback cannot invent one.
                val recorded = try {
                    MmsSpikeJournal.replay(journal)
                } catch (_: Exception) {
                    emptyList()
                }
                val transactionId = recorded.firstOrNull { it.attemptId == attemptId }?.transactionId
                if (transactionId != null) {
                    MmsSpikeJournal.append(journal, MmsSpikeEvent(attemptId, transactionId,
                        if (ok) MmsSpikeJournal.SENT_OK else MmsSpikeJournal.SENT_ERROR,
                        System.currentTimeMillis(), "result_" + resultCode))
                }
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_SENT = "org.zrotext.gateway.MMS_SPIKE_SENT"
    }
}
