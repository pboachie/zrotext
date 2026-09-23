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
import android.telephony.SmsMessage
import android.telephony.SubscriptionManager
import androidx.core.content.ContextCompat
import java.util.concurrent.TimeUnit

/**
 * Local radio boundary. A writer-acknowledged Room reservation must be consumed durably
 * before this can make one SmsManager call. The old reserve-and-send entry point is removed.
 */
internal object SmsAttemptAdapter {
    enum class StartResult { NOT_STARTED, ALREADY_CONSUMED, JOURNAL_ERROR, RESERVED_NOT_SENT, CALL_RETURNED, UNKNOWN }

    fun sendAuthorized(
        context: Context,
        grant: AlphaGrantValidator.Grant,
        isSessionCurrent: () -> Boolean,
        finished: (StartResult) -> Unit
    ) {
        val app = context.applicationContext
        JournalRuntime.io.execute {
            val result = sendOnJournalThread(app, grant, isSessionCurrent)
            if (result == StartResult.NOT_STARTED) {
                runCatching { SmsJournalDatabase.get(app).attempts()
                    .markAcknowledgedNoRadio(grant.attemptId.toString(), System.currentTimeMillis()) }
            }
            finished(result)
        }
    }

    private fun sendOnJournalThread(
        context: Context, grant: AlphaGrantValidator.Grant, isSessionCurrent: () -> Boolean
    ): StartResult {
        val attemptId = grant.attemptId.toString()
        val subscriptionId = grant.subscriptionId
        if (!isSessionCurrent() || System.currentTimeMillis() >= grant.expiresAtMs ||
            !hasSelectedSim(context, subscriptionId)) return StartResult.NOT_STARTED

        // Never fall back to the default SIM. A missing or changed SIM is a preflight refusal.
        val manager = try {
            if (Build.VERSION.SDK_INT >= 31) context.getSystemService(SmsManager::class.java)
                .createForSubscriptionId(subscriptionId)
            else @Suppress("DEPRECATION") SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        } catch (_: RuntimeException) {
            return StartResult.NOT_STARTED
        }
        val parts = try { manager.divideMessage(grant.body) } catch (_: RuntimeException) { return StartResult.NOT_STARTED }
        if (parts.isEmpty() || parts.size > MAX_SEGMENTS) return StartResult.NOT_STARTED
        val sent = ArrayList<PendingIntent>(parts.size)
        val delivered = ArrayList<PendingIntent>(parts.size)
        try {
            parts.indices.forEach { index ->
                sent += callbackIntent(context, attemptId, index, SmsCallbackReceiver.ACTION_SENT)
                delivered += callbackIntent(context, attemptId, index, SmsCallbackReceiver.ACTION_DELIVERED)
            }
        } catch (_: RuntimeException) {
            return StartResult.NOT_STARTED
        }

        val dao = try { SmsJournalDatabase.get(context).attempts() }
                  catch (_: RuntimeException) { return StartResult.JOURNAL_ERROR }
        // The writer ack changed Room from reserved to submitting. This single conditional
        // update consumes that authorization before any possible radio invocation.
        if (!isSessionCurrent() || System.currentTimeMillis() >= grant.expiresAtMs ||
            !hasSelectedSim(context, subscriptionId)) return StartResult.NOT_STARTED
        val consumed = try {
            dao.consumeRadioStart(attemptId, grant.messageId.toString(), subscriptionId,
                parts.size, System.currentTimeMillis())
        } catch (_: RuntimeException) {
            return StartResult.JOURNAL_ERROR
        }
        if (consumed != 1) return StartResult.ALREADY_CONSUMED

        // Recheck after the durable one-use boundary. No call is made if the SIM or grant
        // changed in that interval, and the reservation cannot be consumed again.
        if (!isSessionCurrent() || System.currentTimeMillis() >= grant.expiresAtMs ||
            !hasSelectedSim(context, subscriptionId)) {
            return try {
                dao.setState(attemptId, AttemptState.NOT_SUBMITTED, System.currentTimeMillis())
                StartResult.RESERVED_NOT_SENT
            } catch (_: RuntimeException) {
                StartResult.UNKNOWN
            }
        }

        // Best effort while this process lives; startup reconciliation covers process death/reboot.
        JournalRuntime.timeouts.schedule({
            JournalRuntime.io.execute {
                dao.markStalledSubmission(attemptId, System.currentTimeMillis())
            }
        }, SENT_CALLBACK_TIMEOUT_MINUTES, TimeUnit.MINUTES)

        // There is intentionally no retry around this call. A throw may follow a partial radio action.
        return try {
            if (parts.size == 1) {
                manager.sendTextMessage(grant.recipientE164, null, parts[0], sent[0], delivered[0])
            } else {
                manager.sendMultipartTextMessage(grant.recipientE164, null, parts, sent, delivered)
            }
            StartResult.CALL_RETURNED // Call return is not a sent or delivery acknowledgment.
        } catch (_: RuntimeException) {
            runCatching { dao.setState(attemptId, AttemptState.UNKNOWN, System.currentTimeMillis()) }
            StartResult.UNKNOWN
        }
    }

    private fun hasSelectedSim(context: Context, subscriptionId: Int): Boolean {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) return false
        if (context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID) != subscriptionId) return false
        return try {
            val ids = context.getSystemService(SubscriptionManager::class.java)
                .activeSubscriptionInfoList.orEmpty().map { it.subscriptionId }
            SimSelection.isActive(subscriptionId, ids)
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun callbackIntent(context: Context, attemptId: String, index: Int, action: String): PendingIntent {
        val intent = Intent(context, SmsCallbackReceiver::class.java).apply {
            this.action = action
            data = Uri.Builder().scheme("zrotext").authority("sms-callback")
                .appendPath(attemptId).appendPath(action).appendPath(index.toString()).build()
        }
        // The delivery status PDU arrives through the platform fill-in Intent, so it must be mutable.
        // The component/action/data are explicit and the receiver reads identity only from the fixed URI.
        val mutability = if (action == SmsCallbackReceiver.ACTION_DELIVERED) {
            if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
        } else PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getBroadcast(
            context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or mutability
        )
    }

    private const val MAX_SEGMENTS = 6
    private const val SENT_CALLBACK_TIMEOUT_MINUTES = 2L
}

internal object SimSelection {
    fun isActive(selectedId: Int, activeIds: Collection<Int>): Boolean =
        selectedId >= 0 && activeIds.contains(selectedId)
}

/** Explicit, non-exported callbacks persist the result code once per segment. */
class SmsCallbackReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val delivery = when (intent.action) {
            ACTION_SENT -> false
            ACTION_DELIVERED -> true
            else -> return
        }
        val uri = intent.data ?: return
        if (uri.scheme != "zrotext" || uri.authority != "sms-callback" ||
            uri.pathSegments.size != 3 || uri.pathSegments[1] != intent.action) return
        val attemptId = uri.pathSegments[0]
        val index = uri.pathSegments[2].toIntOrNull() ?: return
        if (attemptId.length > 64 || index !in 0..5) return
        val result = resultCode
        val pdu = if (delivery) intent.getByteArrayExtra("pdu") else null
        val format = if (delivery) intent.getStringExtra("format") else null
        val pending = goAsync()
        val app = context.applicationContext
        JournalRuntime.io.execute {
            try {
                SmsJournalDatabase.get(app).attempts()
                    .recordCallback(attemptId, index, delivery, result,
                        if (delivery) {
                            if (result == android.app.Activity.RESULT_OK) readDeliveryStatus(pdu, format)
                            else DeliveryStatus.UNVERIFIED
                        } else null,
                        System.currentTimeMillis())
            } finally {
                pending.finish()
            }
        }
    }

    private fun readDeliveryStatus(pdu: ByteArray?, format: String?): Int {
        if (pdu == null || pdu.isEmpty() || pdu.size > 512 || format !in listOf("3gpp", "3gpp2")) {
            return DeliveryStatus.UNVERIFIED
        }
        val report = runCatching { SmsMessage.createFromPdu(pdu, format) }.getOrNull()
            ?: return DeliveryStatus.UNVERIFIED
        if (!report.isStatusReportMessage) return DeliveryStatus.UNVERIFIED
        return SmsDeliveryReportStatus.classify(format, report.status)
    }

    companion object {
        const val ACTION_SENT = "org.zrotext.gateway.SMS_SENT"
        const val ACTION_DELIVERED = "org.zrotext.gateway.SMS_DELIVERED"
    }
}

/** The platform reports GSM and CDMA delivery statuses in different numeric spaces. */
internal object SmsDeliveryReportStatus {
    fun classify(format: String?, status: Int): Int = when (format) {
        "3gpp" -> when (status) {
            0 -> DeliveryStatus.RECEIVED
            in 64..127 -> DeliveryStatus.FAILED
            else -> DeliveryStatus.UNVERIFIED
        }
        "3gpp2" -> when (status) {
            2 shl 16 -> DeliveryStatus.RECEIVED
            else -> DeliveryStatus.UNVERIFIED
        }
        else -> DeliveryStatus.UNVERIFIED
    }
}
