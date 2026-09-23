// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SmsMessage
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

/** No country-code inference: only an explicit international sender can match the local approval. */
internal object InboundNormalizer {
    data class Part(val sender: String?, val body: String?, val timestampMs: Long)
    data class Message(val senderE164: String, val body: String, val partCount: Int)

    fun e164(raw: String?): String? {
        if (raw == null || raw.length > 32 || !raw.startsWith('+')) return null
        val compact = raw.filterNot { it == ' ' || it == '-' || it == '(' || it == ')' }
        return compact.takeIf { it.matches(Regex("^\\+[1-9][0-9]{1,14}$")) }
    }

    /** Android's broadcast groups PDUs for one message; preserve their supplied order. */
    fun normalize(parts: List<Part>): Message? {
        if (parts.size !in 1..6) return null
        val sender = e164(parts.first().sender) ?: return null
        if (parts.any { e164(it.sender) != sender || it.body.isNullOrEmpty() }) return null
        val timestamps = parts.map { it.timestampMs }
        if (timestamps.any { it <= 0 } || timestamps.max() - timestamps.min() > 5 * 60_000L) return null
        val body = parts.joinToString(separator = "") { it.body!! }
        if (body.toByteArray(Charsets.UTF_8).size > 4096) return null
        return Message(sender, body, parts.size)
    }
}

/** Android Keystore keys never leave the phone. The Room body is AES-GCM ciphertext. */
internal object InboundVault {
    data class Sealed(val ciphertext: ByteArray, val nonce: ByteArray)

    @Synchronized private fun key(alias: String, algorithm: String): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(algorithm, "AndroidKeyStore")
        val spec = if (algorithm == KeyProperties.KEY_ALGORITHM_AES) {
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()
        } else {
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256).build()
        }
        generator.init(spec)
        return generator.generateKey()
    }

    /** Domain-separated, length-delimited HMAC avoids a guessable plaintext/PDU hash in Room. */
    fun token(domain: String, vararg fields: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key("zt_m1_inbound_hmac_v1", KeyProperties.KEY_ALGORITHM_HMAC_SHA256))
        val data = ByteArrayOutputStream()
        for (field in arrayOf(domain.toByteArray(Charsets.US_ASCII), *fields)) {
            require(field.size <= 8192)
            data.write((field.size ushr 24) and 0xff)
            data.write((field.size ushr 16) and 0xff)
            data.write((field.size ushr 8) and 0xff)
            data.write(field.size and 0xff)
            data.write(field)
        }
        return mac.doFinal(data.toByteArray()).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
    }

    fun seal(body: String, eventToken: String): Sealed {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key("zt_m1_inbound_aes_v1", KeyProperties.KEY_ALGORITHM_AES))
        cipher.updateAAD(eventToken.toByteArray(Charsets.US_ASCII))
        return Sealed(cipher.doFinal(body.toByteArray(Charsets.UTF_8)), cipher.iv)
    }

    fun open(sealed: Sealed, eventToken: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key("zt_m1_inbound_aes_v1", KeyProperties.KEY_ALGORITHM_AES),
            javax.crypto.spec.GCMParameterSpec(128, sealed.nonce))
        cipher.updateAAD(eventToken.toByteArray(Charsets.US_ASCII))
        return cipher.doFinal(sealed.ciphertext).toString(Charsets.UTF_8)
    }
}

/** Notification only; the default SMS app continues to own inbox writes and user notification. */
class InboundSmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val pending = goAsync()
        val app = context.applicationContext
        io.execute {
            try { capture(app, intent) } catch (_: Exception) {
                // No body, sender, PDU, or exception message is written to a log.
            } finally { pending.finish() }
        }
    }

    private fun capture(context: Context, intent: Intent) {
        val raw = intent.extras?.get("pdus") as? Array<*> ?: return
        if (raw.size !in 1..6 || raw.any { it !is ByteArray || it.size !in 1..512 }) return
        val format = intent.getStringExtra("format")?.takeIf { it == "3gpp" || it == "3gpp2" }
            ?: return
        val pdus = raw.map { it as ByteArray }
        if (pdus.distinctBy { it.toList() }.size != pdus.size) return
        val parts = pdus.map { pdu ->
            val sms = SmsMessage.createFromPdu(pdu, format) ?: return
            if (sms.isEmail) return
            InboundNormalizer.Part(sms.originatingAddress, sms.messageBody, sms.timestampMillis)
        }
        val message = InboundNormalizer.normalize(parts) ?: return
        val now = System.currentTimeMillis()
        val senderToken = InboundVault.token("sender-v1", message.senderE164.toByteArray(Charsets.US_ASCII))
        val dao = SmsJournalDatabase.get(context).attempts()
        val window = dao.activeInboundWindows(senderToken, now).singleOrNull() ?: return
        // SMS_RECEIVED documents PDUs, not a mandatory subscription extra. Missing evidence
        // is stored without a body; a slot/default-SIM guess cannot authorize capture.
        val rawSub = intent.extras?.get("subscription")
        val observedSub = (rawSub as? Number)?.toLong()
            ?.takeIf { it in 0..Int.MAX_VALUE.toLong() }?.toInt()
        if (observedSub != null && observedSub != window.subscriptionId) return
        val pduFingerprint = ByteArrayOutputStream().apply {
            for (pdu in pdus) {
                write((pdu.size ushr 8) and 0xff)
                write(pdu.size and 0xff)
                write(pdu)
            }
        }.toByteArray()
        val dedupeToken = InboundVault.token("pdu-v1", senderToken.toByteArray(Charsets.US_ASCII),
            pduFingerprint)
        val sealed = try { InboundVault.seal(message.body, dedupeToken) }
            catch (_: Exception) { null }
        dao.recordInbound(window, dedupeToken, observedSub, message.partCount, now,
            sealed?.ciphertext, sealed?.nonce)
    }

    companion object {
        private val io = Executors.newSingleThreadExecutor()
    }
}
