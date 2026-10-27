// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/** Explicit isolated-emulator fixture, not a production first-ever/adoption factory. Never
 * replaces an alias, clears negative state, seeds capture counters or runs on a physical phone. */
internal object InboundProtectionDeviceFixture {
    fun prepare(context: Context) {
        check(Build.FINGERPRINT.contains("sdk_gphone", ignoreCase = true))
        val db = SmsJournalDatabase.get(context)
        check(db.attempts().currentLineBinding() == null && db.captures03().releasedElections().isEmpty() &&
            db.captures03().modes().isEmpty() && !db.captures03().hasCapture03History())
        val before = db.captures03().protection()
        check(before?.blocked != true)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = ConversationExistingSuppressionTokens.ALIAS
        val key = (store.getKey(alias, null) as? SecretKey) ?: run {
            check(before == null) // Missing retained fixture key never means regenerate.
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256).build())
                generateKey()
            }
        }
        val tag = Mac.getInstance("HmacSHA256").run {
            init(key); doFinal("zrotext-inbound-protection-continuity-v1\u0000".toByteArray(Charsets.US_ASCII))
        }.joinToString("") { "%02x".format(it.toInt() and 255) }
        if (before == null) db.openHelper.writableDatabase.execSQL(
            "INSERT INTO inbound_protection_state VALUES(1,?,?,0,NULL,0,1000)",
            arrayOf(tag, UUID(0, 31).toString()))
        else check(before.expectedTag == tag && before.originId == UUID(0, 31).toString())
        InboundProtection.key(context)
    }
}
