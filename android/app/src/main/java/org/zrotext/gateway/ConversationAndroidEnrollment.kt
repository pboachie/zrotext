// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean

/** Opens only at the foreground enrollment action; never during pairing or app launch. */
internal object ConversationAndroidEnrollment {
    fun open(context: Context, database: SmsJournalDatabase, foreground: AtomicBoolean): ConversationEnrollmentSession {
        val app = checkNotNull(context.applicationContext)
        val host = checkNotNull(ConversationSocketComposition.currentAuthenticatedIdentity())
        val binding = checkNotNull(database.attempts().currentLineBinding())
        fun current() {
            check(foreground.get() && Build.VERSION.SDK_INT >= 31)
            host.requireCurrent()
            check(binding.accountId == host.identity.accountId && binding.deviceId == host.identity.deviceId &&
                binding.generation > 0 && binding.cardId != null && database.attempts().currentLineBinding() == binding)
            check(listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_PHONE_STATE).all {
                app.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
            })
            val selected = app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            check(selected == binding.subscriptionId && SimCardContinuity.matches(
                ActivatedSimCard(binding.subscriptionId, checkNotNull(binding.cardId)), SimCardContinuity.observe(app)))
            host.requireCurrent(); check(foreground.get())
        }
        current()
        // A stable exact account/device/line alias cannot replace another enrolled reader.
        val alias = "org.zrotext.conversation-reader.${binding.accountId}.${binding.deviceId}.${binding.lineId}.${binding.generation}"
        val storage = Draft02AndroidTrustStorage(app)
        return ConversationEnrollmentSession(binding.accountId, ::current,
            { current(); DevicePayloadKeyStore(app, alias).getOrCreateForEnrollment() }, storage, {
                current()
                database.runInTransaction {
                    val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    ConversationProtectionEnrollment.prepare({
                        keys.containsAlias(ConversationExistingJournalProtection.ALIAS) &&
                            keys.containsAlias(ConversationExistingSuppressionTokens.ALIAS)
                    }, {
                        // Never recreate protection after retained content or suppression has lost its key.
                        val files = listOf(ConversationJournalStores.CAPTURE_FILE, ConversationJournalStores.SEND_FILE).any { name ->
                            val path = app.getDatabasePath(name).path
                            listOf("", "-wal", "-shm", "-journal").any { java.io.File(path + it).exists() }
                        }
                        val rows = listOf("inbound_windows", "inbound_events", "inbound_uploads",
                            "local_recipient_suppressions", "local_inbound_withdrawals").any { table ->
                            database.openHelper.readableDatabase.query("SELECT COUNT(*) FROM $table").use {
                                check(it.moveToFirst()); it.getLong(0) != 0L
                            }
                        }
                        files || rows
                    }, {
                        current()
                        InboundVault.token("conversation-enrollment-v1", ByteArray(0))
                        current()
                        val sealed = InboundVault.seal("", "conversation-enrollment-v1")
                        sealed.ciphertext.fill(0); sealed.nonce.fill(0)
                    }, {
                        ConversationExistingJournalProtection().requireAvailable()
                        ConversationExistingSuppressionTokens().requireAvailable()
                    }, ::current)
                }
            }, { java.util.concurrent.ForkJoinPool.commonPool().execute { storage.close() } })
    }
}
