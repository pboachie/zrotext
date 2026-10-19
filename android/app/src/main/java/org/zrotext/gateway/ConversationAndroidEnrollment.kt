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
        if (Build.VERSION.SDK_INT < 31) error("Hardware enrollment unsupported")
        val physical = checkNotNull(binding.activatedSim())
        val lifetime = AndroidEnrollmentStorageLifetime.open(app)
        fun boundCurrent() {
            check(Build.VERSION.SDK_INT >= 31)
            host.requireCurrent()
            check(binding.accountId == host.identity.accountId && binding.deviceId == host.identity.deviceId &&
                binding.generation > 0 && binding.activatedSim() == physical && database.attempts().currentLineBinding() == binding)
            check(listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_PHONE_STATE).all {
                app.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
            })
            val selected = app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            check(selected == binding.subscriptionId && SimCardContinuity.matches(
                physical, SimCardContinuity.observe(app)))
            host.requireCurrent()
        }
        fun ramCurrent() {
            check(foreground.get()); host.requireCurrent(); lifetime.requireCurrent()
            physical.completeSelection?.let { check(it.isCurrent()) }
            physical.profile?.let { check(it.isCurrent()) }
            check(foreground.get())
        }
        fun current() {
            check(foreground.get())
            lifetime.validateOutsideStorage { boundCurrent(); check(foreground.get()) }
            ramCurrent()
        }
        try {
            current()
            val signing = DeviceSigningKeyStore(app)
            val signerPoint = signing.existingConversationPublicPoint()
            current()
            // A stable exact account/device/line alias cannot replace another enrolled reader.
            val alias = readerAlias(binding)
            val storage = Draft02AndroidTrustStorage(app)
            return ConversationEnrollmentSession(binding.accountId, ::current, ::ramCurrent,
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
                }, {
                    lifetime.close() // Withdraw at entry, before file/Keystore cleanup can wait.
                    java.util.concurrent.ForkJoinPool.commonPool().execute { storage.close() }
                }, { reader ->
                    current()
                    ConversationPhonePublicExport(binding.accountId, binding.deviceId, binding.lineId,
                        binding.generation, reader.point, signerPoint, {
                            boundCurrent()
                            check(java.security.MessageDigest.isEqual(signing.existingConversationPublicPoint(), signerPoint))
                            val existing = DevicePayloadKeyStore(app, alias).existingPublic()
                            check(existing.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
                            check(java.security.MessageDigest.isEqual(existing.keyId, reader.keyId) &&
                                java.security.MessageDigest.isEqual(existing.point, reader.point))
                            boundCurrent()
                        }, android.os.SystemClock::elapsedRealtime)
                })
        } catch (failure: Exception) { lifetime.close(); throw failure }
    }

    internal fun readerAlias(binding: LocalLineBinding) =
        "org.zrotext.conversation-reader.${binding.accountId}.${binding.deviceId}.${binding.lineId}.${binding.generation}"

    /** Foreground explicit initial chain import, independent of conversation/interval consent. */
    fun importInitialProfile03Manifests(context: Context, database: SmsJournalDatabase,
        foreground: AtomicBoolean, chain: List<ByteArray>): Long {
        val app = checkNotNull(context.applicationContext)
        val host = checkNotNull(ConversationSocketComposition.currentAuthenticatedIdentity())
        val line = checkNotNull(database.attempts().currentLineBinding())
        val permit = checkNotNull(line.installedSelectionV2())
        val time = Profile03BootstrapClock.capture(java.util.UUID.fromString(line.accountId),
            java.util.UUID.fromString(line.deviceId), host.identity.originHash)
        fun ramNow(): Long {
            check(foreground.get() && permit.isCurrent() && permit.matches(line))
            host.requireCurrent()
            return time().also { check(foreground.get() && permit.isCurrent()) }
        }
        fun current() {
            ramNow()
            check(line.accountId == host.identity.accountId && line.deviceId == host.identity.deviceId &&
                line.v2Purpose == "sealed" && line.protocolVersion == 2 && database.attempts().currentLineBinding() == line)
            val selected = app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            check(selected == line.subscriptionId && SimCardContinuity.matches(line.activatedSim(), SimCardContinuity.observe(app)))
            ramNow()
        }
        current()
        val reader = DevicePayloadKeyStore(app, readerAlias(line)).existingPublic()
        check(reader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
        val signer = DeviceSigningKeyStore(app).existingConversationPublicPoint()
        current()
        return Draft02AndroidTrustStorage(app).use { storage ->
            Profile03ManifestBootstrap.install(Draft02TrustStore(storage), chain, line, reader, signer, ::ramNow, ::current)
        }
    }
}
