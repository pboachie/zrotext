// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Existing stores/keys and the service's genuine current complete-observation issuer only.
 * This factory prepares local review; it neither signs nor publishes a selected-SIM permit.
 */
internal object SamePhoneSelectionReviewAndroid {
    fun open(context: Context, database: SmsJournalDatabase, foreground: AtomicBoolean): SamePhoneSelectionReview {
        val app = checkNotNull(context.applicationContext)
        val host = checkNotNull(ConversationSocketComposition.currentAuthenticatedIdentity())
        val account = UUID.fromString(host.identity.accountId)
        val device = UUID.fromString(host.identity.deviceId)
        val observed = Profile03BootstrapClock.observation(account, device, host.identity.originHash)
        val clock = observed::now
        val origins = observed.origins
        fun session() { check(foreground.get()); host.requireCurrent(); check(foreground.get()) }
        return SamePhoneSelectionReview(object : SamePhoneSelectionReview.Inputs {
            override fun withdrawInstalled() { session(); LineActivationV2SelectedLineMount.retireInstalled(); session() }
            override fun requireSession() = session()
            override fun nowMs(): Long { session(); return clock().also { session() } }
            override fun captureFresh(): SelectedLineLeaseV2? {
                session()
                return LineActivationV2SelectedLineMount.captureForAcceptance().also { session() }
            }
            override fun retained(): SamePhoneSelectionReview.Retained {
                session()
                val binding = checkNotNull(database.attempts().currentLineBinding())
                require(binding.accountId == account.toString() && binding.deviceId == device.toString() &&
                    binding.protocolVersion == 2 && binding.v2Purpose == "sealed")
                val activation = checkNotNull(database.lineActivationsV2().find("sealed", checkNotNull(binding.v2ChallengeId)))
                val election = checkNotNull(database.profile03Elections().installed(binding.accountId, binding.lineId))
                require(election.originHash == origins.protocolHash && activation.originHash == origins.routingHash)
                val recipient = DevicePayloadKeyStore(app, ConversationAndroidEnrollment.readerAlias(binding)).existingPublic()
                check(recipient.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                    Draft02OutboundPreparation.hex(recipient.keyId) == election.readerKeyId)
                val signer = DeviceSigningKeyStore(app).existingConversationPublicPoint()
                val core = Profile03ElectionEncoding.decode(election.coreB64url, 500)
                Draft02AndroidTrustStorage(app).use { storage ->
                    val inspected = Draft02TrustStore(storage).inspect()
                    check(inspected.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                    val snapshot = checkNotNull(inspected.snapshot)
                    val bytes = snapshot.bytes()
                    val manifest = bytes.copyOfRange(127, bytes.size)
                    require(snapshot.version == ByteBuffer.wrap(core, 176, 8).long &&
                        Draft02OutboundPreparation.hex(Draft02RootComparison.fingerprint(snapshot.pin)) == election.rootFingerprint &&
                        manifest.size in 364..9751 && MessageDigest.isEqual(core.copyOfRange(184, 216),
                            MessageDigest.getInstance("SHA-256").digest(manifest.copyOfRange(0, manifest.size - 64))))
                }
                session()
                check(database.attempts().currentLineBinding() == binding &&
                    database.profile03Elections().find(election.challengeId) == election &&
                    database.lineActivationsV2().find("sealed", activation.challengeId) == activation)
                return SamePhoneSelectionReview.Retained(origins, binding, activation, election, signer)
            }
        })
    }
}
