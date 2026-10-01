// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.telephony.SubscriptionManager
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/** Explicit, default-disabled composition over already owned journals, keys and authenticated wire.
 * Creates no database, credential, key, trust pin, phone consent or authenticated session.
 */
internal class ConversationExecutionComposition(context: Context,
    private val database: SmsJournalDatabase, private val enabled: Boolean = false) {
    private val application = checkNotNull(context.applicationContext)

    /** Factory supplies its actual assembled runtime and independently verified current authority. */
    internal class Connection internal constructor(val runtime: ConversationAuthenticatedRuntime,
        val crypto: ConversationContentCrypto, val wire: ConversationAuthenticatedWire,
        val phone: ConversationPhoneSession, val inputs: ConversationConnectionInputs,
        internal val currentCrypto: (ConversationCaptureScope, Long) -> ConversationCryptoCurrent) {
        override fun toString() = "ConversationExecutionConnection(redacted)"
    }
    private class Selection(val current: ConversationExecutionCurrent,
        val crypto: ConversationCryptoCurrent, val cards: List<ActiveSimCard>)

    fun dispatch(connection: Connection): ConversationSendTransport {
        if (!enabled) return Unavailable
        val radioWire = connection.wire as? ConversationRadioIntentWire ?: return Unavailable
        val inputs = connection.inputs
        val attempts = database.attempts()
        val suppression = ConversationExistingSuppressionTokens()

        fun sample(scope: ConversationCaptureScope): Selection? = runCatching {
            fun session() {
                check(connection.wire.currentSession() == connection.phone &&
                    connection.runtime.currentScope() == scope && connection.runtime.captureEligible())
                check(scope.accountId == connection.phone.account.toString() &&
                    scope.deviceId == connection.phone.device.toString() && inputs.lifecycleLoss() == null)
            }
            fun local(): Pair<LocalLineBinding, List<ActiveSimCard>> {
                session()
                check(listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_PHONE_STATE).all {
                    application.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
                })
                val binding = checkNotNull(attempts.currentLineBinding())
                val selected = application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                val cards = checkNotNull(SimCardContinuity.observe(application))
                check(ConversationAndroidConnectionInputs.localLoss(scope, binding, selected, cards) == null)
                inputs.requireAuthority(scope, checkNotNull(connection.runtime.trustedNowMs()))
                return binding.copy() to cards.toList()
            }
            val firstLocal = local()
            val first = connection.currentCrypto(scope, checkNotNull(connection.runtime.trustedNowMs()))
            val reader = inputs.payloadKeys.existingPublic()
            check(reader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
            suppression.requireAvailable() // Lookup-only, before any grant/decryption/radio effects.
            val firstDeadline = checkNotNull(connection.runtime.executionDeadline(scope))
            val nextLocal = local()
            check(nextLocal.first == firstLocal.first)
            val nextReader = inputs.payloadKeys.existingPublic()
            check(nextReader.security == reader.security && same(nextReader.keyId, reader.keyId))
            suppression.requireAvailable()
            val deadline = minOf(firstDeadline, checkNotNull(connection.runtime.executionDeadline(scope)))
            val final = connection.currentCrypto(scope, checkNotNull(connection.runtime.trustedNowMs()))
            check(sameAuthority(first, final))
            session()
            // All Room, card, permission, Keystore, suppression and trust providers precede this sample.
            val now = checkNotNull(connection.runtime.trustedNowMs())
            check(now >= final.trustedNowMs && deadline > now)
            val request = request(scope, scope.intervalId, final, reader.keyId)
            final.authority.context(request, now)
            final.authority.context(request, deadline - 1)
            val inbound = Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.INBOUND,
                uuid(scope.accountId), uuid(scope.intervalId), uuid(scope.deviceId), uuid(scope.lineId),
                scope.peer.toByteArray(Charsets.US_ASCII), final.phoneSignerKeyId,
                listOf(Draft02ManifestAuthority.Reader(2, unhex(scope.readerKeyId))))
            final.authority.context(inbound, now)
            final.authority.context(inbound, deadline - 1)
            val local = SealedDispatchExecutor.Local(nextLocal.first, reader.keyId, final.authority.generation,
                final.authority.version, hex(final.authority.digest), hash(scope.peer.toByteArray(Charsets.US_ASCII)))
            Selection(ConversationExecutionCurrent(asSession(connection.phone), local, now, deadline), final, nextLocal.second)
        }.getOrNull()

        fun preparation(grant: Draft02OutboundPreparation.Grant): Draft02OutboundPreparation.Current? = runCatching {
            val scope = checkNotNull(connection.runtime.currentScope())
            val selected = checkNotNull(sample(scope))
            requirePreparation(grant, scope, selected.current)
            val request = request(scope, grant.messageId, selected.crypto, selected.current.local.pinnedReaderKeyId)
            selected.crypto.authority.context(request, selected.current.trustedNowMs)
            selected.crypto.authority.context(request, grant.expiresAtMs - 1)
            Draft02OutboundPreparation.Current(grant, selected.crypto.authority, request,
                selected.current.trustedNowMs, selected.current.local.binding.subscriptionId, selected.cards)
        }.getOrNull()

        val boundary = connection.runtime.executionBoundary({
            val scope = connection.runtime.currentScope()
            scope?.let { sample(it)?.let { live -> ConversationExecutionAuthority(it,
                ConversationPhoneSession.from(live.current.session), true, true, true, true, true) } }
        }, database, inputs.payloadKeys, ::preparation)

        fun requireCurrent(context: ConversationPreparedSubmissionContext): Long {
            check(context.evidenceDigest.matches(Regex("[0-9a-f]{64}")))
            val receipt = checkNotNull(inputs.sends.receipt(context.message))
            check(receipt.state == "claimed" && receipt.attempt == context.attempt &&
                receipt.interval == context.scope.intervalId && receipt.deadline == context.originalDeadlineMs &&
                receipt.evidenceDigest == context.evidenceDigest && receipt.protectedPayload != null &&
                receipt.nonce != null && inputs.sends.closed(receipt.interval) == 0)
            val aad = "zrotext-conversation-send-v1:${context.message}:${receipt.interval}:${receipt.evidenceDigest}"
            val cipher = checkNotNull(receipt.protectedPayload)
            val nonce = checkNotNull(receipt.nonce)
            check(cipher.size in 17..64 * 1024 && nonce.size == 12)
            val encoded = inputs.protection.open(InboundVault.Sealed(cipher.copyOf(), nonce.copyOf()), aad)
            check(encoded.length in 1..((40 * 1024 + 2) / 3) * 4)
            val original = Base64.getDecoder().decode(encoded)
            var proof: ConversationContentCrypto.Evidence? = null
            try {
                check(original.size in 1..40 * 1024 && hash(original) == context.evidenceDigest)
                proof = ConversationContentCrypto.unpackConfirmedEvidence(original)
                val fields = context.grant
                check(same(sha(proof.envelope), fields.envelopeDigest) &&
                    same(sha(proof.envelope.copyOfRange(0, proof.envelope.size - 64)), fields.unsignedDigest))
                val live = checkNotNull(sample(context.scope))
                check(ConversationPhoneSession.from(context.session) == connection.phone &&
                    sameLocal(context.local, live.current.local))
                requireGrant(fields, context.scope, context.message, context.attempt,
                    context.originalDeadlineMs, live.current)
                check(context.deadlineMs <= fields.expiresAtMs && context.deadlineMs <= live.current.authorizedUntilMs)
                check(live.current.trustedNowMs < context.deadlineMs)
                return live.current.trustedNowMs
            } finally {
                original.fill(0); proof?.envelope?.fill(0); proof?.confirmation?.fill(0); proof?.signature?.fill(0)
            }
        }
        val consumer = ConversationPreparedRadioSubmission(attempts, radioWire, ::requireCurrent,
            { binding -> ConversationRadioPlatform(application, binding, suppression, enabled = true) }, enabled = true)
        return ConversationExecutionTransport(inputs.sends, inputs.protection, connection.crypto,
            connection.wire, { scope -> sample(scope)?.current }, boundary, consumer)
    }
    override fun toString() = "ConversationExecutionComposition(redacted)"

    private object Unavailable : ConversationClaimedEvidenceTransport {
        override fun submit(message: String, attempt: String, scope: ConversationCaptureScope, body: String) = ConversationSubmission.UNKNOWN
        override fun submitClaimed(claim: ConversationClaimedEvidence): ConversationSubmission {
            claim.close(); return ConversationSubmission.UNKNOWN
        }
    }
    companion object {
        internal fun requirePreparation(grant: Draft02OutboundPreparation.Grant, scope: ConversationCaptureScope,
            live: ConversationExecutionCurrent) {
            requireLocalScope(scope, live.local)
            val session = live.session; val local = live.local; val binding = local.binding
            check(grant.accountId == scope.accountId && grant.deviceId == scope.deviceId &&
                grant.lineId == scope.lineId && grant.bindingGeneration == scope.bindingGeneration &&
                grant.attemptGeneration == 1L && grant.accountId == session.accountId.toString() &&
                grant.deviceId == session.deviceId.toString() && grant.sessionId == session.sessionId.toString() &&
                grant.originHash == session.originHash && grant.connectionEpoch == session.connectionEpoch &&
                grant.deploymentEpoch == session.deploymentEpoch && grant.manifestGeneration == local.manifestGeneration &&
                grant.manifestVersion == local.manifestVersion && grant.manifestDigest == local.manifestDigest &&
                grant.recipientDigest == local.recipientDigest && grant.subscriptionId == binding.subscriptionId &&
                grant.cardId == binding.cardId && grant.expiresAtMs > live.trustedNowMs &&
                grant.expiresAtMs <= live.authorizedUntilMs)
        }
        internal fun requireGrant(fields: SealedExecutionGrantValidator.Fields, scope: ConversationCaptureScope,
            message: String, attempt: String, originalDeadline: Long, live: ConversationExecutionCurrent) {
            requireLocalScope(scope, live.local)
            val session = live.session; val local = live.local
            check(fields.accountId.toString() == scope.accountId && fields.deviceId.toString() == scope.deviceId &&
                fields.lineId.toString() == scope.lineId && fields.bindingGeneration == scope.bindingGeneration &&
                fields.accountId == session.accountId && fields.deviceId == session.deviceId &&
                fields.connectionEpoch == session.connectionEpoch && fields.deploymentEpoch == session.deploymentEpoch &&
                fields.messageId.toString() == message && fields.attemptId.toString() == attempt &&
                fields.attemptGeneration == 1L && fields.readerRole == 1 && fields.segmentCount in 1..6 &&
                same(fields.readerKeyId, local.pinnedReaderKeyId) && fields.expiresAtMs > live.trustedNowMs &&
                fields.expiresAtMs <= minOf(originalDeadline, live.authorizedUntilMs))
        }
        private fun requireLocalScope(scope: ConversationCaptureScope, local: SealedDispatchExecutor.Local) {
            val binding = local.binding
            check(binding.accountId == scope.accountId && binding.deviceId == scope.deviceId &&
                binding.lineId == scope.lineId && binding.generation == scope.bindingGeneration &&
                local.manifestGeneration == scope.trustGeneration && local.manifestVersion >= scope.activationVersion &&
                (local.manifestVersion != scope.activationVersion || local.manifestDigest == scope.activationDigest) &&
                local.recipientDigest == hash(scope.peer.toByteArray(Charsets.US_ASCII)))
        }
        private fun sameLocal(a: SealedDispatchExecutor.Local, b: SealedDispatchExecutor.Local) =
            a.binding == b.binding && same(a.pinnedReaderKeyId, b.pinnedReaderKeyId) &&
                a.manifestGeneration == b.manifestGeneration && a.manifestVersion == b.manifestVersion &&
                a.manifestDigest == b.manifestDigest && a.recipientDigest == b.recipientDigest
        private fun sameAuthority(a: ConversationCryptoCurrent, b: ConversationCryptoCurrent) =
            a.scope == b.scope && a.authority.generation == b.authority.generation &&
                a.authority.version == b.authority.version && same(a.authority.digest, b.authority.digest) &&
                same(a.archiveReaderPoint, b.archiveReaderPoint) && same(a.outboundSignerKeyId, b.outboundSignerKeyId) &&
                same(a.phoneSignerKeyId, b.phoneSignerKeyId)
        private fun request(scope: ConversationCaptureScope, message: String, current: ConversationCryptoCurrent, reader: ByteArray) =
            Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.OUTBOUND, uuid(scope.accountId),
                uuid(message), uuid(scope.deviceId), uuid(scope.lineId), scope.peer.toByteArray(Charsets.US_ASCII),
                current.outboundSignerKeyId, listOf(Draft02ManifestAuthority.Reader(1, reader),
                    Draft02ManifestAuthority.Reader(2, unhex(scope.readerKeyId))))
        private fun asSession(phone: ConversationPhoneSession) = SealedDispatchExecutor.Session(phone.account,
            phone.device, phone.connectionEpoch, phone.deploymentEpoch, phone.session, phone.originHash)
        private fun uuid(value: String) = UUID.fromString(value).let {
            java.nio.ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()
        }
        private fun unhex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun hash(bytes: ByteArray) = hex(sha(bytes))
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
