// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/** Independent live admission/clock/manifest/card state, never copied out of the grant reply. */
internal class ConversationExecutionCurrent(val session:SealedDispatchExecutor.Session,
    val local:SealedDispatchExecutor.Local, val trustedNowMs:Long, val authorizedUntilMs:Long) {
    init {require(trustedNowMs>0 && authorizedUntilMs>trustedNowMs)}
    override fun toString()="ConversationExecutionCurrent(redacted)"
}
/** Validated metadata, not bearer authority: only the guarded one-use holder permits consumption. */
internal sealed interface ConversationPreparedSubmissionContext {
    val message:String
    val attempt:String
    val scope:ConversationCaptureScope
    val originalDeadlineMs:Long
    val deadlineMs:Long
    val grant:SealedExecutionGrantValidator.Fields
    val session:SealedDispatchExecutor.Session
    val local:SealedDispatchExecutor.Local
}
/**
 * Mandatory synchronous prepared-holder consumer. It must not retain or asynchronously consume
 * the holder. A writer ACK wait precedes guarded consumption, outside admission monitors; an ACK
 * is not authority unless it binds the exact current session/message/attempt and permits submit.
 */
internal fun interface ConversationPreparedSubmission {
    fun submit(context:ConversationPreparedSubmissionContext,
               prepared:Draft02OutboundPreparation.Prepared):ConversationSubmission
}

/**
 * Dormant grant handoff. Reloads the claimed journal's original protected ZTCR, authenticates it
 * again, obtains one exact binary grant, and invokes the existing grant/preparation boundary.
 * No retry, credentials, enrollment, AlphaGrant conversion, radio implementation or mounting.
 * The injected preparation constructor is solely a fixture seam; production uses the typed
 * ContentCrypto/ExecutionBoundary constructor and independently sampled admission authority.
 */
internal class ConversationExecutionTransport internal constructor(
    private val journal:ConversationSendDao,
    private val protection:ConversationJournalProtection,
    private val verifier:ConversationSendVerifier,
    private val wire:ConversationAuthenticatedWire,
    private val current:(ConversationCaptureScope)->ConversationExecutionCurrent?,
    private val prepare:(ConversationCaptureScope,SealedExecutionGrantValidator.Fields,ByteArray,
                         SealedDispatchExecutor.Session,SealedDispatchExecutor.Local)->SealedDispatchExecutor.Outcome,
    private val consumer:ConversationPreparedSubmission
) : ConversationClaimedEvidenceTransport {
    /** Private implementation prevents callers constructing the transport's validated snapshot. */
    private class SubmissionContext(
        override val message:String,override val attempt:String,override val scope:ConversationCaptureScope,
        override val originalDeadlineMs:Long, fields:SealedExecutionGrantValidator.Fields,
        authority:ConversationExecutionCurrent
    ) : ConversationPreparedSubmissionContext {
        private val fields=copy(fields)
        private val sourceSession=authority.session
        private val sourceLocal=SealedDispatchExecutor.Local(authority.local.binding.copy(),
            authority.local.pinnedReaderKeyId,authority.local.manifestGeneration,authority.local.manifestVersion,
            authority.local.manifestDigest,authority.local.recipientDigest)
        override val deadlineMs=minOf(originalDeadlineMs,fields.expiresAtMs,authority.authorizedUntilMs)
        override val grant get()=copy(fields)
        override val session get()=SealedDispatchExecutor.Session(sourceSession.accountId,sourceSession.deviceId,
            sourceSession.connectionEpoch,sourceSession.deploymentEpoch,sourceSession.sessionId,sourceSession.originHash)
        override val local get()=SealedDispatchExecutor.Local(sourceLocal.binding.copy(),sourceLocal.pinnedReaderKeyId,
            sourceLocal.manifestGeneration,sourceLocal.manifestVersion,sourceLocal.manifestDigest,sourceLocal.recipientDigest)
        override fun toString()="ConversationPreparedSubmissionContext(redacted)"
        companion object {
            private fun copy(value:SealedExecutionGrantValidator.Fields)=value.copy(
                envelopeDigest=value.envelopeDigest.copyOf(),readerKeyId=value.readerKeyId.copyOf(),
                unsignedDigest=value.unsignedDigest.copyOf())
        }
    }
    constructor(journal:ConversationSendDao,protection:ConversationJournalProtection,
        verifier:ConversationContentCrypto,wire:ConversationAuthenticatedWire,
        current:(ConversationCaptureScope)->ConversationExecutionCurrent?,boundary:ConversationExecutionBoundary,
        consumer:ConversationPreparedSubmission) : this(journal,protection,verifier,wire,current,boundary::prepare,consumer)

    private val attempted=mutableSetOf<String>()
    private val gate=Any()
    // Legacy fixture transports retain the body port. Production refuses it without any effect.
    override fun submit(message:String,attempt:String,scope:ConversationCaptureScope,body:String)=ConversationSubmission.UNKNOWN

    override fun submitClaimed(claim:ConversationClaimedEvidence):ConversationSubmission {
        var handed:ByteArray?=null
        var original:ByteArray?=null
        var parts:ConversationContentCrypto.Evidence?=null
        var prepared:Draft02OutboundPreparation.Prepared?=null
        return try {
            handed=claim.take()
            synchronized(gate) {check(attempted.size<1024 && attempted.add(claim.message+":"+claim.attempt))}
            fun row():ConversationSendReceipt {
                val value=checkNotNull(journal.receipt(claim.message))
                check(value.state=="claimed" && value.attempt==claim.attempt && value.interval==claim.scope.intervalId &&
                    value.evidenceDigest==claim.evidenceDigest && value.deadline==claim.deadline &&
                    value.protectedPayload!=null && value.nonce!=null && journal.closed(value.interval)==0)
                return value
            }
            val stored=row()
            val aad="zrotext-conversation-send-v1:${claim.message}:${stored.interval}:${stored.evidenceDigest}"
            original=Base64.getDecoder().decode(protection.open(InboundVault.Sealed(
                checkNotNull(stored.protectedPayload).copyOf(),checkNotNull(stored.nonce).copyOf()),aad))
            val bytes=checkNotNull(original)
            check(bytes.size in 1..40*1024 && hex(sha(bytes))==claim.evidenceDigest && same(bytes,checkNotNull(handed)))
            val evidence=ConversationContentCrypto.unpackConfirmedEvidence(bytes).also{parts=it}
            val confirmation=ConversationContentCrypto.Confirmation.decode(evidence.confirmation)
            val verified=verifier.verify(bytes.copyOf())
            check(verified.scope==claim.scope && verified.message==claim.message && verified.expiresAt==claim.deadline)
            check(confirmation.account==claim.scope.accountId && confirmation.device==claim.scope.deviceId &&
                confirmation.line==claim.scope.lineId && confirmation.interval==claim.scope.intervalId &&
                confirmation.session==claim.scope.initiatingSessionId && confirmation.peer==claim.scope.peer &&
                confirmation.message==claim.message && confirmation.generation==claim.scope.bindingGeneration &&
                confirmation.trustGeneration==claim.scope.trustGeneration && confirmation.expiresMs==claim.deadline &&
                same(confirmation.reader,unhex(claim.scope.readerKeyId)))
            val routing=Draft02OutboundEnvelope.routingClaims(evidence.envelope)
            check(uuid(routing.accountId)==claim.scope.accountId && uuid(routing.deviceId)==claim.scope.deviceId &&
                uuid(routing.lineId)==claim.scope.lineId && uuid(routing.messageId)==claim.message)
            val full=sha(evidence.envelope)
            val unsigned=sha(evidence.envelope.copyOfRange(0,evidence.envelope.size-64))
            check(same(full,confirmation.envelopeDigest) && ByteBuffer.wrap(evidence.envelope,154,8).long==claim.deadline)
            val initial=checkNotNull(current(claim.scope))
            val phone=ConversationPhoneSession.from(initial.session)
            var latestNow=initial.trustedNowMs
            fun live():ConversationExecutionCurrent {
                row()
                val value=checkNotNull(current(claim.scope))
                check(ConversationPhoneSession.from(value.session)==phone && wire.currentSession()==phone &&
                    value.trustedNowMs>=latestNow && value.trustedNowMs<claim.deadline)
                latestNow=value.trustedNowMs
                check(value.local.binding==initial.local.binding &&
                    same(value.local.pinnedReaderKeyId,initial.local.pinnedReaderKeyId) &&
                    value.local.manifestGeneration==initial.local.manifestGeneration &&
                    value.local.manifestVersion==initial.local.manifestVersion &&
                    value.local.manifestDigest==initial.local.manifestDigest &&
                    value.local.recipientDigest==initial.local.recipientDigest)
                val binding=value.local.binding
                check(binding.accountId==claim.scope.accountId && binding.deviceId==claim.scope.deviceId &&
                    binding.lineId==claim.scope.lineId && binding.generation==claim.scope.bindingGeneration &&
                    value.local.manifestGeneration==confirmation.trustGeneration &&
                    value.local.manifestVersion==confirmation.version &&
                    value.local.manifestDigest==hex(confirmation.manifest) &&
                    value.local.recipientDigest==hex(sha(claim.scope.peer.toByteArray(Charsets.US_ASCII))) &&
                    same(value.local.pinnedReaderKeyId,routing.deviceReaderKeyId))
                return value
            }
            live()
            val nonce=UUID.randomUUID()
            val reply=wire.exchange(ConversationChannelCodec.executionRequest(phone,nonce,claim.scope,
                UUID.fromString(claim.message),UUID.fromString(claim.attempt),full))
            check(reply.authenticatedSession==phone)
            val parsed=ConversationChannelCodec.parseExecutionReply(reply.bytes,phone)
            check(parsed.first==nonce)
            val fields=parsed.second
            val after=live()
            check(fields.accountId==phone.account && fields.deviceId==phone.device &&
                fields.lineId.toString()==claim.scope.lineId && fields.messageId.toString()==claim.message &&
                fields.attemptId.toString()==claim.attempt && fields.connectionEpoch==phone.connectionEpoch &&
                fields.deploymentEpoch==phone.deploymentEpoch && fields.bindingGeneration==claim.scope.bindingGeneration &&
                fields.attemptGeneration==1L && fields.readerRole==1 && fields.segmentCount in 1..6 &&
                same(fields.envelopeDigest,full) && same(fields.unsignedDigest,unsigned) &&
                same(fields.readerKeyId,after.local.pinnedReaderKeyId) && fields.expiresAtMs<=claim.deadline &&
                fields.expiresAtMs<=initial.authorizedUntilMs && fields.expiresAtMs<=after.authorizedUntilMs && fields.expiresAtMs>after.trustedNowMs &&
                fields.expiresAtMs-after.trustedNowMs<=35000)
            check(verifier.verify(bytes.copyOf())==verified)
            val before=live()
            check(before.trustedNowMs<fields.expiresAtMs && fields.expiresAtMs<=before.authorizedUntilMs)
            val outcome=prepare(claim.scope,fields,evidence.envelope.copyOf(),before.session,before.local)
            if(outcome !is SealedDispatchExecutor.Ready) return ConversationSubmission.UNKNOWN
            prepared=outcome.prepared
            val final=live()
            check(final.trustedNowMs<fields.expiresAtMs && fields.expiresAtMs<=final.authorizedUntilMs)
            consumer.submit(SubmissionContext(claim.message,claim.attempt,claim.scope,claim.deadline,fields,final),
                outcome.prepared)
        } catch (_:Exception) {ConversationSubmission.UNKNOWN}
        finally {
            try {prepared?.close()} finally {
                handed?.fill(0);original?.fill(0);parts?.envelope?.fill(0);parts?.confirmation?.fill(0);parts?.signature?.fill(0);claim.close()
            }
        }
    }
    override fun toString()="ConversationExecutionTransport(redacted)"
    companion object {
        private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a:ByteArray,b:ByteArray)=MessageDigest.isEqual(a,b)
        private fun hex(bytes:ByteArray)=Draft02OutboundPreparation.hex(bytes)
        private fun unhex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
        private fun uuid(bytes:ByteArray)=Draft02OutboundPreparation.uuid(bytes)
    }
}
