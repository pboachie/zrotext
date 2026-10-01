// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Concrete canonical verification + two-stage authenticated installation. Existing trust/key
 * adapters create no credential here. The proposal alone cannot open either journal's admission.
 */
internal class ConversationPhoneActivation(statement:ByteArray,private val trust:Draft02TrustStore,
    private val wire:ConversationAuthenticatedWire,private val trustedNow:()->Long,
    private val signExisting:(ByteArray,ByteArray,ByteArray)->ByteArray):ConversationActivationVerifier {
    private val original=statement.copyOf()
    private val parsed=ConversationActivationCodec.decode(original)
    private var accepted:ByteArray?=null
    private var acceptedChallenge:String?=null
    private fun uuid(text:String)=UUID.fromString(text).let{ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()}
    private fun hex(text:String)=text.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun context():Draft02ManifestAuthority.Context {
        val session=checkNotNull(wire.currentSession());val scope=parsed.scope
        check(session.account.toString()==scope.accountId && session.device.toString()==scope.deviceId &&
            session.connectionEpoch==parsed.connectionEpoch && session.deploymentEpoch==parsed.deploymentEpoch)
        val authority=trust.currentAuthority(trustedNow)
        check(authority.generation==scope.trustGeneration && authority.version>=scope.activationVersion)
        if(authority.version==scope.activationVersion)check(authority.digest.contentEquals(hex(scope.activationDigest)))
        return authority.context(Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.INBOUND,
            uuid(scope.accountId),uuid(scope.intervalId),uuid(scope.deviceId),uuid(scope.lineId),scope.peer.toByteArray(Charsets.US_ASCII),
            parsed.signerId,listOf(Draft02ManifestAuthority.Reader(2,hex(scope.readerKeyId)))),trustedNow())
    }
    @Synchronized override fun verifiedPreparation(evidence:ByteArray):ConversationCaptureScope {
        check(MessageDigest.isEqual(evidence,original));check(trustedNow() in 1 until parsed.expiresMs);context();return parsed.scope
    }
    private fun exchange(request:ByteArray,session:ConversationPhoneSession):ByteArray {
        check(wire.currentSession()==session);val reply=wire.exchange(request)
        check(reply.authenticatedSession==session && wire.currentSession()==session);context();return reply.bytes
    }
    /** Called only by the shared presentation domain after it consumes exact affirmative phone choice. */
    @Synchronized fun install(request:ConversationRecoveryRequest):ByteArray {
        accepted=null;acceptedChallenge=null
        check(request.intervalId==parsed.scope.intervalId);verifiedPreparation(original)
        val session=checkNotNull(wire.currentSession());val nonce=UUID.randomUUID()
        val approved=signExisting(ConversationActivationCodec.APPROVE_DOMAIN,original.copyOf(),context().signerPoint)
        val approval=ConversationChannelCodec.parseApprovalReply(exchange(ConversationChannelCodec.activationRequest(session,6,nonce,original,approved),session),session)
        check(approval.first==nonce && approval.second==parsed.scope);verifiedPreparation(original)
        val installed=signExisting(ConversationActivationCodec.INSTALL_DOMAIN,original.copyOf(),context().signerPoint)
        val challenge=UUID.fromString(request.challenge)
        val evidence=exchange(ConversationChannelCodec.activationRequest(session,8,challenge,original,installed),session)
        val lease=ConversationChannelCodec.parseLeaseReply(evidence,session)
        check(lease.first==challenge && lease.second==parsed.scope);verifiedPreparation(original)
        accepted=evidence.copyOf();acceptedChallenge=request.challenge;return evidence.copyOf()
    }
    @Synchronized override fun verifiedActiveLease(scope:ConversationCaptureScope,challenge:String,evidence:ByteArray):Long {
        check(scope==parsed.scope && challenge==acceptedChallenge && accepted!=null && MessageDigest.isEqual(accepted,evidence))
        context();val lease=ConversationChannelCodec.parseLeaseReply(evidence,checkNotNull(wire.currentSession()))
        check(lease.first.toString()==challenge && lease.second==scope);return lease.third
    }
    @Synchronized fun close(){accepted?.fill(0);accepted=null;acceptedChallenge=null;original.fill(0)}
}
