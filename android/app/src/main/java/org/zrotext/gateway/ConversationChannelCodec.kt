// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.*
import java.util.UUID

/** Proposed dormant channel frames. Authentication comes from the existing connection, not bytes.
 * Fixed-width network order, exact kinds/lengths, no Java modified UTF or local journal encoding.
 */
internal object ConversationChannelCodec {
    private val magic = byteArrayOf(90,84,67,87,1)
    private fun bound(scope:ConversationCaptureScope,session:ConversationPhoneSession):ConversationCaptureScope = scope.also {
        require(it.accountId==session.account.toString() && it.deviceId==session.device.toString())
    }
    private fun DataOutputStream.id(value: UUID) { require(value != UUID(0,0));writeLong(value.mostSignificantBits);writeLong(value.leastSignificantBits) }
    private fun DataInputStream.id() = UUID(readLong(),readLong()).also { require(it != UUID(0,0)) }
    private fun DataInputStream.positive() = readLong().also { require(it > 0) }
    private fun DataOutputStream.hex(value: String) {require(Regex("[0-9a-f]{64}").matches(value));write(value.chunked(2).map{it.toInt(16).toByte()}.toByteArray())}
    private fun DataInputStream.hex() = ByteArray(32).also(::readFully).joinToString(""){"%02x".format(it.toInt() and 255)}
    private fun write(kind: Int, session: ConversationPhoneSession, challenge: UUID, body:(DataOutputStream)->Unit):ByteArray {
        val bytes=ByteArrayOutputStream();DataOutputStream(bytes).use { out ->
            out.write(magic);out.writeByte(kind);out.id(session.account);out.id(session.device);out.id(session.session)
            out.writeLong(session.connectionEpoch);out.writeLong(session.deploymentEpoch);out.hex(session.originHash);out.id(challenge);body(out)
        };return bytes.toByteArray()
    }
    private fun <T> read(bytes:ByteArray, kind:Int, authenticated:ConversationPhoneSession, body:(DataInputStream,UUID)->T):T {
        require(bytes.size in 118..512)
        val input=DataInputStream(ByteArrayInputStream(bytes.copyOf()))
        return input.use {
            require(ByteArray(5).also(it::readFully).contentEquals(magic) && it.readUnsignedByte()==kind)
            val session=ConversationPhoneSession(it.id(),it.id(),it.id(),it.positive(),it.positive(),it.hex())
            require(session==authenticated)
            body(it,it.id()).also { _ -> require(it.available()==0) }
        }
    }
    private fun DataOutputStream.scope(s:ConversationCaptureScope) {
        listOf(s.accountId,s.deviceId,s.lineId,s.intervalId,s.receiptId,s.initiatingSessionId).forEach {id(UUID.fromString(it))}
        writeLong(s.bindingGeneration);writeLong(s.trustGeneration);writeLong(s.activationVersion)
        listOf(s.disclosureDigest,s.readerKeyId,s.activationDigest,s.transcriptDigest).forEach {hex(it)}
        val peer=s.peer.toByteArray(Charsets.US_ASCII);writeByte(peer.size);write(peer)
    }
    private fun DataInputStream.scope():ConversationCaptureScope {
        val ids=List(6){id().toString()};val generation=positive();val trust=positive();val version=positive()
        val digests=List(4){hex()};val size=readUnsignedByte();require(size in 3..16)
        val peer=ByteArray(size).also(::readFully);require(peer.all{it.toInt() in 33..126})
        return ConversationCaptureScope(ids[0],ids[1],ids[2],generation,peer.toString(Charsets.US_ASCII),ids[3],ids[4],ids[5],digests[0],digests[1],trust,version,digests[2],digests[3])
    }
    fun timeRequest(r:ConversationTrustedClock.Request)=write(1,r.session,r.challenge){}
    fun parseTimeRequest(bytes:ByteArray, session:ConversationPhoneSession)=read(bytes,1,session){_,nonce->ConversationTrustedClock.Request(nonce,session)}
    fun timeReply(r:ConversationTimeReply)=write(2,r.session,r.challenge){require(r.sentUtcMs>0);it.writeLong(r.sentUtcMs)}
    fun parseTimeReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,2,session){input,nonce->ConversationTimeReply(session,nonce,input.positive())}
    fun closeRequest(r:ConversationClosureRequest)=write(3,r.session,r.challenge){it.scope(bound(r.scope,r.session))}
    fun parseCloseRequest(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,3,session){input,nonce->ConversationClosureRequest(session,nonce,bound(input.scope(),session))}
    fun closeReply(r:ConversationClosureReply)=write(4,r.session,r.challenge){it.scope(bound(r.scope,r.session));it.writeByte(if(r.durablyClosed)1 else 0)}
    fun parseCloseReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,4,session){input,nonce->
        val scope=bound(input.scope(),session);val state=input.readUnsignedByte();require(state in 0..1);ConversationClosureReply(session,nonce,scope,state==1)
    }
}

/** Socket owner supplies out-of-band authenticated session for every response; no default exists. */
internal interface ConversationAuthenticatedWire {
    fun currentSession():ConversationPhoneSession?
    fun exchange(request:ByteArray):Reply
    class Reply(val authenticatedSession:ConversationPhoneSession, bytes:ByteArray) {
        val bytes=bytes.copyOf()
        override fun toString()="ConversationAuthenticatedReply(redacted)"
    }
}
internal class ConversationSerializedChannel(private val wire:ConversationAuthenticatedWire):ConversationAuthenticatedChannel {
    private fun checked(session:ConversationPhoneSession,bytes:ByteArray):ByteArray {
        check(wire.currentSession()==session)
        val reply=wire.exchange(bytes.copyOf())
        check(reply.authenticatedSession==session && wire.currentSession()==session)
        return reply.bytes.copyOf()
    }
    override fun time(request:ConversationTrustedClock.Request)=ConversationChannelCodec.parseTimeReply(checked(request.session,ConversationChannelCodec.timeRequest(request)),request.session)
    override fun close(request:ConversationClosureRequest)=ConversationChannelCodec.parseCloseReply(checked(request.session,ConversationChannelCodec.closeRequest(request)),request.session)
}
