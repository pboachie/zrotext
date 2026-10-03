// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.*
import java.util.UUID
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import org.json.JSONObject

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
    private fun <T> read(bytes:ByteArray, kind:Int, authenticated:ConversationPhoneSession, maximum:Int=1024, body:(DataInputStream,UUID)->T):T {
        require(bytes.size in 118..maximum)
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
        if(s.selectedReaders.isNotEmpty()) {
            require(s.disclosureDigest==ConversationActivationCodec.readerDisclosureDigest())
            writeByte(s.selectedReaders.size)
            s.selectedReaders.forEach { id(UUID.fromString(it.connectorId));id(UUID.fromString(it.readGrantId));hex(it.keyId) }
        }
    }
    private fun DataInputStream.scope():ConversationCaptureScope {
        val ids=List(6){id().toString()};val generation=positive();val trust=positive();val version=positive()
        val digests=List(4){hex()};val size=readUnsignedByte();require(size in 3..16)
        val peer=ByteArray(size).also(::readFully);require(peer.all{it.toInt() in 33..126})
        val selected=if(digests[0]==ConversationActivationCodec.readerDisclosureDigest()) {
            val count=readUnsignedByte();require(count in 1..6)
            List(count) { ConversationIntegrationReader(id().toString(),id().toString(),hex()) }
        } else emptyList()
        return ConversationCaptureScope(ids[0],ids[1],ids[2],generation,peer.toString(Charsets.US_ASCII),ids[3],ids[4],ids[5],digests[0],digests[1],trust,version,digests[2],digests[3],ConversationReaderSelection(selected))
    }
    fun timeRequest(r:ConversationTrustedClock.Request)=write(1,r.session,r.challenge){}
    fun proposalRequest(session:ConversationPhoneSession,challenge:UUID,interval:UUID)=
        write(16,session,challenge){it.id(interval)}
    fun parseProposalRequest(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,16,session,134){input,nonce->
        nonce to input.id()
    }
    fun proposalReply(session:ConversationPhoneSession,challenge:UUID,statement:ByteArray,manifest:ByteArray):ByteArray {
        require(statement.size in 380..1024 && manifest.size in 364..9751)
        return write(17,session,challenge){it.writeShort(statement.size);it.write(statement);it.writeShort(manifest.size);it.write(manifest)}
    }
    fun parseProposalReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,17,session,10897){input,nonce->
        val length=input.readUnsignedShort();require(length in 380..1024 && input.available()>=length+2)
        val statement=ByteArray(length).also(input::readFully)
        val manifestLength=input.readUnsignedShort();require(manifestLength in 364..9751 && input.available()==manifestLength)
        Triple(nonce,statement,ByteArray(manifestLength).also(input::readFully))
    }
    fun captureRequest(session:ConversationPhoneSession,challenge:UUID,scope:ConversationCaptureScope,envelope:ByteArray):ByteArray {
        val owned=envelope.copyOf();require(owned.size in 1..40000)
        return write(12,session,challenge){it.scope(bound(scope,session));it.writeInt(owned.size);it.write(owned)}
    }
    fun parseCaptureRequest(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,12,session,48000){input,nonce->
        val scope=bound(input.scope(),session);val length=input.readInt();require(length in 1..40000 && input.available()==length)
        Triple(nonce,scope,ByteArray(length).also(input::readFully))
    }
    fun captureReply(session:ConversationPhoneSession,challenge:UUID,event:UUID,digest:String,created:Boolean)=
        write(13,session,challenge){it.id(event);it.hex(digest);it.writeByte(if(created)1 else 0)}
    fun parseCaptureReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,13,session){input,nonce->
        val event=input.id();val digest=input.hex();val created=input.readUnsignedByte();require(created in 0..1)
        ConversationCaptureAck(nonce,event,digest,created==1)
    }
    fun deliveryRequest(session:ConversationPhoneSession,challenge:UUID,scope:ConversationCaptureScope,message:UUID)=
        write(14,session,challenge){it.scope(bound(scope,session));it.id(message)}
    fun parseDeliveryRequest(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,14,session){input,nonce->
        Triple(nonce,bound(input.scope(),session),input.id())
    }
    fun deliveryReply(session:ConversationPhoneSession,challenge:UUID,packet:ByteArray):ByteArray {
        require(packet.size in 1..40000)
        return write(15,session,challenge){it.writeInt(packet.size);it.write(packet)}
    }
    fun parseDeliveryReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,15,session,40122){input,nonce->
        val length=input.readInt();require(length in 1..40000 && input.available()==length)
        nonce to ByteArray(length).also(input::readFully)
    }
    fun executionRequest(session:ConversationPhoneSession, challenge:UUID, scope:ConversationCaptureScope,
                         message:UUID, attempt:UUID, envelopeDigest:ByteArray):ByteArray {
        require(envelopeDigest.size==32)
        val digest=envelopeDigest.copyOf()
        return write(18,session,challenge){it.scope(bound(scope,session));it.id(message);it.id(attempt);it.write(digest)}
    }
    fun parseExecutionRequest(bytes:ByteArray,session:ConversationPhoneSession):ConversationExecutionRequest {
        require(bytes.size in 434..832)
        return read(bytes,18,session,832){input,nonce->
            ConversationExecutionRequest(nonce,bound(input.scope(),session),input.id(),input.id(),ByteArray(32).also(input::readFully))
        }
    }
    fun executionReply(session:ConversationPhoneSession,challenge:UUID,json:ByteArray):ByteArray {
        require(json.size in 1..2048)
        val owned=json.copyOf();strictGrant(owned)
        return write(19,session,challenge){it.writeShort(owned.size);it.write(owned)}
    }
    fun parseExecutionReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,19,session,2168){input,nonce->
        val length=input.readUnsignedShort();require(length in 1..2048 && input.available()==length)
        nonce to strictGrant(ByteArray(length).also(input::readFully))
    }
    /** Existing grant semantics plus bounded strict JSON: no duplicate names or permissive tokens. */
    private fun strictGrant(bytes:ByteArray):SealedExecutionGrantValidator.Fields {
        val text=Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        val fields=SealedExecutionGrantFrame.parse(GrantJson(text).parse())
        require(fields.readerRole==1 && fields.segmentCount in 1..6)
        return fields
    }
    private class GrantJson(private val text:String) {
        private var at=0
        private fun space(){while(at<text.length && text[at] in " \t\r\n")at++}
        private fun expected(ch:Char){space();require(at<text.length && text[at++]==ch)}
        private fun string():String {
            space();val start=at;require(at<text.length && text[at++]=='"')
            while(at<text.length){
                val ch=text[at++]
                if(ch=='"')return JSONObject("{\"value\":"+text.substring(start,at)+"}").getString("value")
                require(ch.code>=32)
                if(ch=='\\'){
                    require(at<text.length)
                    when(text[at++]){
                        '"','\\','/','b','f','n','r','t'->Unit
                        'u'->{require(at+4<=text.length && text.substring(at,at+4).all{it in "0123456789abcdefABCDEF"});at+=4}
                        else->error("Grant JSON escape")
                    }
                }
            };error("Grant JSON string")
        }
        fun parse():JSONObject {
            val result=JSONObject();val names=mutableSetOf<String>();expected('{')
            while(true){
                space();require(at<text.length)
                if(text[at]=='}'){at++;break}
                val key=string();require(names.add(key));expected(':');space();require(at<text.length)
                val value:Any=if(text[at]=='"')string() else {
                    val start=at;while(at<text.length && text[at] in '0'..'9')at++
                    val number=text.substring(start,at)
                    require(number.matches(Regex("[1-9][0-9]*")))
                    number.toLong().also{require(it in 1..9007199254740991L)}
                }
                result.put(key,value);space();require(at<text.length)
                if(text[at]=='}'){at++;break}
                expected(',');space();require(at<text.length && text[at]!='}')
            }
            space();require(at==text.length)
            return result
        }
    }
    fun parseTimeRequest(bytes:ByteArray, session:ConversationPhoneSession)=read(bytes,1,session){_,nonce->ConversationTrustedClock.Request(nonce,session)}
    fun timeReply(r:ConversationTimeReply)=write(2,r.session,r.challenge){require(r.sentUtcMs>0);it.writeLong(r.sentUtcMs)}
    fun parseTimeReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,2,session){input,nonce->ConversationTimeReply(session,nonce,input.positive())}
    fun closeRequest(r:ConversationClosureRequest)=write(3,r.session,r.challenge){it.scope(bound(r.scope,r.session))}
    fun activationRequest(session:ConversationPhoneSession,kind:Int,challenge:UUID,statement:ByteArray,signature:ByteArray):ByteArray {
        require(kind==6 || kind==8);require(signature.size==64)
        val parsed=ConversationActivationCodec.decode(statement);bound(parsed.scope,session)
        require(parsed.connectionEpoch==session.connectionEpoch && parsed.deploymentEpoch==session.deploymentEpoch)
        return write(kind,session,challenge){it.writeShort(statement.size);it.write(statement);it.write(signature)}
    }
    fun leaseRequest(r:ConversationClosureRequest)=write(10,r.session,r.challenge){it.scope(bound(r.scope,r.session))}
    fun parseApprovalReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,7,session){input,nonce->nonce to bound(input.scope(),session)}
    fun parseLeaseReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,9,session){input,nonce->Triple(nonce,bound(input.scope(),session),input.positive().also{require(it<=60000)})}
    fun reconciliationRequest(r:ConversationClosureRequest, originalStatement:ByteArray):ByteArray {
        val owned=originalStatement.copyOf()
        require(ConversationActivationCodec.decode(owned).scope==bound(r.scope,r.session))
        return write(5,r.session,r.challenge){it.writeShort(owned.size);it.write(owned)}
    }

    fun parseCloseRequest(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,3,session){input,nonce->ConversationClosureRequest(session,nonce,bound(input.scope(),session))}
    fun closeReply(r:ConversationClosureReply)=write(4,r.session,r.challenge){it.scope(bound(r.scope,r.session));it.writeByte(if(r.durablyClosed)1 else 0)}
    fun parseCloseReply(bytes:ByteArray,session:ConversationPhoneSession)=read(bytes,4,session){input,nonce->
        val scope=bound(input.scope(),session);val state=input.readUnsignedByte();require(state in 0..1);ConversationClosureReply(session,nonce,scope,state==1)
    }
}
internal data class ConversationCaptureAck(val challenge:UUID,val event:UUID,val digest:String,val created:Boolean)
internal class ConversationExecutionRequest(val challenge:UUID,val scope:ConversationCaptureScope,
    val message:UUID,val attempt:UUID,envelopeDigest:ByteArray) {
    private val digest=envelopeDigest.copyOf()
    val envelopeDigest get()=digest.copyOf()
    override fun toString()="ConversationExecutionRequest(redacted)"
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
    override fun reconcile(request:ConversationClosureRequest, originalStatement:ByteArray)=ConversationChannelCodec.parseCloseReply(checked(request.session,ConversationChannelCodec.reconciliationRequest(request,originalStatement)),request.session)
}
