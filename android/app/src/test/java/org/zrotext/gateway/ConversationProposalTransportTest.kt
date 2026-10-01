// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECPrivateKeySpec
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class ConversationProposalTransportTest {
    private val vector=javaClass.classLoader!!.getResourceAsStream("candidate02-preparation.json")!!.bufferedReader().use{it.readText()}
    private fun field(name:String)=Regex("\"$name\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"").find(vector)!!.groupValues[1]
    private fun hex(value:String)=value.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
    private fun successor():ByteArray {
        val published=hex(field("manifest"))
        val unsigned=published.copyOfRange(0,published.size-64)
        ByteBuffer.wrap(unsigned).putLong(29,2)
        MessageDigest.getInstance("SHA-256").digest(published.copyOfRange(0,published.size-64)).copyInto(unsigned,53)
        // This public fixture's root is the P-256 generator (synthetic scalar one).
        // The test creates no user key, file, alias or credential.
        val point=hex(field("rootPin")).copyOfRange(29,94)
        val privateKey=KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger.ONE,DevicePayloadKeyStore.decodePoint(point).params))
        val signature=Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey);update("ZTSE/manifest/v2\u0000".toByteArray(Charsets.US_ASCII))
            update(ByteBuffer.allocate(4).putInt(unsigned.size).array());update(unsigned);sign()
        }
        return unsigned+Draft01SignaturePrimitive.canonicalRawFromDer(signature)
    }
    private val manifest=successor()
    private val account=UUID(ByteBuffer.wrap(manifest,5,8).long,ByteBuffer.wrap(manifest,13,8).long)
    private val device=UUID.randomUUID(); private val interval=UUID.randomUUID()
    private val bound=ConversationPhoneSession(account,device,UUID.randomUUID(),7,3,"11".repeat(32))
    private var current:ConversationPhoneSession?=bound
    private var packet=statement()
    private var change:(ByteArray)->ByteArray={it}
    private var previous:ByteArray?=null
    private var replay=false
    private var rotate=false
    private var calls=0
    private fun statement(owner:UUID=account,phone:UUID=device,selected:UUID=interval,
                          connection:Long=7,deployment:Long=3,site:String="fixture-site",instance:String="fixture-instance"):ByteArray {
        val output=ByteArrayOutputStream()
        DataOutputStream(output).use { out->
            fun id(value:UUID){out.writeLong(value.mostSignificantBits);out.writeLong(value.leastSignificantBits)}
            fun text(value:String){val bytes=value.toByteArray(Charsets.US_ASCII);out.writeByte(bytes.size);out.write(bytes)}
            out.write(byteArrayOf(90,84,67,65,1));id(owner);id(phone);id(UUID.randomUUID());out.writeLong(1)
            id(selected);id(UUID.randomUUID());id(UUID.randomUUID());out.write(ByteArray(32){1})
            out.writeLong(200000);text("+12");text("conversation-content-v1")
            out.write(MessageDigest.getInstance("SHA-256").digest(ConversationActivationCodec.DISCLOSURE.toByteArray(Charsets.UTF_8)))
            out.write(hex(field("archiveKeyId")));out.write(hex(field("deviceKeyId")));out.writeLong(1)
            out.writeLong(1);out.write(manifest.copyOfRange(53,85));out.writeLong(2)
            out.write(MessageDigest.getInstance("SHA-256").digest(manifest.copyOfRange(0,manifest.size-64)))
            out.writeLong(connection);out.writeLong(deployment);text(site);text(instance)
        }
        return output.toByteArray()
    }
    private val wire=object:ConversationAuthenticatedWire {
        override fun currentSession()=current
        override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
            calls++;assertEquals(134,request.size);assertEquals(16,request[5].toInt())
            val (nonce,selected)=ConversationChannelCodec.parseProposalRequest(request,bound)
            assertEquals(interval,selected)
            val reply=if(replay)checkNotNull(previous) else ConversationChannelCodec.proposalReply(bound,nonce,packet,manifest).also{previous=it}
            if(rotate)current=bound.copy(connectionEpoch=8)
            return ConversationAuthenticatedWire.Reply(bound,change(reply.copyOf()))
        }
    }
    private fun original()=ConversationProposalTransport(wire).proposal(interval.toString(),"fixture-site","fixture-instance")
    @Test fun exactOriginalIsRetrievedWithoutApprovalOrCaptureFrames() {
        val result=original();assertArrayEquals(packet,result.statement());assertArrayEquals(manifest,result.manifest());assertEquals(1,calls)
        result.statement().fill(0);result.manifest().fill(0);assertArrayEquals(packet,result.statement());assertArrayEquals(manifest,result.manifest())
    }
    @Test fun previousReplyCannotAnswerFreshRequest() {
        original();replay=true;assertThrows(IllegalStateException::class.java){original()}
    }
    @Test fun sessionRotationOrMissingSessionRejectsProposal() {
        rotate=true;assertThrows(IllegalStateException::class.java){original()}
        current=null;assertThrows(IllegalStateException::class.java){original()};assertEquals(1,calls)
    }
    @Test fun originalMustMatchEveryIndependentConnectionAndSelectionBinding() {
        for(value in listOf(statement(owner=UUID.randomUUID()),statement(phone=UUID.randomUUID()),
            statement(selected=UUID.randomUUID()),statement(connection=8),statement(deployment=4),
            statement(site="other-site"),statement(instance="other-instance"))) {
            packet=value;assertThrows(IllegalStateException::class.java){original()}
        }
    }
    @Test fun envelopeHeaderLengthAndTrailingBytesAreRejected() {
        for(offset in listOf(5,6,22,38,54,62,70,102,118)) {
            change={bytes->bytes.also{it[offset]=(it[offset].toInt() xor 1).toByte()}}
            assertThrows(Exception::class.java){original()}
        }
        change={it+byteArrayOf(0)};assertThrows(IllegalArgumentException::class.java){original()}
        change={it.copyOf(it.size-1)};assertThrows(Exception::class.java){original()}
    }
    @Test fun malformedCanonicalOriginalIsRejected() {
        packet=packet+byteArrayOf(0);assertThrows(IllegalArgumentException::class.java){original()}
    }
    @Test fun changedOrMissingSuccessorCannotMatchTheOriginalActivationDigest() {
        change={it.also{bytes->val offset=122+packet.size+100;bytes[offset]=(bytes[offset].toInt() xor 1).toByte()}}
        assertThrows(IllegalStateException::class.java){original()}
        change={it.copyOf(120+packet.size)};assertThrows(Exception::class.java){original()}
    }
    @Test fun realSignedVectorUsesUnsignedIdentityAndStillRequiresIndependentSignatureVerification() {
        val expected=Draft02OutboundPreparation.hash(manifest.copyOfRange(0,manifest.size-64))
        assertEquals(expected,ConversationActivationCodec.decode(original().statement()).scope.activationDigest)
        assertNotEquals(expected,Draft02OutboundPreparation.hash(manifest))
        val pin=hex(field("rootPin"))
        val trust=Draft02ManifestAuthority.Trust(manifest.copyOfRange(5,21),hex(field("rootFingerprint")),1,
            Draft02ManifestAuthority.Position.after(1,manifest.copyOfRange(53,85)))
        val now=Regex("\"now\"\\s*:\\s*(\\d+)").find(vector)!!.groupValues[1].toLong()
        assertEquals(expected,Draft02OutboundPreparation.hash(manifest.copyOfRange(0,manifest.size-64)))
        Draft02ManifestAuthority.verify(pin,manifest,trust,now)
        change={it.also{bytes->bytes[bytes.lastIndex]=(bytes.last().toInt() xor 1).toByte()}}
        val untrusted=original().manifest()
        assertThrows(Exception::class.java){Draft02ManifestAuthority.verify(pin,untrusted,trust,now)}
    }
    @Test fun selectorsAndRequestLengthsAreStrict() {
        val transport=ConversationProposalTransport(wire)
        for(selector in listOf(UUID(0,0).toString(),"1-1-1-1-1"))
            assertThrows(IllegalArgumentException::class.java){transport.proposal(selector,"fixture-site","fixture-instance")}
        assertEquals(0,calls)
        val request=ConversationChannelCodec.proposalRequest(bound,UUID.randomUUID(),interval)
        for(length in listOf(0,117,133)) assertThrows(Exception::class.java){ConversationChannelCodec.parseProposalRequest(request.copyOf(length),bound)}
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.parseProposalRequest(request+byteArrayOf(0),bound)}
    }
}
