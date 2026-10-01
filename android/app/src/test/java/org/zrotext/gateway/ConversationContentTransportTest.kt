// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Test
import org.junit.Assert.*

class ConversationContentTransportTest {
    private fun id()=UUID.randomUUID().toString()
    private val scope=ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),"11".repeat(32),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private var session:ConversationPhoneSession?=ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),1,2,"55".repeat(32))
    private val capture=ConversationCapturedBody(scope,id(),1000,10,"synthetic")
    private val envelope=ByteArray(600){(it%251).toByte()}
    private var mutate:(ByteArray)->ByteArray={it}
    private var rotate=false
    private var previous:ByteArray?=null
    private var replay=false
    private val wire=object:ConversationAuthenticatedWire {
        override fun currentSession()=session
        override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
            val current=checkNotNull(session)
            val raw=when(request[5].toInt()) {
                12->{val (nonce,selected,packet)=ConversationChannelCodec.parseCaptureRequest(request,current)
                    assertEquals(scope,selected);assertArrayEquals(envelope,packet)
                    ConversationChannelCodec.captureReply(current,nonce,UUID.fromString(capture.captureId),Draft02OutboundPreparation.hash(packet),false)}
                14->{val (nonce,selected,message)=ConversationChannelCodec.parseDeliveryRequest(request,current)
                    assertEquals(scope,selected);assertTrue(message!=UUID(0,0))
                    ConversationChannelCodec.deliveryReply(current,nonce,envelope)}
                else->error("Unexpected content frame")
            }
            val reply=if(replay)checkNotNull(previous) else raw.also {previous=it.copyOf()}
            if(rotate)session=current.copy(connectionEpoch=2)
            return ConversationAuthenticatedWire.Reply(current,mutate(reply.copyOf()))
        }
    }
    private val transport=ConversationContentTransport(wire)
    @Test fun exactCommittedAckAndConfirmedPacketUseCurrentAuthenticatedSession() {
        val ack=transport.upload(capture,envelope);assertEquals(capture.captureId,ack.event.toString());assertFalse(ack.created)
        assertArrayEquals(envelope,transport.confirmed(scope,id()))
    }
    @Test fun captureRejectsDifferentEventDigestAndNoncanonicalCreatedByte() {
        for(offset in listOf(118,134,166)) {
            mutate={it.also {bytes->bytes[offset]=if(offset==166)2 else (bytes[offset].toInt() xor 1).toByte()}}
            assertThrows(Exception::class.java){transport.upload(capture,envelope)}
        }
    }
    @Test fun replayedCaptureOrDeliveryReplyCannotAcknowledgeFreshNonce() {
        transport.upload(capture,envelope);replay=true
        assertThrows(IllegalStateException::class.java){transport.upload(capture,envelope)}
        replay=false;transport.confirmed(scope,id());replay=true
        assertThrows(IllegalStateException::class.java){transport.confirmed(scope,id())}
    }
    @Test fun connectionRotationDuringExchangeRejectsContent() {
        rotate=true;assertThrows(IllegalStateException::class.java){transport.upload(capture,envelope)}
    }
    @Test fun deliveryRejectsHeaderTamperLengthTamperAndTrailingBytes() {
        for(offset in listOf(6,53,118)) {
            mutate={it.also {bytes->bytes[offset]=(bytes[offset].toInt() xor 1).toByte()}}
            assertThrows(Exception::class.java){transport.confirmed(scope,id())}
        }
        mutate={it+byteArrayOf(0)}
        assertThrows(IllegalArgumentException::class.java){transport.confirmed(scope,id())}
    }
    @Test fun captureRejectsTruncationAndDeliveryCannotSelectForeignAccount() {
        val request=ConversationChannelCodec.captureRequest(session!!,UUID.randomUUID(),scope,envelope)
        for(size in listOf(0,117,request.size-1))
            assertThrows(Exception::class.java){ConversationChannelCodec.parseCaptureRequest(request.copyOf(size),session!!)}
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.deliveryRequest(session!!,UUID.randomUUID(),scope.copy(accountId=id()),UUID.randomUUID())}
    }
}
