// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import org.junit.Test
import org.junit.Assert.*

class ConversationChannelCodecTest {
    private fun id()=UUID.randomUUID().toString()
    private val scope=ConversationCaptureScope(id(),id(),id(),1,"+12",id(),id(),id(),"11".repeat(32),"22".repeat(32),1,2,"33".repeat(32),"44".repeat(32))
    private var session:ConversationPhoneSession?=ConversationPhoneSession(UUID.fromString(scope.accountId),UUID.fromString(scope.deviceId),UUID.randomUUID(),1,2,"55".repeat(32))
    private var elapsed=10L
    private var mutate:(ByteArray)->ByteArray={it}
    private var previous:ByteArray?=null
    private var replay=false
    private var swapConnection=false
    private val wire=object:ConversationAuthenticatedWire {
        override fun currentSession()=session
        override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
            val authenticated=checkNotNull(session)
            val reply=when(request[5].toInt()) {
                1->{val parsed=ConversationChannelCodec.parseTimeRequest(request,authenticated);ConversationChannelCodec.timeReply(ConversationTimeReply(authenticated,parsed.challenge,100000))}
                3->{val parsed=ConversationChannelCodec.parseCloseRequest(request,authenticated);assertEquals(scope,parsed.scope);ConversationChannelCodec.closeReply(ConversationClosureReply(authenticated,parsed.challenge,parsed.scope,true))}
                else->error("Unexpected fixture kind")
            }
            val result=if(replay)checkNotNull(previous) else reply.also{previous=it.copyOf()}
            if(swapConnection)session=authenticated.copy(connectionEpoch=2)
            return ConversationAuthenticatedWire.Reply(authenticated,mutate(result.copyOf()))
        }
    }
    private val clock=ConversationTrustedClock({elapsed},{session})
    private val transport=ConversationAuthorityTransport(ConversationSerializedChannel(wire),clock,{session},{elapsed})
    @Test fun serializedTimeAndClosureIntegrateAuthenticatedAdapter() {transport.refreshTime();assertEquals(100000L,clock.nowMs());transport.close(scope)}
    @Test fun frameKindsAndNetworkOrderHaveExactWidths() {
        val request=ConversationTrustedClock.Request(UUID.randomUUID(),session!!)
        val bytes=ConversationChannelCodec.timeRequest(request)
        assertEquals(118,bytes.size);assertArrayEquals(byteArrayOf(90,84,67,87,1,1),bytes.copyOfRange(0,6))
        assertEquals(request,ConversationChannelCodec.parseTimeRequest(bytes,session!!))
        val close=ConversationClosureRequest(session!!,request.challenge,scope)
        assertEquals(close,ConversationChannelCodec.parseCloseRequest(ConversationChannelCodec.closeRequest(close),session!!))
    }
    @Test fun everyTruncationAndTrailingBytesReject() {
        val bytes=ConversationChannelCodec.closeReply(ConversationClosureReply(session!!,UUID.randomUUID(),scope,true))
        for(size in 0 until bytes.size)assertThrows(Exception::class.java){ConversationChannelCodec.parseCloseReply(bytes.copyOf(size),session!!)}
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.parseCloseReply(bytes+byteArrayOf(0),session!!)}
    }
    @Test fun wrongKindRejectsTimeReply() {mutate={it.also{b->b[5]=4}};assertThrows(IllegalArgumentException::class.java){transport.refreshTime()};assertNull(clock.nowMs())}
    @Test fun serializedSessionTamperRejects() {mutate={it.also{b->b[53]=(b[53].toInt() xor 1).toByte()}};assertThrows(IllegalArgumentException::class.java){transport.refreshTime()};assertNull(clock.nowMs())}
    @Test fun outOfBandConnectionChangeRejectsReply() {swapConnection=true;assertThrows(IllegalStateException::class.java){transport.refreshTime()};assertNull(clock.nowMs())}
    @Test fun replayedTimeReplyCannotRenewAnchor() {transport.refreshTime();replay=true;assertThrows(IllegalArgumentException::class.java){transport.refreshTime()};assertNull(clock.nowMs())}
    @Test fun replayedClosureCannotAcknowledgeNewRequest() {transport.close(scope);replay=true;assertThrows(IllegalStateException::class.java){transport.close(scope)}}
    @Test fun changedReaderCannotAcknowledgeExactScope() {
        mutate={bytes->val r=ConversationChannelCodec.parseCloseReply(bytes,session!!);ConversationChannelCodec.closeReply(r.copy(scope=r.scope.copy(readerKeyId="66".repeat(32))))}
        assertThrows(IllegalStateException::class.java){transport.close(scope)}
    }
    @Test fun changedOwnerSessionCannotAcknowledgeExactScope() {
        mutate={bytes->val r=ConversationChannelCodec.parseCloseReply(bytes,session!!);ConversationChannelCodec.closeReply(r.copy(scope=r.scope.copy(initiatingSessionId=id())))}
        assertThrows(IllegalStateException::class.java){transport.close(scope)}
    }
    @Test fun uncommittedOrNoncanonicalClosureReplyRejects() {
        mutate={it.also{b->b[b.lastIndex]=0}};assertThrows(IllegalStateException::class.java){transport.close(scope)}
        mutate={it.also{b->b[b.lastIndex]=2}};assertThrows(IllegalArgumentException::class.java){transport.close(scope)}
    }
    @Test fun closureCannotUseDifferentAuthenticatedAccount() {
        val bytes=ConversationChannelCodec.closeRequest(ConversationClosureRequest(session!!,UUID.randomUUID(),scope))
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.parseCloseRequest(bytes,session!!.copy(account=UUID.randomUUID()))}
    }
    @Test fun embeddedClosureAccountAndDeviceMustMatchAuthenticatedSession() {
        val request=ConversationChannelCodec.closeRequest(ConversationClosureRequest(session!!,UUID.randomUUID(),scope))
        val reply=ConversationChannelCodec.closeReply(ConversationClosureReply(session!!,UUID.randomUUID(),scope,true))
        for(offset in listOf(118,134)) {
            val changed=request.copyOf();changed[offset]=(changed[offset].toInt() xor 1).toByte()
            assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.parseCloseRequest(changed,session!!)}
            val changedReply=reply.copyOf();changedReply[offset]=(changedReply[offset].toInt() xor 1).toByte()
            assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.parseCloseReply(changedReply,session!!)}
        }
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.closeRequest(ConversationClosureRequest(session!!,UUID.randomUUID(),scope.copy(accountId=id())))}
        assertThrows(IllegalArgumentException::class.java){ConversationChannelCodec.closeReply(ConversationClosureReply(session!!,UUID.randomUUID(),scope.copy(deviceId=id()),true))}
    }
}
