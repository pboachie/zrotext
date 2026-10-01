// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk=[28])
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
    @Test fun executionRequestHasExactWidthsAndRejectsEveryTruncationOrSuffix() {
        val s=checkNotNull(session);val challenge=UUID.randomUUID();val message=UUID.randomUUID();val attempt=UUID.randomUUID()
        val bytes=ConversationChannelCodec.executionRequest(s,challenge,scope,message,attempt,ByteArray(32){7})
        assertEquals(434,bytes.size)
        val parsed=ConversationChannelCodec.parseExecutionRequest(bytes,s)
        assertEquals(scope,parsed.scope);assertEquals(challenge,parsed.challenge);assertEquals(message,parsed.message);assertEquals(attempt,parsed.attempt)
        for(size in 0 until bytes.size)assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionRequest(bytes.copyOf(size),s)}
        assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionRequest(bytes+byteArrayOf(0),s)}
        assertEquals(447,ConversationChannelCodec.executionRequest(s,challenge,scope.copy(peer="+123456789012345"),message,attempt,ByteArray(32)).size)
    }
    @Test fun strictExecutionGrantJsonRejectsDuplicatePermissiveUnsafeAndInvalidUtf8Frames() {
        val s=checkNotNull(session);val nonce=UUID.randomUUID()
        val json=ConversationGrantFixture.json(s,scope,UUID.randomUUID(),UUID.randomUUID(),ByteArray(32),ByteArray(32),ByteArray(32),100000).toString()
        val reply=ConversationChannelCodec.executionReply(s,nonce,json.toByteArray())
        assertEquals(nonce,ConversationChannelCodec.parseExecutionReply(reply,s).first)
        val invalid=listOf(json.dropLast(1)+",\"v\":1}",json.dropLast(1)+",}",json+" true",
            json.replace("\"v\":1","\"v\":1.0"),json.replace("\"v\":1","\"v\":01"),
            json.replace("\"v\":1","\"v\":true"),json.replace("\"v\":1","\"v\":9007199254740992"),
            json.replace("\"reader_role\":1","\"reader_role\":2"),json.replace("\"segment_count\":6","\"segment_count\":7"),
            json.dropLast(1)+",\"unknown\":1}",json.replace("\"v\"","'v'"))
        invalid.forEach{bad->assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionReply(ConversationGrantFixture.rawReply(s,nonce,bad.toByteArray()),s)}}
        assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionReply(ConversationGrantFixture.rawReply(s,nonce,byteArrayOf(0xc3.toByte(),0x28)),s)}
        for(size in 0 until reply.size)assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionReply(reply.copyOf(size),s)}
        assertThrows(Exception::class.java){ConversationChannelCodec.parseExecutionReply(reply+byteArrayOf(0),s)}
    }
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
