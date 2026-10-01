// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.junit.Test
import org.junit.Assert.*

class ConversationSocketWireTest {
    private val phone=ConversationPhoneSession(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,"11".repeat(32))
    private var session:ConversationPhoneSession?=phone
    private lateinit var wire:ConversationSocketWire
    private var sent=0
    private var respond:(ByteArray)->Boolean={true}
    private val socket=object:WebSocket {
        override fun request()=Request.Builder().url("https://example.org").build()
        override fun queueSize()=0L
        override fun send(text:String)=false
        override fun send(bytes:ByteString):Boolean {sent++;return respond(bytes.toByteArray())}
        override fun close(code:Int,reason:String?)=true
        override fun cancel()=Unit
    }
    private fun request()=ConversationChannelCodec.timeRequest(ConversationTrustedClock.Request(UUID.randomUUID(),phone))
    @Test fun actualSocketAdapterAcceptsOnlyBoundNonceAndSession() {
        wire=ConversationSocketWire(socket,{session},10)
        respond={bytes->
            val r=ConversationChannelCodec.parseTimeRequest(bytes,phone)
            assertFalse(wire.acceptReply(phone,ConversationChannelCodec.timeReply(ConversationTimeReply(phone,UUID.randomUUID(),100000))))
            assertTrue(wire.acceptReply(phone,ConversationChannelCodec.timeReply(ConversationTimeReply(phone,r.challenge,100000))))
            true
        }
        assertEquals(100000,ConversationChannelCodec.parseTimeReply(wire.exchange(request()).bytes,phone).sentUtcMs)
        assertEquals(1,sent)
    }
    @Test fun timeoutAndSocketRefusalNeverReplay() {
        wire=ConversationSocketWire(socket,{session},1)
        assertThrows(IllegalStateException::class.java){wire.exchange(request())};assertEquals(1,sent)
        respond={false};assertThrows(IllegalStateException::class.java){wire.exchange(request())};assertEquals(2,sent)
    }
    @Test fun proposalBundleCrossesActualSocketOnlyWithExactChallengeAndBoundedFrame() {
        wire=ConversationSocketWire(socket,{session},10)
        val selected=UUID.randomUUID();val challenge=UUID.randomUUID()
        val original=ByteArray(380);val manifest=ByteArray(364)
        respond={bytes->
            assertEquals(selected,ConversationChannelCodec.parseProposalRequest(bytes,phone).second)
            assertFalse(wire.acceptReply(phone,ConversationChannelCodec.proposalReply(phone,UUID.randomUUID(),original,manifest)))
            val correct=ConversationChannelCodec.proposalReply(phone,challenge,original,manifest)
            assertFalse(wire.acceptReply(phone,correct+ByteArray(10898)))
            assertFalse(wire.acceptReply(phone,correct+byteArrayOf(0)))
            assertTrue(wire.acceptReply(phone,correct))
            assertFalse(wire.acceptReply(phone,correct))
            true
        }
        val response=wire.exchange(ConversationChannelCodec.proposalRequest(phone,challenge,selected))
        val parsed=ConversationChannelCodec.parseProposalReply(response.bytes,phone)
        assertEquals(challenge,parsed.first);assertArrayEquals(original,parsed.second);assertArrayEquals(manifest,parsed.third)
        assertEquals(1,sent)
    }
    @Test fun sessionRotationCannotAcceptOldReply() {
        wire=ConversationSocketWire(socket,{session},1)
        respond={bytes->val r=ConversationChannelCodec.parseTimeRequest(bytes,phone);session=phone.copy(connectionEpoch=2)
            assertFalse(wire.acceptReply(phone,ConversationChannelCodec.timeReply(ConversationTimeReply(phone,r.challenge,100000))));true}
        assertThrows(IllegalStateException::class.java){wire.exchange(request())}
        assertEquals(1,sent)
    }
    @Test fun invalidatedSocketCannotSubmitOrInstallLateReply() {
        wire=ConversationSocketWire(socket,{session},1);wire.invalidate()
        assertNull(wire.currentSession());assertThrows(IllegalStateException::class.java){wire.exchange(request())};assertEquals(0,sent)
        assertFalse(wire.acceptReply(phone,ConversationChannelCodec.timeReply(ConversationTimeReply(phone,UUID.randomUUID(),100000))))
    }

    @Test fun duplicateLossWaitsForFirstAdmissionFence() {
        wire=ConversationSocketWire(socket,{session},1)
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        val secondReturned=java.util.concurrent.CountDownLatch(1);val fenced=java.util.concurrent.atomic.AtomicBoolean(false)
        val lifecycle=ConversationSocketLifecycle(wire,{entered.countDown();release.await();session=null},{fenced.set(true)})
        val first=Thread{lifecycle.lost()};val second=Thread{lifecycle.lost();secondReturned.countDown()}
        try {
            first.start();assertTrue(entered.await(1,java.util.concurrent.TimeUnit.SECONDS));second.start()
            assertFalse(secondReturned.await(50,java.util.concurrent.TimeUnit.MILLISECONDS))
            release.countDown();first.join(1000);second.join(1000)
            assertEquals(0L,secondReturned.count);assertTrue(fenced.get());assertNull(wire.currentSession())
        } finally {release.countDown();first.join(1000);second.join(1000)}
    }
}
