// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONObject
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk=[28])
class ConversationRadioAckWireTest {
    private val phone=ConversationPhoneSession(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,1,"11".repeat(32))
    private var current:ConversationPhoneSession?=phone
    private lateinit var wire:ConversationSocketWire
    private var sends=0
    private var respond:(JSONObject)->Boolean={true}
    private val socket=object:WebSocket {
        override fun request()=Request.Builder().url("https://example.org").build()
        override fun queueSize()=0L
        override fun send(text:String):Boolean {sends++;return respond(JSONObject(text))}
        override fun send(bytes:ByteString)=false
        override fun close(code:Int,reason:String?)=true
        override fun cancel()=Unit
    }
    private fun event()=AlphaRadioEvent(UUID.randomUUID().toString(),UUID.randomUUID().toString(),
        UUID.randomUUID().toString(),"durable_submit_intent",1000,accountId=phone.account.toString(),
        deviceId=phone.device.toString(),originHash=phone.originHash)
    @Test fun exactWriterAckAcceptedOnceAndDuplicateNeverFallsThroughToAlpha() {
        wire=ConversationSocketWire(socket,{current},10)
        val event=event()
        respond={frame->
            assertEquals("radio_event",frame.getString("type"))
            assertEquals(event.eventId,frame.getString("event_id"))
            assertEquals(ConversationRadioAckRoute.NOT_OURS,wire.acceptRadioAck(phone,UUID.randomUUID().toString(),"submitting",true))
            assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,event.eventId,"submitted",true))
            assertEquals(ConversationRadioAckRoute.CONSUMED,wire.acceptRadioAck(phone,event.eventId,"submitting",true))
            assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,event.eventId,"submitting",true))
            true
        }
        assertTrue(wire.submitIntent(phone,event))
        assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,event.eventId,"submitting",true))
        assertThrows(IllegalStateException::class.java){wire.submitIntent(phone,event)}
        assertEquals(1,sends)
    }
    @Test fun timeoutAndSessionRotationNeverReplayOrAcceptLatePermission() {
        wire=ConversationSocketWire(socket,{current},1)
        val event=event()
        assertThrows(IllegalStateException::class.java){wire.submitIntent(phone,event)}
        assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,event.eventId,"submitting",true))
        assertThrows(IllegalStateException::class.java){wire.submitIntent(phone,event)}
        val next=event()
        respond={current=phone.copy(connectionEpoch=2)
            assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,next.eventId,"submitting",true));true}
        assertThrows(IllegalStateException::class.java){wire.submitIntent(phone,next)}
        assertEquals(2,sends)
    }
    @Test fun deniedAckSettlesFalseAndInvalidationAbsorbsOwnedLateAck() {
        wire=ConversationSocketWire(socket,{current},10)
        val event=event()
        respond={assertEquals(ConversationRadioAckRoute.CONSUMED,wire.acceptRadioAck(phone,event.eventId,"unknown",false));true}
        assertFalse(wire.submitIntent(phone,event))
        wire.invalidate()
        assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(phone,event.eventId,"submitting",true))
        current=null
        assertEquals(ConversationRadioAckRoute.KNOWN_STALE,wire.acceptRadioAck(null,event.eventId,"submitting",true))
        assertEquals(ConversationRadioAckRoute.NOT_OURS,wire.acceptRadioAck(null,UUID.randomUUID().toString(),"submitting",true))
        assertNull(wire.currentSession());assertEquals(1,sends)
    }
}
