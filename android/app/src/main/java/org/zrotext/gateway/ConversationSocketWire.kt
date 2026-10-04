// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.WebSocket
import okio.ByteString.Companion.toByteString

/** Owned by an already authenticated socket. Construction never negotiates or trusts payload identity.
 * One bounded request, no replay, no HTTP fallback. Feed replies only from this socket's binary callback.
 * Socket loss/session rotation must invalidate this adapter and synchronously close the runtime mount.
 */
internal class ConversationSocketWire(private val socket: WebSocket,
    private val authenticatedSession: () -> ConversationPhoneSession?, private val timeoutMs: Long = 5000
): ConversationAuthenticatedWire, ConversationRadioIntentWire {
    init { require(timeoutMs in 1..5000) }
    private class Waiting(val session: ConversationPhoneSession, val challenge: UUID, val replyKind: Int) {
        val latch=CountDownLatch(1)
        var reply: ByteArray?=null
    }
    private val lock=Any()
    private var waiting:Waiting?=null
    private var closed=false
    private class RadioWaiting(val session:ConversationPhoneSession, val event:String) {
        val latch=CountDownLatch(1)
        var permitted:Boolean?=null
    }
    private var radioWaiting:RadioWaiting?=null
    private val radioAttempted=mutableSetOf<String>()
    override fun currentSession()=synchronized(lock) { if(closed) null else authenticatedSession() }
    override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
        val owned=request.copyOf()
        require(owned.size in 118..48000 && owned.copyOfRange(0,5).contentEquals(byteArrayOf(90,84,67,87,1)))
        val session=checkNotNull(currentSession())
        val kind=owned[5].toInt()
        val challenge=ByteBuffer.wrap(owned,102,16).let{UUID(it.long,it.long)}
        when(kind) {
            12 -> ConversationChannelCodec.parseCaptureRequest(owned,session)
            14 -> ConversationChannelCodec.parseDeliveryRequest(owned,session)
            16 -> ConversationChannelCodec.parseProposalRequest(owned,session)
            18 -> ConversationChannelCodec.parseExecutionRequest(owned,session)
            1 -> ConversationChannelCodec.parseTimeRequest(owned,session)
            3 -> ConversationChannelCodec.parseCloseRequest(owned,session)
            6,8 -> {
                require(owned.size>=564);val length=ByteBuffer.wrap(owned,118,2).short.toInt() and 65535
                require(length in 380..1024 && owned.size==184+length)
                require(ConversationChannelCodec.activationRequest(session,kind,challenge,owned.copyOfRange(120,120+length),owned.copyOfRange(120+length,owned.size)).contentEquals(owned))
            }
            10 -> require(ConversationChannelCodec.leaseRequest(ConversationClosureRequest(session,challenge,
                ConversationChannelCodec.parseCloseRequest(owned.copyOf().also{it[5]=3},session).scope)).contentEquals(owned))
            5 -> {
                require(owned.size>=120)
                val length=ByteBuffer.wrap(owned,118,2).short.toInt() and 65535
                require(length in 380..1024 && owned.size==120+length)
                val scope=ConversationActivationCodec.decode(owned.copyOfRange(120,owned.size)).scope
                val expected=ConversationChannelCodec.reconciliationRequest(ConversationClosureRequest(session,challenge,scope),owned.copyOfRange(120,owned.size))
                require(expected.contentEquals(owned))
            }
            else -> error("Conversation request kind unavailable")
        }
        val pending=Waiting(session,challenge,when(kind){1->2;6->7;8,10->9;12->13;14->15;16->17;18->19;else->4})
        synchronized(lock) {check(!closed && waiting==null && authenticatedSession()==session);waiting=pending}
        try {
            check(socket.send(owned.toByteString())) { "Socket submission refused" }
            check(pending.latch.await(timeoutMs,TimeUnit.MILLISECONDS)) { "Authenticated reply unavailable" }
            return synchronized(lock) {
                check(!closed && authenticatedSession()==session)
                ConversationAuthenticatedWire.Reply(session,checkNotNull(pending.reply))
            }
        } finally { synchronized(lock) { if(waiting===pending) waiting=null };owned.fill(0) }
    }
    fun acceptReply(session:ConversationPhoneSession, bytes:ByteArray):Boolean = synchronized(lock) {
        val pending=waiting ?: return@synchronized false
        val maximum=when(pending.replyKind){15->40122;17->10897;19->2168;else->1024}
        if(closed || session!=pending.session || authenticatedSession()!=session || bytes.size !in 118..maximum) return@synchronized false
        val challenge=runCatching {
            when(pending.replyKind) {
                2 -> ConversationChannelCodec.parseTimeReply(bytes,session).challenge
                7 -> ConversationChannelCodec.parseApprovalReply(bytes,session).first
                9 -> ConversationChannelCodec.parseLeaseReply(bytes,session).first
                13 -> ConversationChannelCodec.parseCaptureReply(bytes,session).challenge
                15 -> ConversationChannelCodec.parseDeliveryReply(bytes,session).first
                17 -> ConversationChannelCodec.parseProposalReply(bytes,session).first
                19 -> ConversationChannelCodec.parseExecutionReply(bytes,session).first
                else -> ConversationChannelCodec.parseCloseReply(bytes,session).challenge
            }
        }.getOrNull()
        if(challenge!=pending.challenge || pending.reply!=null) return@synchronized false
        pending.reply=bytes.copyOf();pending.latch.countDown();true
    }
    override fun submitIntent(session:ConversationPhoneSession,event:AlphaRadioEvent):Boolean {
        require(event.evidence=="durable_submit_intent" && event.segmentIndex==null && event.segmentCount==null &&
            event.acknowledgedAtMs==null && event.quarantinedAtMs==null && event.observedAtMs>0)
        require(event.accountId==session.account.toString() && event.deviceId==session.device.toString() &&
            event.originHash==session.originHash)
        listOf(event.eventId,event.messageId,event.attemptId).forEach {
            require(UUID.fromString(it)!=UUID(0,0) && UUID.fromString(it).toString()==it)
        }
        val pending=RadioWaiting(session,event.eventId)
        synchronized(lock) {
            check(!closed && authenticatedSession()==session && radioWaiting==null &&
                radioAttempted.size<1024 && radioAttempted.add(event.eventId))
            radioWaiting=pending
        }
        try {
            val frame=org.json.JSONObject().put("v",1).put("type","radio_event")
                .put("connection_epoch",session.connectionEpoch).put("event_id",event.eventId)
                .put("message_id",event.messageId).put("attempt_id",event.attemptId)
                .put("evidence",event.evidence).put("observed_at_ms",event.observedAtMs)
            check(socket.send(frame.toString()))
            check(pending.latch.await(timeoutMs,TimeUnit.MILLISECONDS))
            return synchronized(lock) {
                check(!closed && authenticatedSession()==session)
                checkNotNull(pending.permitted)
            }
        } finally { synchronized(lock) { if(radioWaiting===pending)radioWaiting=null } }
    }
    /** Feed only an already strictly parsed ACK from this socket's current authenticated listener. */
    fun acceptRadioAck(session:ConversationPhoneSession?,event:String,state:String,permitted:Boolean):ConversationRadioAckRoute = synchronized(lock) {
        if(event !in radioAttempted)return@synchronized ConversationRadioAckRoute.NOT_OURS
        val pending=radioWaiting ?: return@synchronized ConversationRadioAckRoute.KNOWN_STALE
        if(closed || authenticatedSession()!=session || pending.session!=session || pending.event!=event ||
            pending.permitted!=null || (permitted && state!="submitting"))
            return@synchronized ConversationRadioAckRoute.KNOWN_STALE
        pending.permitted=permitted;pending.latch.countDown();ConversationRadioAckRoute.CONSUMED
    }
    fun invalidate() = synchronized(lock) {closed=true;waiting?.latch?.countDown();radioWaiting?.latch?.countDown()}
}

/** Socket listener owns this bridge. Every graceful/failure path must invoke lost synchronously. */
internal class ConversationSocketLifecycle(private val wire:ConversationSocketWire,
    private val invalidateSession:()->Unit, private val closeAdmission:()->Unit) {
    private val closed=java.util.concurrent.atomic.AtomicBoolean(false)
    @Synchronized fun lost() {
        if(!closed.compareAndSet(false,true))return
        try {invalidateSession()} finally {try {wire.invalidate()} finally {closeAdmission()}}
    }
}
