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
): ConversationAuthenticatedWire {
    init { require(timeoutMs in 1..5000) }
    private class Waiting(val session: ConversationPhoneSession, val challenge: UUID, val replyKind: Int) {
        val latch=CountDownLatch(1)
        var reply: ByteArray?=null
    }
    private val lock=Any()
    private var waiting:Waiting?=null
    private var closed=false
    override fun currentSession()=synchronized(lock) { if(closed) null else authenticatedSession() }
    override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
        val owned=request.copyOf()
        require(owned.size in 118..1144 && owned.copyOfRange(0,5).contentEquals(byteArrayOf(90,84,67,87,1)))
        val session=checkNotNull(currentSession())
        val kind=owned[5].toInt()
        val challenge=ByteBuffer.wrap(owned,102,16).let{UUID(it.long,it.long)}
        when(kind) {
            1 -> ConversationChannelCodec.parseTimeRequest(owned,session)
            3 -> ConversationChannelCodec.parseCloseRequest(owned,session)
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
        val pending=Waiting(session,challenge,if(kind==1)2 else 4)
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
        if(closed || session!=pending.session || authenticatedSession()!=session || bytes.size !in 118..512) return@synchronized false
        val challenge=runCatching {
            when(pending.replyKind) {
                2 -> ConversationChannelCodec.parseTimeReply(bytes,session).challenge
                else -> ConversationChannelCodec.parseCloseReply(bytes,session).challenge
            }
        }.getOrNull()
        if(challenge!=pending.challenge || pending.reply!=null) return@synchronized false
        pending.reply=bytes.copyOf();pending.latch.countDown();true
    }
    fun invalidate() = synchronized(lock) {closed=true;waiting?.latch?.countDown()}
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
