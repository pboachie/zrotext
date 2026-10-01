// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import okhttp3.WebSocket
import org.json.JSONObject

/** Only after existing enrolled-device authentication. Negotiation grants no consent. */
internal class ConversationSocketNegotiation(private val socket:WebSocket,
    private val identity:EvidenceIdentity, private val connectionEpoch:Long,
    private val elapsedMillis:()->Long, private val worker:java.util.concurrent.Executor,
    private val ready:(ConversationSocketWire,()->Unit)->Unit, lost:()->Unit) {
    private val session=AtomicReference<ConversationPhoneSession?>(null)
    private val challenge=UUID.randomUUID()
    private var requestedAt:Long?=null
    private var accepted=false
    private var closed=false
    val wire=ConversationSocketWire(socket,session::get)
    private val lifecycle=ConversationSocketLifecycle(wire,{session.set(null)},lost)
    @Synchronized fun start() {
        check(!closed && requestedAt==null && connectionEpoch>0)
        val now=elapsedMillis();check(now>=0);requestedAt=now
        check(socket.send(JSONObject().put("v",1).put("type","conversation_ready")
            .put("connection_epoch",connectionEpoch).put("challenge",challenge.toString()).toString()))
    }
    @Synchronized fun accept(frame:JSONObject) {
        check(!closed && !accepted)
        val start=checkNotNull(requestedAt);val now=elapsedMillis();check(now>=start && now-start<=5000)
        check(frame.keys().asSequence().toSet()==setOf("v","type","challenge","account_id","device_id","phone_session","connection_epoch","deployment_epoch","origin_hash"))
        fun integer(name:String):Long {val value=frame.opt(name);check(value is Int || value is Long);return (value as Number).toLong()}
        check(integer("v")==1L && frame.opt("type") is String && frame.getString("type")=="conversation_session")
        fun id(name:String):UUID { check(frame.opt(name) is String);val text=frame.getString(name);return UUID.fromString(text).also {check(it!=UUID(0,0) && it.toString()==text)} }
        check(id("challenge")==challenge && id("account_id").toString()==identity.accountId && id("device_id").toString()==identity.deviceId)
        check(integer("connection_epoch")==connectionEpoch)
        check(integer("deployment_epoch")>0)
        check(frame.opt("origin_hash") is String && frame.getString("origin_hash")==identity.originHash)
        val value=ConversationPhoneSession(UUID.fromString(identity.accountId),UUID.fromString(identity.deviceId),id("phone_session"),connectionEpoch,frame.getLong("deployment_epoch"),identity.originHash)
        accepted=true;session.set(value)
        val listener=Thread.currentThread()
        try {worker.execute {
            // Never block the socket listener that must deliver authenticated replies.
            val guard={synchronized(this){check(!closed && session.get()==value && wire.currentSession()==value)};Unit}
            try {check(Thread.currentThread()!==listener);guard();ready(wire,guard);guard()}
            catch(_:Exception){close()}
        }} catch(error:Exception){close();throw error}
    }
    fun binary(bytes:ByteArray):Boolean = session.get()?.let {wire.acceptReply(it,bytes)} ?: false
    fun radioAck(event:String,state:String,permitted:Boolean):ConversationRadioAckRoute =
        wire.acceptRadioAck(session.get(),event,state,permitted)
    @Synchronized fun close(){closed=true;lifecycle.lost()}
}

/** Explicit process-only future setup; no preference, key, permission or cold-start recovery. */
internal object ConversationSocketComposition {
    @Volatile private var factory:((WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation)?=null
    @Synchronized fun install(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation,enabled:Boolean=false):Boolean {
        if(!enabled || factory!=null)return false;factory=value;return true
    }
    fun create(socket:WebSocket,identity:EvidenceIdentity,epoch:Long)=factory?.invoke(socket,identity,epoch)
    @Synchronized fun clear(){factory=null;ConversationProcessMount.runtime.pause(ConversationStopReason.PHONE_SESSION_LOST)}
}
