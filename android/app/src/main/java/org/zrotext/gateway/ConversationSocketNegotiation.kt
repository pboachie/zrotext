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
    /** Cancellation and enqueue share this monitor; a closed candidate cannot start later. */
    @Synchronized internal fun startIfCurrent(requireCurrent:()->Unit) { requireCurrent();start() }
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
    @Volatile private var authenticatedHost:AuthenticatedHost?=null
    private var factoryAttempted=false // One explicit installer cannot silently attach again after reconnect.
    fun install(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation,enabled:Boolean=false):Boolean =
        installOwned(value,enabled)!=null
    /** Atomically pair either registration order; invoke scheduler/provider outside this registry. */
    private fun pairLocked():(()->Unit)? {
        val host=authenticatedHost?:return null
        val creator=factory?:return null
        if(factoryAttempted)return null
        if(!host.claim(creator))return null
        factoryAttempted=true
        return {host.schedule(creator)}
    }
    /** Closing an obsolete installer cannot clear a later process-only owner. */
    fun installOwned(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation,
        enabled:Boolean=false):AutoCloseable? {
        val attach=synchronized(this) {
            if(!enabled || factory!=null || authenticatedHost?.attempted==true)return null
            factory=value;factoryAttempted=false;pairLocked()
        }
        attach?.invoke()
        return AutoCloseable {
            val host=synchronized(this) {if(factory===value){factory=null;authenticatedHost}else null}
            host?.cancelFactory(value)
        }
    }
    /** Only the proof-authenticated ordinary service registers an ACTIVE, immutable socket epoch. */
    fun registerAuthenticatedHost(socket:WebSocket,identity:EvidenceIdentity,epoch:Long,scheduler:java.util.concurrent.Executor,
        requireCurrent:()->Unit,
        publishAndStart:(ConversationSocketNegotiation,()->Unit)->Boolean,
        unpublishOwned:(ConversationSocketNegotiation)->Unit):AutoCloseable {
        require(epoch>0)
        val host=AuthenticatedHost(socket,identity,epoch,scheduler,requireCurrent,publishAndStart,unpublishOwned)
        val attach=synchronized(this) {
            check(authenticatedHost==null)
            authenticatedHost=host;pairLocked()
        }
        attach?.invoke()
        return AutoCloseable {
            synchronized(this){if(authenticatedHost===host)authenticatedHost=null}
            host.close()
        }
    }
    private class AuthenticatedHost(private val socket:WebSocket,private val identity:EvidenceIdentity,private val epoch:Long,
        private val scheduler:java.util.concurrent.Executor,private val requireCurrent:()->Unit,
        private val publishAndStart:(ConversationSocketNegotiation,()->Unit)->Boolean,
        private val unpublishOwned:(ConversationSocketNegotiation)->Unit) {
        private val closed=java.util.concurrent.atomic.AtomicBoolean(false)
        private val assigned=AtomicReference<((WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation)?>(null)
        private val connection=AtomicReference<ConversationSocketNegotiation?>(null)
        var attempted=false;private set // Accessed only under the global registry monitor.
        fun claim(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation):Boolean {
            if(closed.get() || attempted)return false
            attempted=true;assigned.set(value);return true
        }
        private fun current(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation) {
            check(!closed.get() && assigned.get()===value && authenticatedHost===this && factory===value)
            requireCurrent()
            check(!closed.get() && assigned.get()===value && authenticatedHost===this && factory===value)
        }
        fun identitySnapshot(): EvidenceIdentity {
            check(!closed.get() && authenticatedHost === this)
            requireCurrent()
            check(!closed.get() && authenticatedHost === this)
            return identity.copy()
        }
        fun schedule(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation) {
            try {scheduler.execute {
                var candidate:ConversationSocketNegotiation?=null
                try {
                    current(value)
                    candidate=value(socket,identity,epoch)
                    current(value)
                    check(connection.compareAndSet(null,candidate))
                    check(publishAndStart(checkNotNull(candidate)){current(value)})
                    current(value)
                } catch(_:Exception) {
                    candidate?.let {connection.compareAndSet(it,null);try{it.close()}finally{unpublishOwned(it)}}
                }
            }} catch(_:Exception){cancelFactory(value)}
        }
        fun cancelFactory(value:(WebSocket,EvidenceIdentity,Long)->ConversationSocketNegotiation) {
            if(assigned.compareAndSet(value,null))closeConnection()
        }
        private fun closeConnection() {connection.getAndSet(null)?.let {try{it.close()}finally{unpublishOwned(it)}}}
        fun close(){closed.set(true);assigned.set(null);closeConnection()}
    }
    internal class AuthenticatedIdentitySnapshot internal constructor(val identity: EvidenceIdentity,
        private val current: () -> Unit) {
        fun requireCurrent() = current()
        override fun toString() = "ConversationAuthenticatedIdentity(redacted)"
    }
    /** Exact proof-host lifetime, not identity equality across replacement hosts. */
    fun currentAuthenticatedIdentity(): AuthenticatedIdentitySnapshot? {
        val host = authenticatedHost ?: return null
        return runCatching {
            val identity = host.identitySnapshot()
            AuthenticatedIdentitySnapshot(identity) { check(host.identitySnapshot() == identity) }
        }.getOrNull()
    }
    fun create(socket:WebSocket,identity:EvidenceIdentity,epoch:Long)=factory?.invoke(socket,identity,epoch)
    fun clear(){
        val old=synchronized(this){val creator=factory;factory=null;creator to authenticatedHost}
        old.first?.let {old.second?.cancelFactory(it)}
        ConversationProcessMount.runtime.pause(ConversationStopReason.PHONE_SESSION_LOST)
    }
}
