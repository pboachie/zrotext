// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
@RunWith(RobolectricTestRunner::class) @Config(sdk=[28])
class ConversationSocketNegotiationTest {
    private val identity=EvidenceIdentity(UUID.randomUUID().toString(),UUID.randomUUID().toString(),"11".repeat(32))
    private var now=100L
    private var sent=""
    private var ready=0
    private var lost=0
    private val socket=object:okhttp3.WebSocket {
        override fun request()=okhttp3.Request.Builder().url("https://example.org").build()
        override fun queueSize()=0L
        override fun send(text:String):Boolean{sent=text;return true}
        override fun send(bytes:okio.ByteString)=true
        override fun close(code:Int,reason:String?)=true
        override fun cancel()=Unit
    }
    private val worker=java.util.concurrent.Executors.newSingleThreadExecutor()
    @org.junit.After fun cleanup(){worker.shutdownNow();ConversationSocketComposition.clear()}
    private fun drain(){worker.submit{}.get(5,java.util.concurrent.TimeUnit.SECONDS)}
    private fun connection()=ConversationSocketNegotiation(socket,identity,7,{now},worker,{_,guard->guard();ready++},{lost++})
    private fun reply()=JSONObject().put("v",1).put("type","conversation_session")
        .put("challenge",JSONObject(sent).getString("challenge")).put("account_id",identity.accountId).put("device_id",identity.deviceId)
        .put("phone_session",UUID.randomUUID().toString()).put("connection_epoch",7).put("deployment_epoch",3).put("origin_hash",identity.originHash)
    @Test fun authenticatedSelectionAndNonceBoundSessionThenSynchronousLoss(){
        val c=connection();assertNull(c.wire.currentSession());c.start();assertEquals(0,ready)
        c.accept(reply());drain();assertEquals(1,ready);assertEquals(7L,c.wire.currentSession()!!.connectionEpoch)
        assertThrows(IllegalStateException::class.java){c.accept(reply())}
        c.close();c.close();assertNull(c.wire.currentSession());assertEquals(1,lost)
    }
    @Test fun tamperedScopeNonceOrOriginCannotInstall(){
        for(field in listOf("account_id","device_id","challenge","origin_hash","connection_epoch","deployment_epoch")){
            val c=connection();c.start();val r=reply();r.put(field,when(field){"origin_hash"->"22".repeat(32);"connection_epoch"->8;"deployment_epoch"->0;else->UUID.randomUUID().toString()})
            assertThrows(IllegalStateException::class.java){c.accept(r)};assertNull(c.wire.currentSession());c.close()
        };assertEquals(0,ready)
    }
    @Test fun timeoutAndRollbackRefuseLateNegotiation(){for(time in listOf(99L,5101L)){val c=connection();now=100;c.start();now=time;assertThrows(IllegalStateException::class.java){c.accept(reply())};assertNull(c.wire.currentSession());c.close()}}
    @Test fun compositionIsAbsentUnlessExplicitlyInstalled(){ConversationSocketComposition.clear();assertNull(ConversationSocketComposition.create(socket,identity,7));assertFalse(ConversationSocketComposition.install({_,_,_->connection()}));assertNull(ConversationSocketComposition.create(socket,identity,7))}
    @Test fun heldReadyWorkCannotDelayLossOrMountAfterCancellation(){
        val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1)
        val c=ConversationSocketNegotiation(socket,identity,7,{now},worker,{_,guard->entered.countDown();release.await(5,java.util.concurrent.TimeUnit.SECONDS);guard();ready++},{lost++})
        try {c.start();c.accept(reply());assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS))
            c.close();assertNull(c.wire.currentSession());assertEquals(1,lost);release.countDown();drain();assertEquals(0,ready)
        } finally {release.countDown();c.close()}
    }
    @Test fun inlineReadyExecutorFailsClosed(){val c=ConversationSocketNegotiation(socket,identity,7,{now},java.util.concurrent.Executor{it.run()},{_,_->ready++},{lost++});c.start();c.accept(reply());assertNull(c.wire.currentSession());assertEquals(0,ready);assertEquals(1,lost)}
}
