// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.file.Files
import java.nio.file.Paths
import java.util.UUID
import java.util.concurrent.Executor
import org.json.JSONObject
import org.junit.Assert.*
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.*
import android.os.*
import android.view.accessibility.AccessibilityNodeInfo
import java.util.concurrent.TimeUnit
import org.junit.Test
import org.junit.runner.RunWith

/** Authenticated runtime assembly; ephemeral loopback fixture keys, no carrier dispatch. */
@RunWith(AndroidJUnit4::class)
class ConversationProbeDeviceTest {
    private fun click(text:String) {
        val automation=InstrumentationRegistry.getInstrumentation().uiAutomation
        fun find(node:AccessibilityNodeInfo?):AccessibilityNodeInfo? {
            node?:return null
            if(node.text?.toString()==text) return node
            for(i in 0 until node.childCount) find(node.getChild(i))?.let {return it}
            return null
        }
        val deadline=SystemClock.uptimeMillis()+5000
        while(SystemClock.uptimeMillis()<deadline) {
            val found=find(automation.rootInActiveWindow)
            if(found!=null) {
                var target:AccessibilityNodeInfo?=found
                while(target!=null && !target.isClickable) target=target.parent
                if(target?.performAction(AccessibilityNodeInfo.ACTION_CLICK)==true) return
            }
            automation.rootInActiveWindow?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
            Thread.sleep(25)
        }
        error("Synthetic phone consent control unavailable")
    }
    @Test fun authenticatedActivationCaptureReadableBrowserReplyAndDurableStop() {
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        check(Build.HARDWARE in setOf("ranchu","goldfish") && context.packageName=="org.zrotext.gateway.conversationprobe")
        val file=checkNotNull(InstrumentationRegistry.getArguments().getString("fixturePath"))
        require(file.startsWith("/data/local/tmp/conversation-") && file.endsWith(".json"))
        val ready=JSONObject(java.io.File(file).readText(Charsets.UTF_8))
        val fixture=ConversationSimulatorFixture(ready)
        fun decode(value:String)=java.util.Base64.getDecoder().decode(value)
        val scenario=InstrumentationRegistry.getArguments().getString("scenario") ?: "roundtrip"
        require(scenario in setOf("roundtrip","stop-install","loss-install"))
        val installationReply=java.util.concurrent.CountDownLatch(1)
        val releaseInstallation=java.util.concurrent.CountDownLatch(1)
        val client=okhttp3.OkHttpClient()
        val opened=java.util.concurrent.CountDownLatch(1)
        val authenticated=java.util.concurrent.atomic.AtomicReference<ConversationPhoneSession?>(fixture.channelSession)
        lateinit var socketWire:ConversationSocketWire
        val runtimeRef=java.util.concurrent.atomic.AtomicReference<ConversationAuthenticatedRuntime?>()
        val wireRef=java.util.concurrent.atomic.AtomicReference<ConversationSocketWire?>()
        fun channelLost(){authenticated.set(null);wireRef.get()?.invalidate();runtimeRef.get()?.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST);opened.countDown()}
        val socket=client.newWebSocket(okhttp3.Request.Builder().url("ws://localhost:"+ready.getInt("port")+"/phone-channel")
            .header("x-zrotext-fixture-token",ready.getString("token")).build(),object:okhttp3.WebSocketListener(){
                override fun onOpen(socket:okhttp3.WebSocket,response:okhttp3.Response){opened.countDown()}
                override fun onMessage(socket:okhttp3.WebSocket,bytes:okio.ByteString){authenticated.get()?.let {socketWire.acceptReply(it,bytes.toByteArray())}}
                override fun onFailure(socket:okhttp3.WebSocket,error:Throwable,response:okhttp3.Response?){channelLost()}
                override fun onClosing(socket:okhttp3.WebSocket,code:Int,reason:String){channelLost();socket.close(code,reason)}
                override fun onClosed(socket:okhttp3.WebSocket,code:Int,reason:String){channelLost()}
            })
        socketWire=ConversationSocketWire(socket,{authenticated.get()});wireRef.set(socketWire)
        check(opened.await(10,TimeUnit.SECONDS) && authenticated.get()!=null)

        val db=Room.inMemoryDatabaseBuilder(context,ConversationCaptureDatabase::class.java).build()
        val sends=Room.inMemoryDatabaseBuilder(context,ConversationSendDatabase::class.java).build()
        val worker=java.util.concurrent.Executors.newSingleThreadExecutor()
        val delivery=java.util.concurrent.Executor {Handler(Looper.getMainLooper()).post(it)}
        val snapshots=java.util.Collections.synchronizedList(mutableListOf<ConversationPresentationSnapshot>())
        val scope=fixture.parsed.scope
        val start=System.nanoTime()
        var decisions=0;var installs=0;var submissions=0
        var permission=true
        var installedGate: () -> Boolean = { false }
        val bootstrapClock=ConversationTrustedClock({(System.nanoTime()-start)/1_000_000},socketWire::currentSession)
        ConversationAuthorityTransport(ConversationSerializedChannel(socketWire),bootstrapClock,socketWire::currentSession,{(System.nanoTime()-start)/1_000_000}).refreshTime()
        val trust=Draft02TrustStore(ProbeTrustStorage())
        val compare=Draft02RootComparison();val pin=decode(ready.getString("pin"))
        val display=compare.begin(pin,pin.copyOfRange(5,21))
        var root=checkNotNull(trust.enroll(compare.confirm(display.fingerprintHex,true)).snapshot)
        root=checkNotNull(trust.acceptManifest(root,decode(ready.getString("predecessor"))){checkNotNull(bootstrapClock.nowMs())}.snapshot)
        checkNotNull(trust.acceptManifest(root,decode(ready.getString("manifest"))){checkNotNull(bootstrapClock.nowMs())}.snapshot)
        val activationWire=object:ConversationAuthenticatedWire {
            override fun currentSession()=socketWire.currentSession()
            override fun exchange(request:ByteArray):ConversationAuthenticatedWire.Reply {
                val reply=socketWire.exchange(request)
                if(scenario!="roundtrip" && request[5].toInt()==8) {
                    installationReply.countDown() // Actual server installation already committed.
                    check(releaseInstallation.await(10,TimeUnit.SECONDS))
                }
                return reply
            }
        }
        val activation=ConversationPhoneActivation(fixture.statement,trust,activationWire,
            {checkNotNull(runtimeRef.get()?.trustedNowMs())},
            {domain,statement,point->check(statement.contentEquals(fixture.statement) && point.contentEquals(decode(ready.getString("signerPoint"))));decode(fixture.sign(domain))})
        val runtime=ConversationAuthenticatedRuntime(db.journal(),sends.sends(),activation,fixture.protection,
            socketWire,{(System.nanoTime()-start)/1_000_000},
            { selected,now -> check(permission && selected==scope && now<fixture.parsed.expiresMs) },
            { selected -> check(selected==scope);decisions++ },
            { request ->
                check(decisions==1)
                check(!installedGate())
                activation.install(request).also {installs++}
            },worker,delivery)
        runtimeRef.set(runtime)
        if(authenticated.get()==null)runtime.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST)
        installedGate = runtime::captureEligible
        runtime.presentation.observe { snapshots.add(it) }
        fun drain() {worker.submit {}.get(10,TimeUnit.SECONDS);instrumentation.waitForIdleSync()}
        ConversationProbeSession.runtime=runtime;ConversationProbeSession.scope=scope;ConversationProbeSession.token=ready.getString("token")
        val connected=java.util.concurrent.CountDownLatch(1)
        val connection=object:ServiceConnection {
            override fun onServiceConnected(name:ComponentName,binder:IBinder) {connected.countDown()}
            override fun onServiceDisconnected(name:ComponentName) {}
        }
        assertTrue(context.bindService(Intent(context,ConversationProbeService::class.java),connection,Context.BIND_AUTO_CREATE))
        assertTrue(connected.await(10,TimeUnit.SECONDS))
        try {
            val review=ConversationPhoneReview(UUID.randomUUID().toString(),scope.intervalId,scope.lineId,scope.bindingGeneration,
                scope.peer,ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",scope.disclosureDigest,30000)
            runtime.propose(review,fixture.statement);drain()
            assertEquals(ConversationPresentationPhase.AWAITING_PHONE_REVIEW,snapshots.last().phase)
            assertFalse(runtime.captureEligible());assertEquals(0,decisions);assertEquals(0,installs)
            context.startActivity(Intent(context,ConversationProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            instrumentation.waitForIdleSync()
            click("Agree and continue")
            if(scenario!="roundtrip") {
                assertTrue(installationReply.await(10,TimeUnit.SECONDS))
                instrumentation.waitForIdleSync()
                assertEquals(ConversationPresentationPhase.PREPARING,snapshots.last().phase)
                assertFalse(runtime.captureEligible())
                if(scenario=="stop-install") {
                    val current=snapshots.last()
                    runtime.presentation.requestStop(scope.intervalId,current.version)
                } else channelLost()
                assertFalse(runtime.captureEligible()) // Synchronous shared admission closure.
                releaseInstallation.countDown();drain()
                assertFalse(runtime.captureEligible())
                assertFalse(snapshots.any {it.phase==ConversationPresentationPhase.CONFIRMED_ACTIVE})
                assertEquals(0,db.journal().contentCount())
                if(scenario=="stop-install") {
                    assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,snapshots.last().phase)
                    assertFalse(fixture.command("lease",challenge=UUID.randomUUID()).getBoolean("ok"))
                } else assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,snapshots.last().close)
                return
            }
            drain()
            assertEquals(1,decisions);assertEquals(1,installs)
            assertEquals(ConversationPresentationPhase.CONFIRMED_ACTIVE,snapshots.last().phase)
            val token="01".repeat(32);val body="Synthetic authenticated inbound \u03A9\nSecond line"
            fun syntheticReceipt() {
                ConversationProbeSession.received=java.util.concurrent.CountDownLatch(1)
                context.sendBroadcast(Intent(ConversationProbeSession.ACTION).setPackage(context.packageName)
                    .putExtra("token",ConversationProbeSession.token).putExtra("body",body))
                assertTrue(ConversationProbeSession.received.await(10,TimeUnit.SECONDS))
            }
            syntheticReceipt();assertEquals(ConversationObservation.CAPTURED,ConversationProbeSession.observation.get())
            syntheticReceipt();assertEquals(ConversationObservation.DUPLICATE,ConversationProbeSession.observation.get())
            val captured=checkNotNull(runtime.retryCapture(token))
            val sealed=java.util.concurrent.atomic.AtomicReference<JSONObject?>()
            val uploaded=java.util.concurrent.atomic.AtomicBoolean(false)
            val uploadDone=java.util.concurrent.CountDownLatch(1)
            // API28 uses disposable fixture crypto; transfer and nonce/event/digest ACK validation
            // cross the production runtime/content channel, not the fixture capture HTTP command.
            runtime.uploadCapture(token,{ value,sequence ->
                assertEquals(captured,value)
                val envelope=fixture.envelope(value.body,value.captureId,value.firstObservedAtMs,sequence)
                sealed.set(envelope);decode(envelope.getString("envelope"))
            }) { accepted -> uploaded.set(accepted);uploadDone.countDown() }
            assertTrue(uploadDone.await(30,TimeUnit.SECONDS));assertTrue(uploaded.get())
            val encrypted=checkNotNull(sealed.get())
            val event=UUID.fromString(captured.captureId)
            val before=fixture.command("history",event=event)
            assertEquals(body,fixture.open(before.getString("envelope")).getString("opened"))
            assertTrue(fixture.command("renew").getBoolean("ok"))
            val after=fixture.command("history",event=event)
            assertEquals(before.getString("envelope"),after.getString("envelope"))
            val browser=fixture.browser(event,body)
            assertEquals(2,browser.getInt("signed"));assertEquals(1,browser.getInt("verified"));assertEquals(0,browser.getInt("midFlightSubmissions"))
            val packet=browser.getJSONObject("packet")
            val verifier=object:ConversationSendVerifier {
                override fun verify(evidence:ByteArray):VerifiedConversationSend {
                    val transferred=ConversationContentCrypto.unpackConfirmedEvidence(evidence)
                    val exact=JSONObject(packet.toString())
                    for((field,bytes) in listOf("envelope" to transferred.envelope,
                        "confirmation" to transferred.confirmation,"signature" to transferred.signature)) {
                        assertArrayEquals(decode(packet.getString(field)),bytes)
                        exact.put(field,fixture.b64(bytes))
                    }
                    return fixture.verifiedSend(exact.toString().toByteArray(Charsets.UTF_8),false)
                }
            }
            val transport=object:ConversationSendTransport {
                override fun submit(message:String,attempt:String,scope:ConversationCaptureScope,body:String):ConversationSubmission {
                    assertEquals("claimed",sends.sends().receipt(message)!!.state)
                    assertEquals("Synthetic browser reply \u03A9\nExact trailing spaces  ",body)
                    submissions++;return ConversationSubmission.UNKNOWN
                }
            }
            val sender=runtime.confirmedSender(verifier,transport)
            val received=java.util.concurrent.atomic.AtomicBoolean(false)
            val deliveryDone=java.util.concurrent.CountDownLatch(1)
            runtime.receiveConfirmed(scope,packet.getString("message"),sender) { accepted ->
                received.set(accepted);deliveryDone.countDown()
            }
            assertTrue(deliveryDone.await(30,TimeUnit.SECONDS));assertTrue(received.get())
            assertEquals(ConversationSubmission.UNKNOWN,sender.submitConfirmed(packet.getString("message")))
            assertEquals(1,submissions)
            assertThrows(IllegalStateException::class.java) {runtime.confirmedSender(verifier,transport).submitConfirmed(packet.getString("message"))}
            assertEquals(1,submissions)
            runtime.lifecycleLost(ConversationStopReason.OWNER_SESSION_LOST)
            assertFalse(runtime.captureEligible());drain()
            assertEquals(ConversationPresentationPhase.DURABLY_CLOSED,snapshots.last().phase)
            assertFalse(fixture.command("lease",challenge=UUID.randomUUID()).getBoolean("ok"))
            assertFalse(fixture.command("capture",data=encrypted.getString("envelope")).getBoolean("ok"))
            assertFalse(fixture.command("browser_authority").getBoolean("ok"))
            assertNull(runtime.retryCapture(token))

            val reconciled=java.util.concurrent.atomic.AtomicBoolean(false)
            runtime.reconcileClosed{reconciled.set(it)};drain()
            assertTrue(reconciled.get());assertFalse(runtime.captureEligible())
            // Stop retains eligible history; explicit withdrawal revokes access without claiming deletion.
            assertTrue(fixture.command("history",event=event).getBoolean("ok"))
            assertTrue(fixture.command("withdraw").getBoolean("ok"))
            assertFalse(fixture.command("history",event=event).getBoolean("ok"))
        } finally {
            releaseInstallation.countDown()
            context.unbindService(connection);instrumentation.waitForIdleSync();drain()
            runtimeRef.set(null);worker.shutdownNow();activation.close();db.close();sends.close();socketWire.invalidate();socket.close(1000,"synthetic complete")
            client.dispatcher.executorService.shutdown();client.connectionPool.evictAll();fixture.command("finish")
        }
    }

    /** Disposable fixture protection only; never selected by the ordinary root-store factory. */
    private class ProbeTrustStorage:Draft02TrustStore.Storage,Draft02TrustStore.Session {
        private var created=false;private var value:ByteArray?=null
        @Synchronized override fun <T> locked(action:Draft02TrustStore.Session.()->T)=action(this)
        override fun keyState()=if(created)Draft02TrustStore.KeyState.READY else Draft02TrustStore.KeyState.ABSENT
        override fun createKey(){check(!created);created=true}
        override fun read()=value?.copyOf()
        override fun seal(plaintext:ByteArray)=plaintext.copyOf()
        override fun open(ciphertext:ByteArray)=ciphertext.copyOf()
        override fun write(ciphertext:ByteArray,preCommit:()->Unit){preCommit();value=ciphertext.copyOf()}
    }
}
