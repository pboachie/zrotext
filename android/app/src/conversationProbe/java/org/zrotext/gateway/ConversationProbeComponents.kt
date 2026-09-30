// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Service
import android.content.*
import android.os.*
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/** Test-only APK. No telephony permission, SMS action or actual dispatch adapter exists. */
internal object ConversationProbeSession {
    lateinit var runtime: ConversationAuthenticatedRuntime
    lateinit var scope: ConversationCaptureScope
    lateinit var token: String
    val observation=AtomicReference<ConversationObservation>()
    @Volatile var received=CountDownLatch(1)
    const val ACTION="org.zrotext.gateway.conversationprobe.SYNTHETIC_RECEIPT"
}
class ConversationProbeActivity:ComponentActivity() {
    override fun onCreate(state:Bundle?) {
        super.onCreate(state)
        check(Build.HARDWARE in setOf("ranchu","goldfish") && packageName=="org.zrotext.gateway.conversationprobe")
        setContent {Column {Text("SIMULATOR ONLY: synthetic input and dispatch")
            FutureConversationPane(ConversationProbeSession.runtime.presentation,{_,_->"Synthetic line"})}}
    }
}
class ConversationProbeService:Service() {
    private val thread=HandlerThread("synthetic-receipt")
    private lateinit var ingress:ConversationServiceIngress
    private val receiver=object:BroadcastReceiver() {
        override fun onReceive(context:Context,intent:Intent) {
            if(intent.action!=ConversationProbeSession.ACTION || intent.getStringExtra("token")!=ConversationProbeSession.token) return
            val body=intent.getStringExtra("body")?:return
            if(body.length !in 1..32768) return
            val scope=ConversationProbeSession.scope
            try {ConversationProbeSession.observation.set(ingress.observeFirstReceipt(
                "01".repeat(32),scope.peer,scope.lineId,scope.bindingGeneration,body))}
            finally {ConversationProbeSession.received.countDown()}
        }
    }
    override fun onCreate() {
        super.onCreate()
        check(Build.HARDWARE in setOf("ranchu","goldfish") && packageName=="org.zrotext.gateway.conversationprobe")
        ingress=ConversationServiceIngress(ConversationProbeSession.runtime,{null},enabled=true)
        thread.start()
        val filter=IntentFilter(ConversationProbeSession.ACTION)
        if(Build.VERSION.SDK_INT>=33) registerReceiver(receiver,filter,null,Handler(thread.looper),Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(receiver,filter,null,Handler(thread.looper))
    }
    override fun onBind(intent:Intent):IBinder=Binder()
    override fun onDestroy() {
        unregisterReceiver(receiver)
        ingress.pause(ConversationStopReason.WORKER_SHUTDOWN)
        thread.quitSafely();super.onDestroy()
    }
}
