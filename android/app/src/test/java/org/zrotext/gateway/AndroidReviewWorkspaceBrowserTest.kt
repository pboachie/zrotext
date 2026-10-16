// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Looper
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.LooperMode
import java.time.Duration
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28])
@LooperMode(LooperMode.Mode.PAUSED)
class AndroidReviewWorkspaceBrowserTest {
    private val origin="https://review.example.test"
    private fun browser(script:(String,(String)->Unit)->Unit)=AndroidReviewWorkspaceBrowser(
        RuntimeEnvironment.getApplication(),origin,{}, {it.onReceiveValue(null)},script)
    private fun id(source:String)=Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}").find(source)!!.value
    @Test fun onlyFixedOriginReviewResourcesAreReachable() {
        for(path in listOf("/review/root","/review/root.js","/review/single-flight.mjs","/v1/review/session/context"))
            assertTrue(AndroidReviewWorkspaceBrowser.allowed(origin,origin+path))
        for(url in listOf("http://review.example.test/review/root","https://other.example.test/review/root",
            origin+"/owner/devices",origin+"/v1/auth/session",origin+"/review/../owner/devices",
            origin+"/review/root#handoff","https://user@review.example.test/review/root","file:///review/root"))
            assertFalse(AndroidReviewWorkspaceBrowser.allowed(origin,url))
    }
    @Test fun pickerWaitsForExactPausedAckThenRequiresExactResume() {
        var settled=false;var accepted:Boolean?=null;var resumed=false
        val b=browser { source,done -> when {
            source.contains("requestPause")->done("true")
            source.contains("pauseStatus")->done("{\"version\":1,\"request_id\":\""+id(source)+"\",\"state\":\""+(if(settled)"paused" else "waiting")+"\"}")
            source.contains("resume")-> {resumed=true;done("true")}
        }}
        b.pauseForPicker{accepted=it};assertNull(accepted)
        settled=true;shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(100))
        assertEquals(true,accepted);b.background(true)
        var result=false;b.resumePicker{result=it};assertTrue(result);assertTrue(resumed);b.close()
    }
    @Test fun wrongRequestAckOrNoJavascriptResponseCannotHoldBrowserOpen() {
        var result:Boolean?=null
        val b=browser{source,done->if(source.contains("requestPause"))done("true")else done("{\"version\":1,\"request_id\":\""+UUID(0,7)+"\",\"state\":\"paused\"}")}
        b.pauseForPicker{result=it};assertEquals(false,result)
        var called=0
        val c=browser{_,_->}
        c.pauseForPicker{assertFalse(it);called++}
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(6));assertEquals(1,called)
        c.pauseForPicker{assertFalse(it);called++};assertEquals(2,called)
    }
    @Test fun unrelatedBackgroundOrExpiredPickerCannotResumeRenderingRealm() {
        val b=browser{source,done->if(source.contains("pauseStatus"))done("{\"version\":1,\"request_id\":\""+id(source)+"\",\"state\":\"paused\"}")else done("true")}
        b.pauseForPicker{assertTrue(it)}
        b.background(false)
        b.resumePicker{assertFalse(it)}
        val c=browser{source,done->if(source.contains("pauseStatus"))done("{\"version\":1,\"request_id\":\""+id(source)+"\",\"state\":\"paused\"}")else done("true")}
        c.pauseForPicker{assertTrue(it)}
        c.background(true)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(121))
        c.resumePicker{assertFalse(it)}
    }
}
