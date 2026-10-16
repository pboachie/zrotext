// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.webkit.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.ByteArrayInputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Fixed same-app isolated review page. JS coordination grants NO native authority.
 * No addJavascriptInterface, external browser, arbitrary navigation or secret handoff.
 */
internal class AndroidReviewWorkspaceBrowser(
    context: Context,
    private val origin: String,
    private val changed: () -> Unit,
    private val choosePublic: (ValueCallback<Array<Uri>>) -> Unit,
    private val script: ((String, (String) -> Unit) -> Unit)? = null
) : WebView(context) {
    private val retired=AtomicBoolean()
    private val main=Handler(Looper.getMainLooper())
    private var pauseId:String?=null
    private var pauseStarted=0L
    private var acked=false
    private var dormantDeadline=0L
    private var completion:((Boolean)->Unit)?=null
    private val poll=Runnable{pollPause()}
    private val pauseDeadline=Runnable{completePause(false)}
    private val expire=Runnable{close()}
    private fun currentPage()=url==origin+PAGE
    init {
        AndroidReviewWorkspaceOwnerContext.validateOrigin(origin)
        setWebContentsDebuggingEnabled(false)
        isSaveEnabled=false
        importantForAutofill=View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        settings.javaScriptEnabled=true
        settings.domStorageEnabled=false
        settings.allowFileAccess=false
        settings.allowContentAccess=false
        settings.mixedContentMode=WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.javaScriptCanOpenWindowsAutomatically=false
        settings.setSupportMultipleWindows(false)
        settings.safeBrowsingEnabled=true
        settings.cacheMode=WebSettings.LOAD_NO_CACHE
        CookieManager.getInstance().setAcceptThirdPartyCookies(this,false)
        setDownloadListener{_,_,_,_,_->changed()}
        webChromeClient=object:WebChromeClient(){
            override fun onPermissionRequest(request:PermissionRequest){request.deny()}
            override fun onShowFileChooser(view:WebView,callback:ValueCallback<Array<Uri>>,params:FileChooserParams):Boolean{
                if(params.mode!=FileChooserParams.MODE_OPEN || params.isCaptureEnabled){callback.onReceiveValue(null);return true}
                pauseForPicker{accepted->if(accepted)choosePublic(callback)else callback.onReceiveValue(null)}
                return true
            }
        }
        webViewClient=object:WebViewClient(){
            override fun shouldOverrideUrlLoading(view:WebView,request:WebResourceRequest):Boolean {
                if(request.url.toString()==origin+PAGE && allowed(origin,request.url.toString()))return false
                changed();return true
            }
            override fun shouldInterceptRequest(view:WebView,request:WebResourceRequest):WebResourceResponse?{
                if(allowed(origin,request.url.toString()) && (!request.isForMainFrame || request.url.toString()==origin+PAGE))return null
                changed()
                return WebResourceResponse("text/plain","utf-8",403,"Review origin refused",mapOf("Cache-Control" to "no-store"),ByteArrayInputStream(ByteArray(0)))
            }
            override fun onPageStarted(view:WebView,url:String?,favicon:Bitmap?){
                cancelPause();changed()
                if(url!=origin+PAGE){view.stopLoading();close()}
            }
            override fun onReceivedSslError(view:WebView,handler:SslErrorHandler,error:SslError){
                handler.cancel();view.stopLoading();close()
            }
        }
        loadUrl(origin+PAGE)
    }
    private fun evaluate(source:String,done:(String)->Unit){
        if(retired.get())return
        try{if(script!=null)script.invoke(source,done)else evaluateJavascript(source){done(it)}}
        catch(_:Exception){completePause(false)}
    }
    /** Must ACK settled single-flight HTTP before launching our controlled picker.
     * A timeout/ACK is coordination only; neither means a server mutation had no effect.
     */
    fun pauseForPicker(done:(Boolean)->Unit){
        if(!retired.get() && currentPage() && acked && pauseId!=null){done(true);return}
        if(retired.get() || !currentPage() || pauseId!=null){done(false);return}
        val id=UUID.randomUUID().toString();pauseId=id;pauseStarted=SystemClock.elapsedRealtime();completion=done
        main.postDelayed(pauseDeadline,5000)
        evaluate("(()=>window.ZrotextReviewRoot?.requestPause(\""+id+"\")===true)()"){
            if(it!="true")completePause(false)else pollPause()
        }
    }
    private fun pollPause(){
        val id=pauseId?:return
        if(retired.get() || !currentPage() || SystemClock.elapsedRealtime()-pauseStarted !in 0..5000){completePause(false);return}
        evaluate("(()=>window.ZrotextReviewRoot?.pauseStatus(\""+id+"\"))()"){encoded->
            if(pauseId!=id || retired.get() || !currentPage()){completePause(false);return@evaluate}
            val state=runCatching{
                val f=AndroidReviewJson.objectValue(encoded.toByteArray(Charsets.UTF_8))
                require(f.keys==setOf("version","request_id","state") && f["version"]==1 && f["request_id"]==id)
                (f["state"] as? String).also{require(it in setOf("waiting","paused"))}
            }.getOrNull()
            when(state){
                "paused"->{acked=true;completePause(true)}
                "waiting"->main.postDelayed(poll,100)
                else->completePause(false)
            }
        }
    }
    private fun completePause(value:Boolean){
        main.removeCallbacks(poll)
        main.removeCallbacks(pauseDeadline)
        val callback=completion;completion=null
        if(!value){cancelPause();close()}
        callback?.invoke(value)
    }
    /** Any other background transition destroys the rendering realm. */
    fun background(ownedPicker:Boolean){
        if(!ownedPicker || !acked || !currentPage()){close();return}
        if(dormantDeadline==0L){
            dormantDeadline=Math.addExact(SystemClock.elapsedRealtime(),120000)
            main.postDelayed(expire,120000)
        }
        if(SystemClock.elapsedRealtime()>=dormantDeadline)close()else onPause()
    }
    /** Active native consent can keep a quiescent document, never authority.
     * Only actual controlled SAF background receives the finite dormant lease.
     */
    fun resumePausedNative():Boolean {
        if(retired.get() || !currentPage() || !acked || dormantDeadline!=0L && SystemClock.elapsedRealtime()>=dormantDeadline){close();return false}
        main.removeCallbacks(expire);dormantDeadline=0;onResume();return true
    }
    fun resumePicker(done:(Boolean)->Unit={}){
        val id=pauseId
        if(retired.get() || !currentPage() || !acked || id==null || dormantDeadline!=0L && SystemClock.elapsedRealtime()>=dormantDeadline){close();done(false);return}
        onResume()
        val settled=AtomicBoolean()
        val deadline=Runnable{if(settled.compareAndSet(false,true)){close();done(false)}}
        main.postDelayed(deadline,5000)
        evaluate("(()=>window.ZrotextReviewRoot?.resume(\""+id+"\")===true)()"){value->
            if(!settled.compareAndSet(false,true))return@evaluate
            main.removeCallbacks(deadline)
            val valid=value=="true" && !retired.get() && currentPage() && pauseId==id
            if(valid)cancelPause()else close()
            done(valid)
        }
    }
    private fun cancelPause(){
        main.removeCallbacks(poll);main.removeCallbacks(pauseDeadline);main.removeCallbacks(expire);pauseId=null;acked=false;dormantDeadline=0
        val pending=completion;completion=null;pending?.invoke(false)
    }
    fun close(){
        if(!retired.compareAndSet(false,true))return
        cancelPause();changed();stopLoading();onPause();clearHistory();removeAllViews();destroy()
    }
    companion object {
        const val PAGE="/review/root"
        fun allowed(origin:String,target:String):Boolean {
            val source=origin.toHttpUrlOrNull()?:return false
            val url=target.toHttpUrlOrNull()?:return false
            return url.scheme=="https" && url.host==source.host && url.port==source.port &&
                url.username.isEmpty() && url.password.isEmpty() && url.fragment==null &&
                (url.encodedPath.startsWith("/review/") || url.encodedPath.startsWith("/v1/review/"))
        }
    }
}
