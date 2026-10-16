// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.WindowManager
import android.webkit.ValueCallback
import android.widget.EditText
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** App-owned same-WebView journey. Public text/file handoff is explicit; no JS signer. */
@Composable internal fun AndroidReviewRootCustodyScreen(onClose:()->Unit,modifier:Modifier=Modifier) {
    val app=LocalContext.current
    DisposableEffect(app){
        var context=app
        while(context is android.content.ContextWrapper && context !is Activity && context.baseContext!==context)context=context.baseContext
        val activity=context as? Activity
        val secure=(activity?.window?.attributes?.flags?:0).and(WindowManager.LayoutParams.FLAG_SECURE)!=0
        activity?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose{if(!secure)activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)}
    }
    var entry by remember{mutableStateOf("")}
    var selected by remember{mutableStateOf<String?>(null)}
    var error by remember{mutableStateOf(false)}
    val origin=selected
    if(origin==null)Column(modifier.padding(16.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(12.dp)){
        Text("Review workspace custody",style=MaterialTheme.typography.headlineSmall)
        Text("Open the isolated review service in this app. Save its private workspace selector separately from your public root files.")
        OutlinedTextField(entry,{entry=it;error=false},label={Text("Review service HTTPS origin")},singleLine=true,modifier=Modifier.fillMaxWidth())
        if(error)Text("Enter the exact HTTPS origin without a path.")
        Button(onClick={runCatching{AndroidReviewWorkspaceOwnerContext.validateOrigin(entry);selected=entry}.onFailure{error=true}}){Text("Open review sign-in")}
        TextButton(onClick=onClose){Text("Close")}
    }else AndroidReviewRootCustodyConnected(origin,onClose,modifier)
}

private class ReviewPublicSave(val kind:String,val bytes:ByteArray)
private class ReviewPrivateSave(val record:AndroidReviewLocatorRecord,val bytes:ByteArray)

@Composable private fun AndroidReviewRootCustodyConnected(origin:String,onClose:()->Unit,modifier:Modifier) {
    val app=LocalContext.current
    val lifecycle=LocalLifecycleOwner.current.lifecycle
    val main=remember{Handler(Looper.getMainLooper())}
    val worker=remember{Executors.newSingleThreadExecutor()}
    val epoch=remember{AtomicLong()}
    val actionPending=remember{AtomicBoolean()}
    val actionTicket=remember{AtomicLong()}
    val controllerRef=remember{AtomicReference<AndroidReviewRootCustodyController?>()}
    val secretRef=remember{AtomicReference<EditText?>()}
    val browserRef=remember{AtomicReference<AndroidReviewWorkspaceBrowser?>()}
    val ownedPicker=remember{AtomicBoolean()}
    val disposed=remember{AtomicBoolean()}
    val importOwner=remember{UUID.randomUUID()}
    val deferred=remember{AtomicReference<(() -> Unit)?>(null)}
    val publicCallback=remember{AtomicReference<ValueCallback<Array<Uri>>?>()}
    val publicSave=remember{AtomicReference<ReviewPublicSave?>()}
    val privateSave=remember{AtomicReference<ReviewPrivateSave?>()}
    var snapshot by remember{mutableStateOf<AndroidReviewRootCustodyController.Snapshot?>(null)}
    var observed by remember{mutableStateOf<AndroidReviewWorkspaceAuthority?>(null)}
    var browserVisible by remember{mutableStateOf(true)}
    var busy by remember{mutableStateOf(false)}
    var notice by remember{mutableStateOf("")}
    var account by remember{mutableStateOf("")}
    var fingerprint by remember{mutableStateOf("")}
    var publicChallenge by remember{mutableStateOf("")}
    var backup by remember{mutableStateOf<ByteArray?>(null)}
    var card by remember{mutableStateOf<ByteArray?>(null)}
    var retained by remember{mutableStateOf(false)}
    var approved by remember{mutableStateOf(false)}
    var recorded by remember{mutableStateOf(false)}
    var locatorConsent by remember{mutableStateOf(false)}
    var revealed by remember{mutableStateOf("")}
    val owner=remember(origin){AndroidReviewWorkspaceOwnerContext(unavailable={controllerRef.get()?.contextLost()})}
    val controller=remember(origin){
        AndroidReviewRootCustodyController(origin,owner,AndroidReviewRootCustodyNative(),AndroidOwnerCustodyNative(),
            AndroidReviewRootKitFiles.create(app.applicationContext),SystemClock::elapsedRealtime){
            main.post{if(!disposed.get())controllerRef.get()?.let{snapshot=it.snapshot()}}
        }.also{controllerRef.set(it)}
    }
    val retention=remember(origin){AndroidReviewLocatorRetention(owner,AndroidReviewLocatorAckJournal.create(app.applicationContext))}
    fun postCurrent(rejected:()->Unit={},operation:()->Unit){
        val ticket=actionTicket.get()
        main.post{if(!disposed.get() && ticket==epoch.get() && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))operation()else rejected()}
    }
    fun abandonPicker(){
        publicCallback.getAndSet(null)?.onReceiveValue(null)
        publicSave.getAndSet(null)?.bytes?.fill(0)
        privateSave.getAndSet(null)?.let{it.bytes.fill(0);it.record.close()}
    }
    fun clearSecrets(){secretRef.get()?.setText("");revealed="";approved=false;retained=false;recorded=false}
    fun permitted(ticket:Long)=!disposed.get() && ticket==epoch.get() && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
    fun action(finalize:()->Unit={},operation:()->Unit){
        if(disposed.get() || !actionPending.compareAndSet(false,true)){finalize();return}
        busy=true;notice=""
        val ticket=epoch.get()
        actionTicket.set(ticket)
        try{worker.execute{
            try{
                check(ticket==epoch.get()&&lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                operation()
            }catch(_:Exception){main.post{if(!disposed.get() && ticket==epoch.get())notice="Action refused or unconfirmed. Retain your files and reconcile the original server result."}}
            finally{finalize();actionPending.set(false);main.post{if(!disposed.get()){busy=false;snapshot=controllerRef.get()?.snapshot()}}}
        }}catch(_:java.util.concurrent.RejectedExecutionException){finalize();actionPending.set(false);busy=false}
    }
    fun local(operation:()->Unit){try{operation()}catch(_:Exception){clearSecrets();notice="Local custody step unavailable. Recover retained files before another approval.";snapshot=controller.snapshot()}}
    // Read managed input only AFTER the controller's HTTPS preflight. It is
    // cleared before native recovery and before any subsequent network request.
    fun token():ByteArray {
        val latch=CountDownLatch(1);val gate=Any();var accepting=true;var result:ByteArray?=null
        main.post{
            var candidate:ByteArray?=null
            try{
                check(permitted(actionTicket.get()))
                val field=checkNotNull(secretRef.get());candidate=decodeAndroidOwnerRecoveryToken(field.text.toString());field.setText("")
                synchronized(gate){if(accepting){result=candidate;candidate=null}}
            }catch(_:Exception){secretRef.get()?.setText("")}finally{candidate?.fill(0);latch.countDown()}
        }
        try{
            check(latch.await(2,TimeUnit.SECONDS))
            return synchronized(gate){accepting=false;checkNotNull(result).also{result=null}}
        }finally{synchronized(gate){accepting=false;result?.fill(0);result=null}}
    }
    fun resumed(action:(Boolean)->Unit){
        val complete={
            ownedPicker.set(false)
            if(disposed.get())action(false)
            else if(browserVisible){
                val browser=browserRef.get()
                if(browser==null)action(false) else browser.resumePicker{ok->action(ok)}
            } else action(browserRef.get()?.resumePausedNative()==true)
            Unit
        }
        if(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))complete()else deferred.set(complete)
    }
    val publicOpen=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){uri->
        val callback=publicCallback.getAndSet(null)
        resumed{ok->
            val staged=if(ok)runCatching{
                require(uri?.scheme=="content")
                val bytes=app.contentResolver.openInputStream(checkNotNull(uri)).use{readAndroidOwnerCustodyFile(checkNotNull(it),20480)}
                try{AndroidOwnerCustodyPublicImportProvider.stage(app,importOwner,bytes)}
                finally{bytes.fill(0)}
            }.getOrNull() else null
            callback?.onReceiveValue(staged?.let{arrayOf(it)})
        }
    }
    val backupOpen=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){uri->resumed{ok->if(ok && uri!=null)action{
        require(uri?.scheme=="content")
        val bytes=app.contentResolver.openInputStream(checkNotNull(uri)).use{readAndroidOwnerCustodyFile(checkNotNull(it),748)}
        postCurrent{backup=bytes}
    }}}
    val cardOpen=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){uri->resumed{ok->if(ok && uri!=null)action{
        require(uri?.scheme=="content")
        val bytes=app.contentResolver.openInputStream(checkNotNull(uri)).use{readAndroidOwnerCustodyFile(checkNotNull(it),645)}
        postCurrent{card=bytes}
    }}}
    val privateOpen=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()){uri->resumed{ok->if(ok && uri!=null)action{
        require(uri?.scheme=="content")
        val bytes=app.contentResolver.openInputStream(checkNotNull(uri)).use{readAndroidOwnerCustodyFile(checkNotNull(it),AndroidReviewLocatorRecord.MAX_BYTES)}
        try{
            val ticket=actionTicket.get()
            val confirmed=retention.reconcile(origin,bytes){permitted(ticket)}
            postCurrent{notice=if(confirmed)"Original private-retention acknowledgement verified." else "Original acknowledgement remains unavailable; no new request was created."}
        }finally{bytes.fill(0)}
    }}}
    val export=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")){uri->
        val pub=publicSave.getAndSet(null);val privateExport=privateSave.getAndSet(null)
        fun discard(){pub?.bytes?.fill(0);privateExport?.bytes?.fill(0);privateExport?.record?.close()}
        resumed{ok->if(!ok || uri==null){discard()}else action(::discard){
            try{
                require(uri?.scheme=="content")
                val bytes=privateExport?.bytes?:checkNotNull(pub).bytes
                app.contentResolver.openOutputStream(checkNotNull(uri),"wt").use{out->checkNotNull(out);out.write(bytes);out.flush()}
                val readback=app.contentResolver.openInputStream(uri).use{readAndroidOwnerCustodyFile(checkNotNull(it),maxOf(bytes.size,1))}
                try{
                    require(java.security.MessageDigest.isEqual(bytes,readback))
                    if(privateExport!=null){
                        val ticket=actionTicket.get()
                        val confirmed=retention.afterReadback(privateExport.record,readback){permitted(ticket)}
                        postCurrent{notice=if(confirmed)"Private selector saved, read back and acknowledged. Keep it separate from public root files." else "File readback matched; server acknowledgement remains unavailable."}
                    }else{
                        if(pub?.kind=="backup")controller.exportReadback(readback)
                        postCurrent{notice="Public/encrypted artifact saved and read back. Fresh independent recovery is still required."}
                    }
                }finally{readback.fill(0)}
            }finally{discard()}
        }}
    }
    fun picker(launch:()->Unit){
        browserRef.get()?.pauseForPicker{ok->
            if(ok){ownedPicker.set(true);try{launch()}catch(_:Exception){ownedPicker.set(false);abandonPicker();notice="Picker unavailable."}}
            else{abandonPicker();notice="The review page could not settle its current request. Reconcile it before continuing."}
        }
    }
    val browser=remember(origin){
        AndroidReviewWorkspaceBrowser(app,origin,{
            owner.invalidate()
            main.post{publicCallback.getAndSet(null)?.onReceiveValue(null)}
        },{callback->
            publicCallback.getAndSet(callback)?.onReceiveValue(null);ownedPicker.set(true)
            try{publicOpen.launch(arrayOf("application/octet-stream","text/plain"))}
            catch(_:Exception){ownedPicker.set(false);publicCallback.getAndSet(null)?.onReceiveValue(null)}
        }).also{browserRef.set(it)}
    }
    fun copyPublic(label:String,text:String){
        (app.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(label,text))
        notice="Public value copied."
    }
    DisposableEffect(controller,browser){
        val observer=LifecycleEventObserver{_,event->when(event){
            Lifecycle.Event.ON_PAUSE, Lifecycle.Event.ON_STOP->{
                epoch.incrementAndGet();clearSecrets();controller.cancel();browser.background(ownedPicker.get())
                AndroidOwnerCustodyPublicImportProvider.clear(importOwner)
            }
            Lifecycle.Event.ON_RESUME->{deferred.getAndSet(null)?.invoke()}
            Lifecycle.Event.ON_DESTROY->{controller.close();browser.close()}
            else->Unit
        }}
        lifecycle.addObserver(observer)
        onDispose{
            disposed.set(true)
            epoch.incrementAndGet();clearSecrets();controller.close();browser.close();controllerRef.set(null);browserRef.set(null)
            publicCallback.getAndSet(null)?.onReceiveValue(null)
            publicSave.getAndSet(null)?.bytes?.fill(0)
            privateSave.getAndSet(null)?.let{it.bytes.fill(0);it.record.close()}
            AndroidOwnerCustodyPublicImportProvider.clear(importOwner)
            // Let queued tasks reach their failed-lifetime guard and finalizer;
            // discarding queued Runnables would strand private export captures.
            secretRef.set(null);worker.shutdown();lifecycle.removeObserver(observer)
            deferred.getAndSet(null)?.invoke()
        }
    }
    LaunchedEffect(controller){while(true){delay(1000);controller.expireReveal()}}
    LaunchedEffect(revealed){if(revealed.isNotEmpty()){delay(120000);revealed=""}}
    val state=snapshot?:controller.snapshot()
    Column(modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
        Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
            Button(enabled=!busy,onClick={
                if(browserVisible)browser.pauseForPicker{ok->if(ok){clearSecrets();owner.invalidate();browserVisible=false}}
                else{clearSecrets();controller.cancel();browser.resumePicker{ok->if(ok)browserVisible=true else notice="Reopen the review screen to reconcile browser continuity."}}
            }){Text(if(browserVisible)"Open native custody" else "Return to review browser")}
            TextButton(onClick=onClose){Text("Close")}
        }
        AndroidView(factory={browser},modifier=if(browserVisible)Modifier.fillMaxWidth().weight(1f) else Modifier.height(1.dp),
            update={it.visibility=if(browserVisible)android.view.View.VISIBLE else android.view.View.GONE})
        if(!browserVisible)Column(Modifier.weight(1f).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
            Text("Native review custody",style=MaterialTheme.typography.headlineSmall)
            Text(state.status);if(notice.isNotEmpty())Text(notice)
            Button(enabled=!busy,onClick={action{val current=owner.refresh(origin);postCurrent{observed=current}}}){Text("Check review sign-in")}
            observed?.let{Text("Workspace account: "+it.account);Text(if(it.locatorRetained)"Private selector acknowledgement recorded." else "Save the private workspace selector before the root ceremony.")}
            Row{Checkbox(locatorConsent,{locatorConsent=it});Text("I will save the private selector to a trusted location, separate from public root files. Configuration/key rotation can make it unavailable.")}
            Button(enabled=!busy&&locatorConsent,onClick={action{
                val record=retention.prepare(origin)
                val bytes=record.privateBytes(true)
                postCurrent({bytes.fill(0);record.close()}){privateSave.getAndSet(ReviewPrivateSave(record,bytes))?.let{it.bytes.fill(0);it.record.close()};picker{export.launch("review-workspace-selector.private")}}
            }}){Text("Save private workspace selector")}
            Button(enabled=!busy,onClick={picker{privateOpen.launch(arrayOf("application/octet-stream"))}}){Text("Reconcile original selector acknowledgement")}
            HorizontalDivider()
            Button(enabled=!busy&&!state.busy&&observed?.rootState==AndroidReviewRootState.NoRootHistory,onClick={action{controller.create()}}){Text("Create first root kit")}
            if(state.kit.canReveal)Button(enabled=!busy,onClick={local{revealed=controller.reveal()}}){Text("Reveal recovery token once")}
            if(revealed.isNotEmpty()){
                Text(revealed)
                Row{Checkbox(recorded,{recorded=it});Text("I recorded the recovery token separately.")}
                Button(enabled=recorded,onClick={local{controller.confirmTokenRecorded();revealed="";recorded=false}}){Text("Confirm token recorded")}
            }
            if(state.kit.canExportKit){
                for(kind in listOf("backup","card","receipt"))Button(enabled=!busy,onClick={local{
                    val bytes=when(kind){"backup"->controller.backup();"card"->controller.card();else->controller.publicReceipt()}
                    publicSave.set(ReviewPublicSave(kind,bytes));picker{export.launch("review-root-"+kind+".bin")}
                }}){Text("Save "+kind)}
                val kit=runCatching{AndroidOwnerCustodyKit(controller.backup(),controller.card())}.getOrNull()
                kit?.let{
                    Text("Full root fingerprint: "+it.identity.fingerprint)
                    Button(onClick={copyPublic("Public root pin",Base64.getEncoder().encodeToString(it.pin))}){Text("Copy public root pin Base64")}
                    Button(onClick={copyPublic("Public root fingerprint",Base64.getEncoder().encodeToString(it.identity.fingerprintBytes()))}){Text("Copy public root fingerprint Base64")}
                }
            }
            HorizontalDivider()
            Text("Recover independently saved files before each signing approval.")
            Button(enabled=!busy,onClick={picker{backupOpen.launch(arrayOf("application/octet-stream"))}}){Text("Import retained encrypted backup")}
            Button(enabled=!busy,onClick={picker{cardOpen.launch(arrayOf("application/octet-stream"))}}){Text("Import retained public card")}
            OutlinedTextField(account,{account=it},label={Text("Account UUID from saved receipt")},modifier=Modifier.fillMaxWidth())
            OutlinedTextField(fingerprint,{fingerprint=it},label={Text("Full root fingerprint from saved receipt")},modifier=Modifier.fillMaxWidth())
            AndroidView(factory={AndroidOwnerCustodyRecoveryInput(it).also{field->secretRef.set(field)}},modifier=Modifier.fillMaxWidth(),
                onReset=null,onRelease={it.setText("");secretRef.compareAndSet(it,null)})
            Row{Checkbox(retained,{retained=it});Text("These files, token and identity were independently retained.")}
            Button(enabled=!busy&&backup!=null&&card!=null&&retained,onClick={
                val expected=runCatching{AndroidOwnerCustodyIdentity.parse(account,origin,fingerprint)}.getOrNull()
                if(expected==null)notice="Enter the independently saved account and full fingerprint."
                else action{controller.recover(checkNotNull(backup),checkNotNull(card),expected,true,::token)}
            }){Text("Check fresh native recovery")}
            OutlinedTextField(publicChallenge,{publicChallenge=it.take(1024);approved=false},label={Text("Public challenge Base64 from review browser")},modifier=Modifier.fillMaxWidth())
            Button(enabled=!busy&&state.kit.recoveryVerified,onClick={action{
                val bytes=Base64.getDecoder().decode(publicChallenge);require(bytes.size in 152..663&&Base64.getEncoder().encodeToString(bytes)==publicChallenge)
                controller.review(bytes,AndroidOwnerCustodyIdentity.parse(account,origin,fingerprint))
            }}){Text("Review exact enrollment and custody")}
            state.review?.let{
                SelectionContainer{Text("Account: "+it.enrollment.account+"\nOrigin: "+it.enrollment.origin+"\nRoot: "+it.fingerprint+
                    "\nBackup UUID: "+it.bundle+"\nBackup SHA256: "+it.backupSha256+"\nCard SHA256: "+it.cardSha256+
                    "\nCustody statement SHA256: "+it.custodyStatementSha256+"\nChallenge: "+it.enrollment.challengeId+
                    "\nOriginal expiry: "+it.enrollment.expiresMs)}
                Row{Checkbox(approved,{approved=it});Text("I approve exactly this root enrollment and encrypted-custody publication.")}
                Button(enabled=!busy&&approved,onClick={action{controller.sign(true,::token)}}){Text("Recover and sign once")}
            }
            state.signatures?.let{response->
                SelectionContainer{Text(response)}
                Button(onClick={copyPublic("Public enrollment and custody signatures",response)}){Text("Copy public signature response")}
            }
            Button(enabled=!busy&&state.kit.recoveryVerified,onClick={action{controller.verifyServerPublication()}}){Text("Verify actual server receipt and custody")}
        }
    }
}
