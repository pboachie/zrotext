// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import android.webkit.CookieManager
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import android.os.Handler
import android.os.Looper

internal sealed interface AndroidReviewRootState {
    data object NoRootHistory : AndroidReviewRootState
    data class Pending(val challenge: UUID, val pin: String, val fingerprint: String,
        val backupDigest: String, val cardDigest: String, val unsignedDigest: String,
        val statementDigest: String, val expiresMs: Long) : AndroidReviewRootState
    data class Enrolled(val pin: String, val fingerprint: String, val generation: Long) : AndroidReviewRootState
    data object History : AndroidReviewRootState
    data object Unavailable : AndroidReviewRootState
}

/** Only public metadata from the actual same-WebView authenticated response.
 * Construction/parsing is not a database proof; JNI receives no credential.
 * Effective deadlines are capped by the original broker/browser/owner bounds.
 */
internal class AndroidReviewWorkspaceAuthority internal constructor(
    val realm: UUID, val database: String, val config: String, val configRevision: Long, val origin: String,
    val account: UUID, val user: UUID, val session: UUID, val broker: UUID,
    val credential: UUID, val credentialRevision: Long, val brokerSession: UUID, val authEvent: UUID,
    val issuedMs: Long, val absoluteExpiryMs: Long, val idleDeadlineMs: Long,
    val serverMs: Long, val anchoredElapsedMs: Long, val uncertaintyMs: Long,
    val epoch: Long, val rootState: AndroidReviewRootState, val locatorRetained:Boolean
) {
    fun sameSession(other: AndroidReviewWorkspaceAuthority): Boolean =
        realm==other.realm && database==other.database && config==other.config && configRevision==other.configRevision && origin==other.origin &&
        account==other.account && user==other.user && session==other.session && broker==other.broker &&
        credential==other.credential && credentialRevision==other.credentialRevision &&
        brokerSession==other.brokerSession && authEvent==other.authEvent && issuedMs==other.issuedMs &&
        absoluteExpiryMs==other.absoluteExpiryMs && idleDeadlineMs==other.idleDeadlineMs && epoch==other.epoch
    fun nativeSnapshot(): ByteArray {
        fun raw(v: UUID)=ByteBuffer.allocate(16).putLong(v.mostSignificantBits).putLong(v.leastSignificantBits).array()
        fun array(v: ByteArray)=JSONArray(v.map { it.toInt() and 255 })
        return JSONObject().put("version",1).put("realm",array(raw(realm)))
            .put("database_commitment",array(AndroidReviewJson.binary(database,32)))
            .put("config_commitment",array(AndroidReviewJson.binary(config,32))).put("config_revision",configRevision).put("origin",origin)
            .put("account_id",array(raw(account))).put("owner_user_id",array(raw(user)))
            .put("review_owner_session_id",array(raw(session))).put("broker_principal_id",array(raw(broker)))
            .put("credential_id",array(raw(credential))).put("credential_revision",credentialRevision)
            .put("broker_session_id",array(raw(brokerSession))).put("authentication_event_id",array(raw(authEvent)))
            .put("issued_ms",issuedMs).put("absolute_expiry_ms",absoluteExpiryMs).put("idle_deadline_ms",idleDeadlineMs)
            .put("context_epoch",epoch).toString().toByteArray(Charsets.UTF_8)
    }
    override fun toString()="AndroidReviewWorkspaceAuthority(public metadata)"
}

internal fun interface AndroidReviewContextCookies { fun cookies(origin: String): String? }
internal fun interface AndroidReviewContextHttp { fun execute(request: Request): Response }
internal fun interface AndroidReviewCookieDeletion { fun apply(origin:String,header:String,originalCookie:String,permitted:()->Boolean):Boolean }
internal class AndroidReviewWebViewCookieDeletion:AndroidReviewCookieDeletion {
    override fun apply(origin:String,header:String,originalCookie:String,permitted:()->Boolean):Boolean {
        // The normal caller is the owned worker. Never block the UI looper on its callback.
        if(Looper.myLooper()==Looper.getMainLooper())return false
        val done=CountDownLatch(1);val accepted=AtomicBoolean()
        val gate=Any();var active=true
        Handler(Looper.getMainLooper()).post{
            var dispatched=false
            try{synchronized(gate){
                if(!active || !permitted())return@synchronized
                val manager=CookieManager.getInstance()
                val name=originalCookie.substringBefore('=')
                val held=manager.getCookie(origin).orEmpty().split(';').map{it.trim()}.filter{it.substringBefore('=')==name}
                require(held.size<=1 && (held.isEmpty()||held.single()==originalCookie))
                if(!active || !permitted())return@synchronized
                dispatched=true
                manager.setCookie(origin,header){ok->synchronized(gate){if(active && permitted())accepted.set(ok)};done.countDown()}
            }}catch(_:Exception){done.countDown()}
            finally{if(!dispatched)done.countDown()}
        }
        return try{
            if(!done.await(2,TimeUnit.SECONDS))false
            else synchronized(gate){accepted.get() && permitted()}
        }finally{
            // A queued callback cannot later gain authority after timeout or
            // cancellation. If setCookie was already dispatched, false means
            // UNKNOWN; it cannot undo that asynchronous platform operation.
            synchronized(gate){active=false}
        }
    }
}
internal enum class AndroidReviewLocatorAction(val path:String) {
    CONTEXT("/v1/review/locator/context"),
    CONFIRM("/v1/review/locator/retention-confirm"),
    STATUS("/v1/review/locator/retention-status")
}
internal class AndroidReviewContextHttps : AndroidReviewContextHttp {
    private val client=OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).cookieJar(CookieJar.NO_COOKIES).cache(null)
        .callTimeout(5,TimeUnit.SECONDS).build()
    override fun execute(request: Request)=client.newCall(request).execute()
}

/** Distinct closed transport; ordinary /auth/session and its cookie scheme are never accepted. */
internal class AndroidReviewWorkspaceOwnerContext(
    private val cookies: AndroidReviewContextCookies=AndroidReviewContextCookies { CookieManager.getInstance().getCookie(it) },
    private val elapsed: ()->Long=SystemClock::elapsedRealtime,
    private val http: AndroidReviewContextHttp=AndroidReviewContextHttps(),
    private val unavailable: ()->Unit={},
    private val cookieDeletion:AndroidReviewCookieDeletion=AndroidReviewWebViewCookieDeletion()
):AutoCloseable {
    private class Credentials(val values: Map<String,String>) {
        fun header()=NAMES.joinToString("; "){ "$it=${values.getValue(it)}" }
        fun session(name:String):UUID { val b=ByteBuffer.wrap(urlToken(values.getValue(name),48));return UUID(b.long,b.long) }
        fun digest()=MessageDigest.getInstance("SHA-256").digest(header().toByteArray(Charsets.US_ASCII))
        override fun toString()="ReviewCredentials([REDACTED])"
    }
    private class Sample(val authority:AndroidReviewWorkspaceAuthority,val digest:ByteArray,val ticket:Long)
    private val gate=Any()
    private var epoch=1L
    private var ticket=0L
    private var closed=false
    private var inFlight=false
    private var sample:Sample?=null

    @Synchronized fun refresh(origin:String):AndroidReviewWorkspaceAuthority {
        val prior:Sample?
        val operation:Long
        val contextEpoch:Long
        synchronized(gate){check(!closed && !inFlight);prior=sample;sample=null;inFlight=true;operation=++ticket;contextEpoch=epoch}
        try {
            validateOrigin(origin)
            val auth=credentials(origin)
            val requestId=UUID.randomUUID().toString()
            val body=JSONObject().put("version",1).put("request_id",requestId).toString()
            val request=Request.Builder().url((origin+CONTEXT_PATH).toHttpUrl())
                .header("Cookie",auth.header()).header("Origin",origin)
                .header("X-Ztrw-Broker-Csrf",auth.values.getValue(BROKER_CSRF))
                .header("X-Ztrw-Owner-Csrf",auth.values.getValue(OWNER_CSRF))
                .header("Accept","application/json").header("Cache-Control","no-store")
                .post(body.toRequestBody("application/json".toMediaType())).build()
            val started=elapsed();require(started>=0)
            val raw=http.execute(request).use { read(it,request,8192) }
            val received=elapsed();val uncertainty=Math.subtractExact(received,started);require(uncertainty in 0..2000)
            val fields=AndroidReviewJson.objectValue(raw)
            require(fields["request_id"]==requestId)
            val current=parse(fields,origin,received,uncertainty,contextEpoch)
            require(current.session==auth.session(OWNER) && current.brokerSession==auth.session(BROKER))
            require(MessageDigest.isEqual(auth.digest(),credentials(origin).digest()))
            prior?.let{require(it.authority.sameSession(current) && MessageDigest.isEqual(it.digest,auth.digest()))}
            synchronized(gate){check(!closed && ticket==operation && epoch==contextEpoch);sample=Sample(current,auth.digest(),operation)}
            return current
        } catch (_:Exception){invalidate();throw IllegalStateException("Review workspace context unavailable")}
        finally {prior?.digest?.fill(0);synchronized(gate){inFlight=false}}
    }
    fun current():AndroidReviewWorkspaceAuthority? {
        val saved=synchronized(gate){if(closed||inFlight)null else sample}?:return null
        val result=runCatching {
            val age=Math.subtractExact(elapsed(),saved.authority.anchoredElapsedMs);require(age in 0..5000)
            val upper=Math.addExact(Math.addExact(saved.authority.serverMs,age),saved.authority.uncertaintyMs)
            require(upper<saved.authority.idleDeadlineMs && upper<saved.authority.absoluteExpiryMs)
            require(MessageDigest.isEqual(saved.digest,credentials(saved.authority.origin).digest()))
            synchronized(gate){check(!closed && ticket==saved.ticket && epoch==saved.authority.epoch && sample===saved)}
            saved.authority
        }.getOrNull()
        if(result==null)invalidate()
        return result
    }
    /** Two observational reads only. This never issues/completes a root ceremony. */
    @Synchronized fun readRoot(expected:AndroidOwnerCustodyIdentity,export:Boolean):ByteArray {
        try {
            val before=refresh(expected.origin)
            require(before.account==expected.account && before.rootState is AndroidReviewRootState.Enrolled)
            val auth=credentials(expected.origin)
            val requestId=UUID.randomUUID().toString()
            val body=JSONObject().put("version",1).put("request_id",requestId)
                .put("independently_compared_fingerprint_b64",Base64.getEncoder().encodeToString(expected.fingerprintBytes())).toString()
            val path=if(export)"/v1/review/root/custody-export" else "/v1/review/root/result"
            val request=Request.Builder().url((expected.origin+path).toHttpUrl())
                .header("Cookie",auth.header()).header("Origin",expected.origin)
                .header("X-Ztrw-Broker-Csrf",auth.values.getValue(BROKER_CSRF))
                .header("X-Ztrw-Owner-Csrf",auth.values.getValue(OWNER_CSRF))
                .header("Accept","application/json").header("Cache-Control","no-store")
                .post(body.toRequestBody("application/json".toMediaType())).build()
            val bytes=http.execute(request).use{read(it,request,8192)}
            require(AndroidReviewJson.objectValue(bytes)["request_id"]==requestId)
            val after=refresh(expected.origin)
            require(before.sameSession(after) && after.rootState is AndroidReviewRootState.Enrolled)
            return bytes
        }catch(_:Exception){invalidate();throw IllegalStateException("Review root publication unavailable")}
    }
    /** Capture ONLY the narrow selector, then authenticate it and its association before SAF. */
    @Synchronized fun captureLocator(origin:String):AndroidReviewLocatorRecord {
        val current=refresh(origin)
        val record=AndroidReviewLocatorRecord.fromCookieHeader(checkNotNull(cookies.cookies(origin)),current)
        try{locatorRequest(record,AndroidReviewLocatorAction.CONTEXT,UUID.randomUUID());return record}
        catch(failure:Exception){record.close();throw failure}
    }
    /** Caller durably records the original ACK ID BEFORE CONFIRM. STATUS reuses
     * that same ID after UNKNOWN; false never means permission to retry/mint.
     */
    @Synchronized fun locatorRequest(record:AndroidReviewLocatorRecord,action:AndroidReviewLocatorAction,requestId:UUID,permitted:()->Boolean={true}):Boolean {
        try {
            check(permitted())
            require(requestId!=UUID(0,0))
            val before=refresh(record.origin);record.requireCurrent(before)
            record.requireHeldCookie(cookies.cookies(record.origin))
            val auth=credentials(record.origin)
            val body=record.metadata(requestId).toString()
            val request=Request.Builder().url((record.origin+action.path).toHttpUrl())
                .header("Cookie",auth.header()+"; "+record.cookieHeader()).header("Origin",record.origin)
                .header("X-Ztrw-Broker-Csrf",auth.values.getValue(BROKER_CSRF))
                .header("X-Ztrw-Owner-Csrf",auth.values.getValue(OWNER_CSRF))
                .header("Accept","application/json").header("Cache-Control","no-store")
                .post(body.toRequestBody("application/json".toMediaType())).build()
            check(permitted()) // actual HTTPS preflight can race lifecycle/cancel
            var deletions:List<String> = emptyList()
            val bytes=http.execute(request).use{
                deletions=it.headers.values("Set-Cookie")
                read(it,request,2048,action!=AndroidReviewLocatorAction.CONTEXT)
            }
            val f=AndroidReviewJson.objectValue(bytes)
            require(f.keys==setOf("version","request_id","preparation_id","selector_cookie_sha256_b64","retained") &&
                f["version"]==1 && f["request_id"]==requestId.toString() && f["preparation_id"]==record.preparation.toString() &&
                f["selector_cookie_sha256_b64"]==record.selectorDigest && f["retained"] is Boolean)
            val retained=f["retained"]==true
            check(permitted()) // no local cookie effect after a lost UI lifetime
            if(deletions.isNotEmpty()){
                require(action!=AndroidReviewLocatorAction.CONTEXT && retained && deletions.size==1)
                requireLocatorDeletion(deletions.single(),record.cookieName)
                record.requireHeldCookie(cookies.cookies(record.origin))
                require(cookieDeletion.apply(record.origin,deletions.single(),record.cookieHeader(),permitted))
            }
            if(retained && action!=AndroidReviewLocatorAction.CONTEXT){
                val raw=cookies.cookies(record.origin).orEmpty()
                require(raw.split(';').none{it.trim().substringBefore('=')==record.cookieName})
            }
            val after=refresh(record.origin);require(before.sameSession(after));record.requireCurrent(after);check(permitted())
            return retained
        }catch(_:Exception){invalidate();throw IllegalStateException("Private selector acknowledgement unavailable; reconcile the original request")}
    }
    fun invalidate(){synchronized(gate){++ticket;++epoch;sample?.digest?.fill(0);sample=null};runCatching(unavailable)}
    override fun close(){synchronized(gate){closed=true};invalidate()}
    private fun credentials(origin:String):Credentials {
        val raw=checkNotNull(cookies.cookies(origin));require(raw.length in 1..8192 && raw.all{it.code in 32..126})
        val selected=HashMap<String,String>()
        for(part in raw.split(';')){
            val pair=part.trim().split('=',limit=2);require(pair.size==2 && pair[0].isNotEmpty())
            if(pair[0] !in NAMES)continue
            require(!selected.containsKey(pair[0]));selected[pair[0]]=pair[1]
        }
        require(selected.keys==NAMES.toSet())
        for(name in listOf(BROKER,OWNER)){
            val bytes=urlToken(selected.getValue(name),48);require(bytes.copyOfRange(0,16).any{it!=0.toByte()})
        }
        urlToken(selected.getValue(BROKER_CSRF),32);urlToken(selected.getValue(OWNER_CSRF),32)
        val browser=selected.getValue(BROWSER);require(browser.length in 64..1024);urlToken(browser,null)
        return Credentials(selected.toMap())
    }
    companion object {
        const val CONTEXT_PATH="/v1/review/session/context"
        private const val BROWSER="__Host-ztrw-browser"
        private const val BROKER="__Host-ztrw-broker"
        private const val OWNER="__Host-ztrw-owner"
        private const val BROKER_CSRF="__Host-ztrw-broker-csrf"
        private const val OWNER_CSRF="__Host-ztrw-owner-csrf"
        private val NAMES=listOf(BROWSER,BROKER,OWNER,BROKER_CSRF,OWNER_CSRF)
        private val FIELDS=setOf("version","request_id","realm","database_commitment_b64","config_digest_b64","config_revision","origin","account","owner_user",
            "review_owner_session","broker_principal","credential_id","credential_revision","broker_session","auth_event",
            "issued_ms","absolute_expiry_ms","idle_deadline_ms","server_now_ms","capabilities","root_state","locator_retained")
        fun validateOrigin(origin:String){AndroidOwnerCustodyIdentity.validateAccountOrigin(UUID(0,1),origin);require(origin.length<=255)}
        private fun urlToken(value:String,size:Int?):ByteArray {
            require(value.matches(Regex("[A-Za-z0-9_-]+")))
            val bytes=Base64.getUrlDecoder().decode(value)
            require(size==null||bytes.size==size)
            require(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)==value && bytes.any{it!=0.toByte()})
            return bytes
        }
        private fun parse(f:Map<String,Any>,origin:String,received:Long,uncertainty:Long,epoch:Long):AndroidReviewWorkspaceAuthority {
            require(f.keys==FIELDS && f["version"]==1 && f["origin"]==origin)
            val capabilities=f["capabilities"] as? List<*> ?: error("capabilities")
            require(capabilities==listOf("bootstrap_session","root_issue","root_complete","root_receipt","root_custody_export"))
            fun text(key:String)=f[key] as? String?:error("context field")
            fun id(key:String)=AndroidReviewJson.uuid(text(key))
            fun number(key:String)=AndroidReviewJson.decimal(text(key))
            val database=text("database_commitment_b64");require(AndroidReviewJson.binary(database,32).any{it!=0.toByte()})
            val config=text("config_digest_b64");require(AndroidReviewJson.binary(config,32).any{it!=0.toByte()})
            val issued=number("issued_ms");val expiry=number("absolute_expiry_ms");val idle=number("idle_deadline_ms");val now=number("server_now_ms")
            require(issued<=Math.subtractExact(now,uncertainty) && idle<=expiry && Math.addExact(now,uncertainty)<idle)
            val root=AndroidReviewJson.rootState(f["root_state"] as? Map<*,*>?:error("root state"))
            return AndroidReviewWorkspaceAuthority(id("realm"),database,config,number("config_revision"),origin,id("account"),id("owner_user"),id("review_owner_session"),
                id("broker_principal"),id("credential_id"),number("credential_revision"),id("broker_session"),id("auth_event"),
                issued,expiry,idle,now,received,uncertainty,epoch,root,f["locator_retained"] as? Boolean?:error("locator retention"))
        }
        internal fun requireLocatorDeletion(header:String,name:String) {
            val pieces=header.split(';').map{it.trim()}
            require(header.length<=512 && pieces.size==6 && pieces[0]==name+"=")
            val attrs=pieces.drop(1).map{it.lowercase()}
            require(attrs.toSet()==setOf("max-age=0","path=/","secure","httponly","samesite=strict"))
        }
        internal fun read(response:Response,request:Request,max:Int,allowCookie:Boolean=false):ByteArray {
            require(response.code==200 && response.request.url==request.url && response.request.method==request.method &&
                response.priorResponse==null && response.networkResponse?.request?.url?.let{it==request.url}!=false && response.cacheResponse==null && response.cacheControl.noStore && (allowCookie||response.headers.values("Set-Cookie").isEmpty()))
            val body=checkNotNull(response.body);val type=checkNotNull(body.contentType())
            require(type.type=="application"&&type.subtype=="json"&&(type.charset()==null||type.charset()==Charsets.UTF_8)&&body.contentLength()<=max)
            val out=ByteArrayOutputStream();body.byteStream().use { input ->
                val chunk=ByteArray(1024)
                while(true){val n=input.read(chunk,0,minOf(chunk.size,max-out.size()+1));if(n<0)break;require(n>0&&out.size()+n<=max);out.write(chunk,0,n)}
            }
            require(out.size()>0);return out.toByteArray()
        }
    }
}

/** Small closed JSON reader: duplicate keys, coercions, extra values and lenient JSON are refused. */
internal object AndroidReviewJson {
    fun objectValue(bytes:ByteArray):Map<String,Any> {
        require(bytes.size in 1..16384)
        val text=Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
        strictStrings(text)
        val input=JSONTokener(text)
        val value=objectFrom(input,0);require(input.nextClean()=='\u0000');return value
    }
    /** Android JSONTokener accepts unknown escapes and unescaped controls.
     * Reject them before its string decoder; semantic DTO checks follow.
     */
    private fun strictStrings(text:String) {
        var inside=false;var index=0
        while(index<text.length){
            val ch=text[index++]
            if(!inside){
                if(ch=='"')inside=true
                else require(ch in "{}[],: \t\r\n1truefals") // no comments, single quotes, NUL or non-JSON whitespace
                continue
            }
            if(ch=='"'){inside=false;continue}
            require(ch.code>=32)
            if(ch=='\\'){
                require(index<text.length)
                when(text[index++]){
                    '"','\\','/','b','f','n','r','t'->Unit
                    'u'->{require(index+4<=text.length && text.substring(index,index+4).all{it in '0'..'9'||it in 'a'..'f'||it in 'A'..'F'});index+=4}
                    else->error("Invalid JSON string escape")
                }
            }
        }
        require(!inside)
    }
    private fun objectFrom(input:JSONTokener,depth:Int):Map<String,Any> {
        require(depth<=1 && input.nextClean()=='{')
        val out=LinkedHashMap<String,Any>()
        while(true){require(out.size<32&&input.nextClean()=='"');input.back();val key=input.nextValue() as? String?:error("key")
            require(!out.containsKey(key)&&input.nextClean()==':')
            out[key]=value(input,depth)
            when(input.nextClean()){'}'->return out;','->Unit;else->error("object")}
        }
    }
    private fun value(input:JSONTokener,depth:Int):Any = when(input.nextClean()){
        '"'->{input.back();input.nextValue() as? String?:error("string")}
        '{'->{input.back();objectFrom(input,depth+1)}
        '['->{val out=ArrayList<String>();while(true){require(out.size<8 && input.nextClean()=='"');input.back();out+=input.nextValue() as? String?:error("array");when(input.nextClean()){']'->break;','->Unit;else->error("array")}};out}
        '1'->1
        't'->{require(input.next()=='r'&&input.next()=='u'&&input.next()=='e');true}
        'f'->{require(input.next()=='a'&&input.next()=='l'&&input.next()=='s'&&input.next()=='e');false}
        else->error("value")
    }
    fun uuid(value:String)=UUID.fromString(value).also{require(it!=UUID(0,0)&&it.toString()==value)}
    fun decimal(value:String):Long {require(value.matches(Regex("[1-9][0-9]{0,18}")));return value.toLong().also{require(it>0)}}
    fun binary(value:String,size:Int):ByteArray {
        require(value.length<=2048)
        val bytes=Base64.getDecoder().decode(value);require(bytes.size==size&&Base64.getEncoder().encodeToString(bytes)==value)
        return bytes
    }
    fun rootState(f:Map<*,*>):AndroidReviewRootState {
        fun text(k:String)=f[k] as? String?:error("root state")
        fun bin(k:String,n:Int)=text(k).also{binary(it,n)}
        return when(text("kind")){
            "no_root_history"->{require(f.keys==setOf("kind"));AndroidReviewRootState.NoRootHistory}
            "pending_enrollment"->{require(f.keys==setOf("kind","challenge_id","root_pin_b64","root_fingerprint_b64","encrypted_backup_sha256_b64","public_card_sha256_b64","unsigned_enrollment_sha256_b64","custody_statement_sha256_b64","expires_ms"));AndroidReviewRootState.Pending(uuid(text("challenge_id")),bin("root_pin_b64",94),bin("root_fingerprint_b64",32),bin("encrypted_backup_sha256_b64",32),bin("public_card_sha256_b64",32),bin("unsigned_enrollment_sha256_b64",32),bin("custody_statement_sha256_b64",32),decimal(text("expires_ms")))}
            "enrolled"->{require(f.keys==setOf("kind","root_pin_b64","root_fingerprint_b64","generation"));AndroidReviewRootState.Enrolled(bin("root_pin_b64",94),bin("root_fingerprint_b64",32),decimal(text("generation")))}
            "history"->{require(f.keys==setOf("kind"));AndroidReviewRootState.History}
            "unavailable"->{require(f.keys==setOf("kind"));AndroidReviewRootState.Unavailable}
            else->error("root state")
        }
    }
}
