// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28])
class AndroidReviewWorkspaceOwnerContextTest {
    private val origin="https://review.example.test"
    private fun id(n:Int)=UUID(0,n.toLong())
    private fun bin(n:Int)=Base64.getEncoder().encodeToString(ByteArray(32){n.toByte()})
    private fun token(n:Int,size:Int=32)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(size){n.toByte()})
    private fun bearer(id:UUID,n:Int)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteBuffer.allocate(48).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).put(ByteArray(32){n.toByte()}).array())
    private fun cookies(n:Int=7)="__Host-ztrw-browser=${token(3,64)}; __Host-ztrw-broker=${bearer(id(8),n)}; __Host-ztrw-owner=${bearer(id(4),n)}; __Host-ztrw-broker-csrf=${token(5)}; __Host-ztrw-owner-csrf=${token(6)}"
    private fun body()=JSONObject().put("version",1).put("realm",id(1)).put("database_commitment_b64",bin(2)).put("config_digest_b64",bin(3)).put("config_revision","1").put("origin",origin)
        .put("account",id(2)).put("owner_user",id(3)).put("review_owner_session",id(4)).put("broker_principal",id(5)).put("credential_id",id(6)).put("credential_revision","1")
        .put("broker_session",id(8)).put("auth_event",id(9)).put("issued_ms","90000").put("absolute_expiry_ms","200000").put("idle_deadline_ms","180000").put("server_now_ms","100000")
        .put("capabilities",JSONArray(listOf("bootstrap_session","root_issue","root_complete","root_receipt","root_custody_export"))).put("locator_retained",false).put("root_state",JSONObject().put("kind","no_root_history"))
    private fun response(req:Request,text:String=body().toString(),code:Int=200,cache:String="no-store",echo:String?=null):Response {
        val request=okio.Buffer();checkNotNull(req.body).writeTo(request)
        val id=echo?:JSONObject(request.readUtf8()).getString("request_id")
        val result=if(text.startsWith("{")) "{\"request_id\":\""+id+"\","+text.drop(1) else text
        return Response.Builder().request(req).protocol(Protocol.HTTP_1_1).code(code).message("synthetic")
            .header("Cache-Control",cache).body(result.toResponseBody("application/json".toMediaType())).build()
    }
    private fun refused(action:()->Unit){try{action();fail("Review context accepted")}catch(_:IllegalStateException){}}
    @Test fun actualTypedContextBindsCookiesCsrfAndStableEpoch() {
        var now=50L;val requests=mutableListOf<Request>()
        val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{now},AndroidReviewContextHttp{requests+=it;now+=20;response(it)})
        val a=c.refresh(origin);assertEquals(id(4),a.session);assertEquals(id(8),a.brokerSession);assertEquals(20L,a.uncertaintyMs);assertSame(a,c.current())
        val req=requests.single();assertEquals("$origin/v1/review/session/context",req.url.toString());assertEquals("POST",req.method)
        assertEquals(token(5),req.header("X-Ztrw-Broker-Csrf"));assertEquals(token(6),req.header("X-Ztrw-Owner-Csrf"));assertNull(req.header("Authorization"))
        assertFalse(a.nativeSnapshot().toString(Charsets.UTF_8).contains("cookie",true));assertTrue(a.nativeSnapshot().toString(Charsets.UTF_8).contains("config_commitment"))
        val b=c.refresh(origin);assertTrue(a.sameSession(b));assertEquals(a.epoch,b.epoch)
    }
    @Test fun closedDtoRejectsOrdinaryContextCoercionDuplicateAndUnknownFields() {
        val good=body().toString()
        val variants=listOf("{\"account_id\":\"${id(2)}\",\"role\":\"owner\"}",body().put("credential_revision",1).toString(),body().put("version","1").toString(),
            body().put("credential_revision","01").toString(),body().put("credential_revision","9223372036854775808").toString(),body().apply{remove("config_digest_b64")}.toString(),
            body().put("extra",id(4)).toString(),body().put("review_owner_session",id(4).toString().replace("-","")).toString(),good+"{}",good.dropLast(1)+",\"version\":1}")
        for(v in variants){val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{response(it,v)});refused{c.refresh(origin)};assertNull(c.current())}
    }
    @Test fun configRealmCredentialAndSessionChangesCancelPendingAuthority() {
        for(field in listOf("realm","database_commitment_b64","config_digest_b64","config_revision","credential_id","credential_revision","auth_event","broker_session","review_owner_session")){
            var second=false;var cancelled=0
            val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{val b=body();if(second)b.put(field,when(field){"database_commitment_b64","config_digest_b64"->bin(12);"credential_revision","config_revision"->"2";else->id(12).toString()});response(it,b.toString())},{cancelled++})
            c.refresh(origin);second=true;refused{c.refresh(origin)};assertNull(c.current());assertEquals(1,cancelled)
        }
    }
    @Test fun logoutDuplicateMalformedAndOrdinaryCookiesCannotAuthorize() {
        val variants=listOf(null,cookies()+"; __Host-ztrw-owner=${bearer(id(4),7)}","__Host-zrotext_session=ordinary; __Host-zrotext_csrf=ordinary",cookies().replace(token(6),token(6)+"="),cookies().replace(bearer(id(4),7),bearer(id(14),7)))
        for(raw in variants){val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{raw},{50},AndroidReviewContextHttp{response(it)});refused{c.refresh(origin)};assertNull(c.current())}
        var raw=cookies();val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{raw},{50},AndroidReviewContextHttp{response(it)});c.refresh(origin);raw=cookies(8);assertNull(c.current())
    }
    @Test fun deadlineUncertaintyAndElapsedRegressionCannotReviveContext() {
        for(end in listOf(49L,2051L)){var now=50L;val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{now},AndroidReviewContextHttp{now=end;response(it)});refused{c.refresh(origin)}}
        for(field in listOf("issued_ms","idle_deadline_ms","absolute_expiry_ms")){val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{response(it,body().put(field,if(field=="issued_ms")"100001" else "100000").toString())});refused{c.refresh(origin)}}
        var now=50L;val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{now},AndroidReviewContextHttp{response(it)});c.refresh(origin);now=5051;assertNull(c.current());now=50;assertNull(c.current())
    }
    @Test fun cacheRedirectCookieSettingForeignAndOversizeResponsesRefused() {
        for(mode in 0..4){val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{r->when(mode){0->response(r,code=302);1->response(r,cache="public, max-age=30");2->response(r).newBuilder().header("Set-Cookie","unexpected").build();3->response(r.newBuilder().url("https://other.example.test/v1/review/session/context").build());else->response(r," ".repeat(8193))}});refused{c.refresh(origin)}}
    }
    @Test fun historyUnavailableAndIncompletePendingNeverPermitCreate() {
        for(kind in listOf("history","unavailable")){val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{response(it,body().put("locator_retained",false).put("root_state",JSONObject().put("kind",kind)).toString())});assertNotEquals(AndroidReviewRootState.NoRootHistory,c.refresh(origin).rootState)}
        val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{response(it,body().put("locator_retained",false).put("root_state",JSONObject().put("kind","pending_enrollment")).toString())});refused{c.refresh(origin)}
    }
    @Test fun lifecycleCancellationDuringHttpsSuppressesReturnedContext() {
        lateinit var c:AndroidReviewWorkspaceOwnerContext
        c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{c.invalidate();response(it)});refused{c.refresh(origin)};assertNull(c.current())
    }
    @Test fun responseMustEchoExactFreshContextRequest() {
        val c=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookies()},{50},AndroidReviewContextHttp{response(it,echo=id(99).toString())})
        refused{c.refresh(origin)};assertNull(c.current())
    }
    @Test fun jsonLexicalGuardRejectsAndroidLenientStringForms() {
        val escape='\\'
        for(raw in listOf("{\"a\":\"line\nbreak\"}","{\"a\":\"raw\ttab\"}","{\"a\":\"bad"+escape+"q\"}","{\"a\":\"bad"+escape+"u00Q0\"}",
            "{\"a\":1/* comment */}","{\"a\":1}// comment","{'a':1}","\u0000{\"a\":1}","{\"a\":1}\u000b")){
            assertThrows(RuntimeException::class.java){AndroidReviewJson.objectValue(raw.toByteArray())}
        }
        assertEquals("line\nbreak",AndroidReviewJson.objectValue(("{\"a\":\"line"+escape+"nbreak\"}").toByteArray())["a"])
    }
}
