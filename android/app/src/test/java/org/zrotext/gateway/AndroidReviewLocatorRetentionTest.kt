// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Synthetic selector framing and actual transport/journal choreography, not a server MAC proof. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28])
class AndroidReviewLocatorRetentionTest {
    @get:Rule val temporary=TemporaryFolder()
    private val origin="https://review.example.test"
    private fun id(n:Int)=UUID(0,n.toLong())
    private fun raw(id:UUID)=ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
    private fun b64(b:ByteArray)=Base64.getEncoder().encodeToString(b)
    private fun url(b:ByteArray)=Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    private fun bearer(n:Int)=url(raw(id(n))+ByteArray(32){7})
    private val baseCookies="__Host-ztrw-browser="+url(ByteArray(64){3})+"; __Host-ztrw-broker="+bearer(8)+
        "; __Host-ztrw-owner="+bearer(4)+"; __Host-ztrw-broker-csrf="+url(ByteArray(32){5})+"; __Host-ztrw-owner-csrf="+url(ByteArray(32){6})
    private val prep=id(10)
    private val name="__Host-ztrw-l-"+prep.toString().replace("-","")
    private fun selector():String {
        val bytes=ByteBuffer.allocate(267+origin.length).put(1).put(raw(id(1))).put(ByteArray(32){2})
            .putShort(origin.length.toShort()).put(origin.toByteArray()).put(ByteArray(32){3}).putLong(1)
            .put(ByteArray(32){4}).put(raw(id(2))).put(raw(id(3))).put(raw(prep)).put(raw(id(11)))
            .putLong(1).putLong(95000).put(ByteArray(32){8}).put(ByteArray(32){9}).array()
        return url(bytes)
    }
    private var cookie=baseCookies+"; "+name+"="+selector()
    private var rootRevision="1"
    private var retained=false
    private var unknownConfirm=false
    private var foreignDeletion=false
    private val operations=ArrayList<Pair<String,UUID>>()
    private var beforeConfirm:()->Unit={}
    private var beforeContext:()->Unit={}
    private fun contextBody()=JSONObject().put("version",1).put("realm",id(1)).put("database_commitment_b64",b64(ByteArray(32){2}))
        .put("config_digest_b64",b64(ByteArray(32){3})).put("config_revision",rootRevision).put("origin",origin)
        .put("account",id(2)).put("owner_user",id(3)).put("review_owner_session",id(4)).put("broker_principal",id(5))
        .put("credential_id",id(6)).put("credential_revision","1").put("broker_session",id(8)).put("auth_event",id(9))
        .put("issued_ms","90000").put("absolute_expiry_ms","200000").put("idle_deadline_ms","180000").put("server_now_ms","100000")
        .put("capabilities",JSONArray(listOf("bootstrap_session","root_issue","root_complete","root_receipt","root_custody_export")))
        .put("root_state",JSONObject().put("kind","no_root_history")).put("locator_retained",retained)
    private fun http(request:Request):Response {
        val buffer=okio.Buffer();checkNotNull(request.body).writeTo(buffer);val body=JSONObject(buffer.readUtf8())
        val requestId=UUID.fromString(body.getString("request_id"))
        val path=request.url.encodedPath
        val response=if(path.endsWith("/session/context")){beforeContext();contextBody().put("request_id",requestId)} else {
            operations+=path to requestId
            assertEquals(setOf("version","request_id","preparation_id","selector_cookie_sha256_b64"),body.keys().asSequence().toSet())
            assertTrue(request.header("Cookie")!!.contains(name+"="+selector()))
            if(path.endsWith("retention-confirm")){beforeConfirm();retained=true;if(unknownConfirm)error("Synthetic lost response")}
            JSONObject().put("version",1).put("request_id",requestId).put("preparation_id",prep)
                .put("selector_cookie_sha256_b64",body.getString("selector_cookie_sha256_b64")).put("retained",retained)
        }
        val result=Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
            .header("Cache-Control","no-store").body(response.toString().toResponseBody("application/json".toMediaType()))
        if(retained && !path.endsWith("/context"))result.header("Set-Cookie",(if(foreignDeletion)"__Host-ztrw-owner" else name)+"=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
        return result.build()
    }
    private fun owner()=AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies{cookie},{50},AndroidReviewContextHttp{http(it)},cookieDeletion=AndroidReviewCookieDeletion{_,header,original,permitted->
        check(permitted())
        assertEquals(name+"="+selector(),original)
        assertTrue(header.startsWith(name+"="));cookie=baseCookies;true
    })
    private fun journal(dir:File,sync:(File)->Unit={})=AndroidReviewLocatorAckJournal(dir,sync)
    @Test fun narrowPrivateRecordIsClosedCanonicalIndependentAndNeverAUiCredential() {
        val c=owner();val current=c.refresh(origin)
        val record=AndroidReviewLocatorRecord.fromCookieHeader(cookie,current)
        assertEquals(prep,record.preparation)
        assertEquals("AndroidReviewLocatorRecord([PRIVATE])",record.toString())
        assertThrows(IllegalArgumentException::class.java){record.privateBytes(false)}
        val bytes=record.privateBytes(true);record.requireReadback(bytes)
        assertFalse(AndroidOwnerCustodyOwnerBrowser.publicImport(bytes.inputStream()))
        assertFalse(bytes.toString(Charsets.UTF_8).contains("broker-csrf"))
        AndroidReviewLocatorRecord.fromPrivateFile(bytes,current).use{assertEquals(record.selectorDigest,it.selectorDigest)}
        assertThrows(IllegalArgumentException::class.java){AndroidReviewLocatorRecord.fromPrivateFile(bytes+byteArrayOf(32),current)}
        assertThrows(IllegalArgumentException::class.java){AndroidReviewLocatorRecord.fromCookieHeader(cookie+"; "+name+"="+selector(),current)}
        val foreign=cookie.replace(name,"__Host-ztrw-l-"+id(12).toString().replace("-",""))
        assertThrows(IllegalArgumentException::class.java){AndroidReviewLocatorRecord.fromCookieHeader(foreign,current)}
        record.close();assertThrows(IllegalStateException::class.java){record.privateBytes(true)}
    }
    @Test fun exactReadbackAndDurableOriginalRequestPrecedeTheOnlyConfirm() {
        val c=owner();val directory=temporary.newFolder();var synced=false
        val j=journal(directory){synced=true};val flow=AndroidReviewLocatorRetention(c,j)
        flow.prepare(origin).use{record->
            val file=record.privateBytes(true)
            assertEquals(listOf("/v1/review/locator/context"),operations.map{it.first})
            beforeConfirm={assertTrue(synced);assertNotNull(j.existing(record,c.current()!!))}
            assertTrue(flow.afterReadback(record,file));assertEquals(baseCookies,cookie)
            val pending=j.existing(record,c.refresh(origin))!!
            assertEquals(pending.request,operations.last().second)
            assertTrue(flow.reconcile(origin,file));assertEquals("/v1/review/locator/retention-status",operations.last().first)
            assertEquals(pending.request,operations.last().second)
            assertEquals(1,operations.count{it.first.endsWith("retention-confirm")})
        }
    }
    @Test fun lostConfirmResponseUsesOriginalStatusAndNeverReplacementRequest() {
        val c=owner();val flow=AndroidReviewLocatorRetention(c,journal(temporary.newFolder()))
        flow.prepare(origin).use{record->
            val file=record.privateBytes(true);unknownConfirm=true
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,file)}
            val original=operations.last().second;unknownConfirm=false
            assertTrue(flow.reconcile(origin,file));assertEquals(original,operations.last().second)
            assertEquals(1,operations.count{it.first.endsWith("retention-confirm")})
        }
    }
    @Test fun parentFsyncFailurePreservesMetadataAndRefusesConfirmOrBlindReplay() {
        val c=owner();val directory=temporary.newFolder();val flow=AndroidReviewLocatorRetention(c,journal(directory){error("Synthetic fsync failure")})
        flow.prepare(origin).use{record->
            val file=record.privateBytes(true)
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,file)}
            assertEquals(1,directory.listFiles()!!.size);val original=directory.listFiles()!!.single().readBytes()
            assertFalse(flow.afterReadback(record,file)) // existing request means STATUS, never confirm
            assertArrayEquals(original,directory.listFiles()!!.single().readBytes())
            assertEquals(0,operations.count{it.first.endsWith("retention-confirm")})
        }
    }
    @Test fun mismatchedReadbackPartialJournalAndConfigAbaRefuseBeforeMutation() {
        val c=owner();val directory=temporary.newFolder();val flow=AndroidReviewLocatorRetention(c,journal(directory))
        flow.prepare(origin).use{record->
            val file=record.privateBytes(true)
            assertThrows(IllegalArgumentException::class.java){flow.afterReadback(record,file+byteArrayOf(32))}
            File(directory,prep.toString()+".json").writeText("{")
            assertThrows(RuntimeException::class.java){flow.afterReadback(record,file)}
            rootRevision="2"
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,file)}
            assertEquals(0,operations.count{it.first.endsWith("retention-confirm")})
        }
    }
    @Test fun foreignCookieDeletionCannotClearOrReplaceAuthority() {
        val c=owner();val flow=AndroidReviewLocatorRetention(c,journal(temporary.newFolder()))
        flow.prepare(origin).use{record->foreignDeletion=true
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,record.privateBytes(true))}
            assertTrue(cookie.contains(name+"="));assertTrue(cookie.contains("__Host-ztrw-owner="));assertNull(c.current())
        }
    }
    @Test fun lifecycleLostDuringActualPreflightCannotDispatchConfirm() {
        val c=owner();val directory=temporary.newFolder();val flow=AndroidReviewLocatorRetention(c,journal(directory))
        flow.prepare(origin).use{record->
            var active=true
            beforeContext={if(directory.listFiles()!!.isNotEmpty())active=false}
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,record.privateBytes(true)){active}}
            assertEquals(1,directory.listFiles()!!.size)
            assertEquals(0,operations.count{it.first.endsWith("retention-confirm")})
            // The durable original remains; lifecycle loss does not authorize replacement.
            beforeContext={};assertFalse(flow.reconcile(origin,record.privateBytes(true)))
            assertTrue(operations.last().first.endsWith("retention-status"))
        }
    }
    @Test fun importedSelectorCannotOverwriteOrDeleteDifferentSameNamedCookie() {
        val c=owner();val flow=AndroidReviewLocatorRetention(c,journal(temporary.newFolder()))
        flow.prepare(origin).use{record->
            val other=Base64.getUrlDecoder().decode(selector()).also{it[it.lastIndex]=1}
            cookie=baseCookies+"; "+name+"="+url(other)
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,record.privateBytes(true))}
            assertEquals(0,operations.count{it.first.endsWith("retention-confirm")})
            assertTrue(cookie.endsWith(url(other)))
        }
    }
    @Test fun newlyCreatedJournalParentEntryMustSyncBeforeConfirm() {
        val c=owner();val directory=File(temporary.newFolder(),"pending")
        val synced=ArrayList<File>()
        val flow=AndroidReviewLocatorRetention(c,journal(directory){dir->synced+=dir;if(dir==directory.parentFile)error("Synthetic parent-entry fsync failure")})
        flow.prepare(origin).use{record->
            assertThrows(IllegalStateException::class.java){flow.afterReadback(record,record.privateBytes(true))}
            assertEquals(listOf(directory,directory.parentFile),synced)
            assertEquals(1,directory.listFiles()!!.size)
            assertEquals(0,operations.count{it.first.endsWith("retention-confirm")})
            val original=directory.listFiles()!!.single().readBytes()
            assertFalse(flow.afterReadback(record,record.privateBytes(true)))
            assertArrayEquals(original,directory.listFiles()!!.single().readBytes())
            assertTrue(operations.last().first.endsWith("retention-status"))
        }
    }
}
