// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import java.util.UUID
import java.io.ByteArrayInputStream
import android.os.Looper
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AndroidOwnerCustodyOwnerContextTest {
    private val account = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val user = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private val session = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    private val expected = AndroidOwnerCustodyIdentity(account, "https://example.test", "12".repeat(32))
    private fun token(prefix: String, byte: Byte) = prefix + Base64.getUrlEncoder().withoutPadding()
        .encodeToString(ByteArray(32) { byte })
    private fun cookies(byte: Byte = 7) = "__Host-zrotext_session=${token("zts_", byte)}; __Host-zrotext_csrf=${token("ztc_", byte)}"
    private fun sessionBody() = JSONObject().put("account_id", account.toString()).put("user_id", user.toString())
        .put("session_id", session.toString()).put("role", "owner").put("server_now_ms", "1000000").toString()
    private fun response(request: Request, body: String = sessionBody(), status: Int = 200,
        type: String = "application/json", cache: String = "no-store") = Response.Builder()
        .request(request).protocol(Protocol.HTTP_1_1).code(status).message("synthetic")
        .header("Cache-Control", cache).body(body.toResponseBody(type.toMediaType())).build()
    private fun refused(action: () -> Unit) {
        try { action(); fail("Invalid owner context accepted") } catch (_: IllegalStateException) { }
    }

    @Test fun currentAuthorityComesOnlyFromActualOwnerSessionAndRoundtripBoundTime() {
        var now = 500L
        val requests = mutableListOf<Request>()
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { origin ->
            assertEquals(expected.origin, origin); cookies()
        }, { now }, AndroidOwnerContextHttp { request ->
            requests += request; now += 80; response(request)
        })
        assertNull(context.currentAuthority())
        val authority = context.refresh(expected)
        assertEquals(account, authority.account); assertEquals(user, authority.user); assertEquals(session, authority.session)
        assertEquals(1_000_000L, authority.utcMs); assertEquals(580L, authority.anchoredElapsedMs); assertEquals(80L, authority.uncertaintyMs)
        assertEquals(authority, context.currentAuthority())
        assertEquals("https://example.test/v1/auth/session", requests.single().url.toString())
        assertEquals("GET", requests.single().method); assertEquals(cookies(), requests.single().header("Cookie"))
        assertEquals(expected.origin, requests.single().header("Origin"))
        assertEquals(token("ztc_", 7), requests.single().header("x-zrotext-csrf"))
        assertNull(requests.single().header("Authorization"))
        assertEquals("no-store", requests.single().header("Cache-Control"))
    }

    @Test fun oldSessionResponseWithoutAuthenticatedTimeFailsClosed() {
        var closed = 0
        val old = JSONObject(sessionBody()).apply { remove("server_now_ms") }.toString()
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
            AndroidOwnerContextHttp { response(it, old) }, { closed++ })
        refused { context.refresh(expected) }; assertNull(context.currentAuthority()); assertEquals(1, closed)
    }

    @Test fun observerForeignAccountAndMalformedIdentityCannotAuthenticateOwner() {
        val invalid = listOf(
            JSONObject(sessionBody()).put("role", "observer").toString(),
            JSONObject(sessionBody()).put("account_id", user.toString()).toString(),
            JSONObject(sessionBody()).put("user_id", UUID(0, 0).toString()).toString(),
            JSONObject(sessionBody()).put("session_id", "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC").toString(),
            JSONObject(sessionBody()).put("extra", "untrusted").toString()
        )
        for (body in invalid) {
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { response(it, body) })
            refused { context.refresh(expected) }; assertNull(context.currentAuthority())
        }
    }

    @Test fun sessionParserRejectsDuplicateKeysAliasesNonStringsAndTrailingData() {
        val body = sessionBody()
        for (invalid in listOf(
            body.dropLast(1) + ",\"session_id\":\"$session\"}",
            body.replace("\"1000000\"", "1000000"), body + "{}", body + " trailing",
            body.replace("\"owner\"", "'owner'"), body.replace("\"role\"", "role")
        )) {
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { response(it, invalid) })
            refused { context.refresh(expected) }
        }
    }

    @Test fun authenticatedTimeMustBeCanonicalPositiveBoundedDecimal() {
        for (time in listOf("0", "-1", "01", "1.0", "1e6", "9223372036854775808", " 1", "")) {
            val body = JSONObject(sessionBody()).put("server_now_ms", time).toString()
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { response(it, body) })
            refused { context.refresh(expected) }
        }
    }

    @Test fun cachedRedirectForeignUrlStatusTypeAndOversizedResponsesAreRejected() {
        for (mode in 0..6) {
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { request -> when (mode) {
                    0 -> response(request, status = 401)
                    1 -> response(request, status = 302)
                    2 -> response(request, type = "text/plain")
                    3 -> response(request, cache = "public, max-age=60")
                    4 -> response(request.newBuilder().url("https://other.example.test/v1/auth/session").build())
                    5 -> response(request, sessionBody() + " ".repeat(2048))
                    else -> response(request, type = "application/json; charset=utf-16")
                } })
            refused { context.refresh(expected) }; assertNull(context.currentAuthority())
        }
    }

    @Test fun excessiveRoundtripRegressedElapsedAndAgedSampleCannotExtendAuthority() {
        for (ending in listOf(499L, 2501L)) {
            var now = 500L
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { now },
                AndroidOwnerContextHttp { now = ending; response(it) })
            refused { context.refresh(expected) }
        }
        var now = 500L; var closed = 0
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { now },
            AndroidOwnerContextHttp { response(it) }, { closed++ })
        context.refresh(expected); now = 5500; assertNotNull(context.currentAuthority())
        now = 5501; assertNull(context.currentAuthority()); assertEquals(1, closed)
        now = 500; assertNull(context.currentAuthority())
    }

    @Test fun logoutCookieReplacementAndCancelledInflightRefreshInvalidatePendingReview() {
        var selected: String? = cookies(); var closed = 0
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { selected }, { 0 },
            AndroidOwnerContextHttp { response(it) }, { closed++ })
        context.refresh(expected); selected = null; assertNull(context.currentAuthority()); assertEquals(1, closed)
        selected = cookies(); context.refresh(expected); selected = cookies(8); assertNull(context.currentAuthority())
        lateinit var cancelled: AndroidOwnerCustodyOwnerContext
        cancelled = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
            AndroidOwnerContextHttp { cancelled.invalidate(); response(it) })
        refused { cancelled.refresh(expected) }; assertNull(cancelled.currentAuthority())
    }

    @Test fun missingMalformedDuplicateAndForeignCredentialsNeverLeaveApp() {
        val malformed = listOf(null, "", cookies() + "; __Host-zrotext_session=${token("zts_", 8)}",
            cookies().replace("zts_", "ztd_"), cookies().replace("ztc_", "ztk_"), cookies() + "\r\nInjected: value")
        for (raw in malformed) {
            var calls = 0
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { raw }, { 0 },
                AndroidOwnerContextHttp { calls++; response(it) })
            refused { context.refresh(expected) }; assertEquals(0, calls)
        }
        var forwarded = ""
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() + "; other=unrelated" }, { 0 },
            AndroidOwnerContextHttp { forwarded = checkNotNull(it.header("Cookie")); response(it) })
        context.refresh(expected); assertEquals(cookies(), forwarded)
    }

    @Test fun exactAuthenticatedExchangeUsesSameSessionAndSuppressesPostActionLogout() {
        val requests = mutableListOf<Request>()
        var calls = 0
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
            AndroidOwnerContextHttp { request ->
                requests += request; calls++
                response(request, if (calls == 2) "{\"proposal\":\"public-only\"}" else sessionBody())
            })
        val body = "{}".toByteArray()
        assertEquals("{\"proposal\":\"public-only\"}", String(context.exchange(expected, "/v1/auth/sealed-root/challenge", "POST", body)))
        assertEquals(3, calls); assertEquals("POST", requests[1].method)
        assertTrue(requests.all { it.header("Cookie") == cookies() })
        var selected: String? = cookies(); var mutations = 0
        val withdrawing = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { selected }, { 0 },
            AndroidOwnerContextHttp { request ->
                if (request.method == "POST") { mutations++; selected = null; response(request, "{}") } else response(request)
            })
        refused { withdrawing.exchange(expected, "/v1/auth/sealed-root", "POST", body) }
        assertEquals(1, mutations); assertNull(withdrawing.currentAuthority())
    }

    @Test fun publicProposalDigestRequiresAuthenticationAndUnsafePathsNeverReceiveCredentials() {
        var calls = 0
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
            AndroidOwnerContextHttp { calls++; response(it) })
        refused { context.proposalDigest(ByteArray(16) { 4 }) }
        for (path in listOf("https://other.example.test/v1/auth/session", "//other.example.test/x", "/v1/auth/../owner", "/v1/auth/session?token=x")) {
            val before = calls
            refused { context.exchange(expected, path, "GET") }
            assertTrue(calls in before..before + 1) // At most a fixed same-origin session refresh.
        }
    }

    @Test fun authenticatedBootstrapAndTypedProposalBoundsIncludeLargestSupportedArtifacts() {
        for (length in listOf(65_536, 65_537)) {
            var calls = 0
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { request ->
                    calls++
                    response(request, if (request.url.encodedPath.endsWith("bootstrap"))
                        "{}" + " ".repeat(length - 2) else sessionBody())
                })
            if (length == 65_536) {
                assertEquals(length, context.exchange(expected, "/v1/owner/conversation/genesis/bootstrap", "POST",
                    ByteArray(20_480) { 32 }).size)
                assertEquals(3, calls)
                assertEquals(32, context.proposalDigest(ByteArray(20_480) { 4 }).size)
                try { context.proposalDigest(ByteArray(20_481)); fail("Oversized proposal accepted") }
                catch (_: IllegalArgumentException) { }
            } else {
                refused { context.exchange(expected, "/v1/owner/conversation/genesis/bootstrap", "POST", "{}".toByteArray()) }
                assertNull(context.currentAuthority())
            }
        }
        var calls = 0
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
            AndroidOwnerContextHttp { calls++; response(it) })
        refused { context.exchange(expected, "/v1/owner/conversation/genesis/bootstrap", "POST", ByteArray(20_481)) }
        assertEquals(0, calls)
    }

    @Test fun ownerWebViewAllowsOnlySelectedHttpsOriginWithoutForeignCredentialsOrSchemes() {
        val allowed = AndroidOwnerCustodyOwnerBrowser.Companion::allowed
        assertTrue(allowed(expected.origin, "https://example.test/owner/devices#login"))
        for (url in listOf("http://example.test/owner/devices", "https://other.example.test", "https://example.test:8443", "https://user@example.test/", "file:///synthetic", "content://synthetic", "javascript:alert(1)", "blob:https://example.test/public"))
            assertFalse(allowed(expected.origin, url))
    }

    @Test fun exactRegistrationRouteHasBoundedSpaceForLargestBase64Proposal() {
        for (length in listOf(32_768, 32_769)) {
            var registrations = 0
            val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource { cookies() }, { 0 },
                AndroidOwnerContextHttp { request ->
                    if (request.url.encodedPath == "/v1/owner/conversation/android-proposal") {
                        registrations++; response(request, "{}")
                    } else response(request)
                })
            if (length == 32_768) {
                assertEquals("{}", String(context.exchange(expected, "/v1/owner/conversation/android-proposal", "POST", ByteArray(length) { 32 })))
                assertEquals(1, registrations)
            } else {
                refused { context.exchange(expected, "/v1/owner/conversation/android-proposal", "POST", ByteArray(length) { 32 }) }
                assertEquals(0, registrations)
            }
        }
    }

    @Test fun ownerWebViewFileChooserAcceptsOnlyBoundedPublicOrEncryptedArtifacts() {
        val valid = ByteArray(20_480).apply { "ZTCF".toByteArray().copyInto(this); this[4] = 1 }
        assertTrue(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(valid)))
        assertFalse(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(valid + byteArrayOf(0))))
        assertTrue(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(ByteArray(64) { 7 })))
        assertTrue(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(ByteArray(65) { 4 })))
        for (secret in listOf(ByteArray(32) { 7 }, "1".repeat(64).toByteArray(), "ZTRK1-".toByteArray() + ByteArray(73), "{\"private\":\"synthetic\"}".toByteArray()))
            assertFalse(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(secret)))
    }

    @Test fun actualBackgroundPauseDiscardsBrowserRealmEvenIfCleanupAcknowledges() {
        var retired = 0
        val browser = AndroidOwnerCustodyOwnerBrowser(RuntimeEnvironment.getApplication(), expected.origin, {})
        val shadow = shadowOf(browser)
        browser.discardOnPause(false) { retired++ }
        shadow.lastEvaluatedJavascriptCallback?.onReceiveValue("true")
        assertTrue(shadow.wasDestroyCalled()); assertEquals(1, retired)
        browser.close(); assertEquals(1, retired)
    }

    @Test fun ownedSafTransitionRequiresCleanupAcknowledgementBeforeRetainingDormantRealm() {
        var retired = 0
        val browser = AndroidOwnerCustodyOwnerBrowser(RuntimeEnvironment.getApplication(), expected.origin, {})
        val shadow = shadowOf(browser)
        try {
            browser.discardOnPause(true) { retired++ }
            assertTrue(shadow.lastEvaluatedJavascript.contains("zrotext-owner-custody-pause"))
            assertFalse(shadow.lastEvaluatedJavascript.contains("Cookie"))
            shadow.lastEvaluatedJavascriptCallback.onReceiveValue("true")
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(501))
            assertFalse(shadow.wasDestroyCalled()); assertEquals(0, retired)
            assertTrue(shadow.wasOnPauseCalled()); assertTrue(browser.resumeAfterPicker())
        } finally { browser.close() }
    }

    @Test fun missingSafCleanupAcknowledgementDiscardsRealmAtBoundedDeadline() {
        var retired = 0
        val browser = AndroidOwnerCustodyOwnerBrowser(RuntimeEnvironment.getApplication(), expected.origin, {})
        browser.discardOnPause(true) { retired++ }
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(501))
        assertTrue(shadowOf(browser).wasDestroyCalled()); assertEquals(1, retired)
        browser.close()
    }

    @Test fun ownedSafCannotOutliveNativeDeadlineWhileRendererTimersArePaused() {
        var retired = 0
        val browser = AndroidOwnerCustodyOwnerBrowser(RuntimeEnvironment.getApplication(), expected.origin, {})
        browser.discardOnPause(true) { retired++ }
        shadowOf(browser).lastEvaluatedJavascriptCallback.onReceiveValue("true")
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(120_001))
        assertTrue(shadowOf(browser).wasDestroyCalled()); assertEquals(1, retired)
        assertFalse(browser.resumeAfterPicker()); browser.close()
    }
}
