// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.Base64
import java.util.UUID
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.MediaType.Companion.toMediaType
import okio.Buffer
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = android.app.Application::class)
class SealedEnvelopeFetchTest {
    private fun vector() = JSONObject(checkNotNull(javaClass.classLoader?.getResourceAsStream(
        "sealed-dispatch-01.json")).use { it.readBytes() }.toString(Charsets.UTF_8))
    private fun grant() = SealedExecutionGrantFrame.parse(vector().getJSONObject("grant"))
    private fun envelope() = ByteArray(557) { (it % 251).toByte() }
    private fun bound() = grant().copy(envelopeDigest = SealedExecutionGrantValidator.sha256(envelope()))
    private fun refused(block: () -> Unit) {
        try { block(); fail("invalid fetch accepted") } catch (_: IllegalArgumentException) { }
    }

    @Test fun signatureTranscriptMatchesTheExistingServerVectorAndBindsEveryField() {
        val original = grant()
        val expected = vector().getString("transcriptHex")
        assertEquals(expected, Draft02OutboundPreparation.hex(SealedEnvelopeFetch.transcript(original)))
        val others = listOf(
            original.copy(accountId = UUID(5, 5)), original.copy(deviceId = UUID(6, 6)),
            original.copy(lineId = UUID(7, 7)), original.copy(messageId = UUID(8, 8)),
            original.copy(attemptId = UUID(9, 9)), original.copy(connectionEpoch = 2),
            original.copy(deploymentEpoch = 2), original.copy(bindingGeneration = 2),
            original.copy(attemptGeneration = 2), original.copy(expiresAtMs = original.expiresAtMs + 1),
            original.copy(readerKeyId = ByteArray(32) { 3 }), original.copy(envelopeDigest = ByteArray(32) { 4 }),
            original.copy(unsignedDigest = ByteArray(32) { 5 }), original.copy(segmentCount = 2))
        for (other in others) assertFalse(SealedEnvelopeFetch.transcript(original).contentEquals(
            SealedEnvelopeFetch.transcript(other)))
        for (other in listOf(original.copy(readerRole = 2), original.copy(segmentCount = 0),
            original.copy(accountId = UUID(0, 0)))) refused { SealedEnvelopeFetch.transcript(other) }
    }

    @Test fun exactDeviceSignedPostHasNoBearerAndReturnsOnlyTheBoundCiphertext() {
        var calls = 0
        val original = bound()
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            calls++
            val request = chain.request()
            assertEquals("POST", request.method)
            assertEquals("https://example.test/v1/sealed/dispatch/envelope", request.url.toString())
            assertNull(request.header("Authorization")); assertNull(request.header("Cookie"))
            assertEquals("no-store", request.header("Cache-Control"))
            val buffer = Buffer(); checkNotNull(request.body).writeTo(buffer)
            val json = JSONObject(buffer.readUtf8())
            assertEquals(setOf("grant", "signature_der"), json.keys().asSequence().toSet())
            val framed = SealedExecutionGrantFrame.parse(json.getJSONObject("grant"))
            assertArrayEquals(SealedEnvelopeFetch.transcript(original), SealedEnvelopeFetch.transcript(framed))
            assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(70) { 7 }),
                json.getString("signature_der"))
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Content-Type", "application/vnd.zrotext.sealed.v1")
                .body(envelope().toResponseBody("application/vnd.zrotext.sealed.v1".toMediaType())).build()
        }.build()
        val transport = SealedEnvelopeClient("wss://example.test/v1/device-stream", client,
            { ByteArray(70) { 7 } }, {})
        assertArrayEquals(envelope(), transport.fetch(original)); assertEquals(1, calls)
        assertEquals("SealedEnvelopeClient(redacted)", transport.toString())
    }

    @Test fun refusedStaleOversizedAndSubstitutedResponsesNeverRetry() {
        for (mode in listOf("refused", "redirect", "unavailable", "type", "oversized", "digest", "timeout")) {
            var calls = 0
            val client = OkHttpClient.Builder().addInterceptor { chain ->
                calls++
                if (mode == "timeout") throw java.io.IOException("synthetic private diagnostic")
                val code = when (mode) { "refused" -> 404; "redirect" -> 302; "unavailable" -> 503; else -> 200 }
                val bytes = when (mode) { "oversized" -> ByteArray(34_214); "digest" -> ByteArray(557); else -> envelope() }
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(code).message("synthetic")
                    .header("Content-Type", if (mode == "type") "text/plain" else "application/vnd.zrotext.sealed.v1")
                    .header("Location", "https://other.test/").body(bytes.toResponseBody()).build()
            }.build()
            assertNull(SealedEnvelopeClient("wss://example.test/stream", client, { ByteArray(70) }, {}).fetch(bound()))
            assertEquals(mode, 1, calls)
        }
        var calls = 0; var checks = 0
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            calls++
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Content-Type", "application/vnd.zrotext.sealed.v1").body(envelope().toResponseBody()).build()
        }.build()
        assertNull(SealedEnvelopeClient("wss://example.test/stream", client, { ByteArray(70) }, {
            checks++; check(checks < 3) { "Session revoked while reading" }
        }).fetch(bound()))
        assertEquals(1, calls)
    }

    @Test fun callerScopeAndSignerWaitAreCheckedBeforeAnyNetworkRequest() {
        var calls = 0
        val client = OkHttpClient.Builder().addInterceptor { calls++; error("unexpected request") }.build()
        var valid = true
        val transport = SealedEnvelopeClient("wss://example.test/stream", client,
            { valid = false; ByteArray(70) }, { check(valid) })
        assertNull(transport.fetch(bound())); assertEquals(0, calls)
        for (url in listOf("http://example.test", "wss://user@example.test/stream", "wss://example.test/?token=x",
            "wss://example.test/#fragment")) refused { SealedEnvelopeClient(url, client, { ByteArray(70) }, {}) }
    }

    @Test fun providerCallbacksCannotSubstituteTheOwnedGrant() {
        val original = bound()
        val expected = SealedEnvelopeFetch.transcript(original)
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            val buffer = Buffer(); checkNotNull(chain.request().body).writeTo(buffer)
            assertArrayEquals(expected, SealedEnvelopeFetch.transcript(SealedExecutionGrantFrame.parse(
                JSONObject(buffer.readUtf8()).getJSONObject("grant"))))
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Content-Type", "application/vnd.zrotext.sealed.v1").body(envelope().toResponseBody()).build()
        }.build()
        val transport = SealedEnvelopeClient("wss://example.test/stream", client,
            { it.readerKeyId.fill(0); ByteArray(70) }, { it.envelopeDigest.fill(0) })
        assertArrayEquals(envelope(), transport.fetch(original))
        assertArrayEquals(expected, SealedEnvelopeFetch.transcript(original))
    }
}
