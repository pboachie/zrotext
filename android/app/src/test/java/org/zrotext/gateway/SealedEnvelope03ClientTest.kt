// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Synthetic intercepted HTTPS exchanges. No server/current-adapter or maintained provider claim. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedEnvelope03ClientTest {
    private fun packet(f: Profile03ExecutionFixture) = JSONObject().put("v", 1)
        .put("envelope", Profile03ExecutionFixture.b64(f.envelope))
        .put("reviewed_intent", Profile03ExecutionFixture.b64(f.intentBytes))
        .put("reviewed_signature", Profile03ExecutionFixture.b64(f.intentSignature))
        .put("accepted_ms", f.admittedAt.toString()).put("interval_starts_ms", "100000")
        .put("interval_expires_ms", "100800").put("selection_epoch", "3")
        .put("interval_permission", ConversationInterval03TestFixture(f).permission())
        .put("current", JSONObject().put("v", 1)) // Deliberately unverified projection, never a current authority handle.
    private fun signature(f: Profile03ExecutionFixture, grant: SealedDispatch03Frames.Grant): ByteArray {
        val raw = Profile03ExecutionFixture.rawSign(f.enrollment, SealedEnvelopeFetch03.transcript(grant))
        fun integer(at: Int) = BigInteger(1, raw.copyOfRange(at, at + 32)).toByteArray()
            .let { byteArrayOf(2, it.size.toByte()) + it }
        val fields = integer(0) + integer(32)
        return byteArrayOf(0x30, fields.size.toByte()) + fields
    }
    @Test fun exactDeviceSignedPostTransportsTheExactCiphertextAndReviewedSidecarWithoutPromotingProjection() = Profile03ExecutionFixture().use { f ->
        var calls = 0
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            calls++
            val request = chain.request()
            assertEquals("POST", request.method)
            assertEquals("https://example.test/v1/sealed/dispatch/envelope03", request.url.toString())
            assertNull(request.header("Authorization")); assertNull(request.header("Cookie"))
            val buffer = Buffer(); checkNotNull(request.body).writeTo(buffer)
            val fetch = SealedEnvelopeFetch03.parse(buffer.readUtf8())
            assertArrayEquals(SealedEnvelopeFetch03.transcript(f.grant), SealedEnvelopeFetch03.transcript(fetch.grant))
            assertTrue(SealedEnvelopeFetch03.verify(fetch, Profile03ExecutionFixture.point(f.enrollment)))
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Cache-Control", "no-store").body(packet(f).toString().toResponseBody("application/json".toMediaType())).build()
        }.build()
        val received = checkNotNull(SealedEnvelope03Client("wss://example.test/v1/device-stream", client,
            { signature(f, it) }, {}).fetch(f.grant))
        assertEquals(1, calls)
        assertArrayEquals(f.envelope, received.envelope()); assertArrayEquals(f.intentBytes, received.intent())
        assertEquals(f.admittedAt, received.acceptedMs)
        assertEquals("Profile03FetchPacket(unverified-public-evidence)", received.toString())
        received.envelope().fill(0); received.intent().fill(0); received.signature().fill(0)
        assertArrayEquals(f.envelope, received.envelope())
    }
    @Test fun responseSubstitutionCoercionUnknownFieldsAndDuplicateNamesRefuse() = Profile03ExecutionFixture().use { f ->
        val original = packet(f).toString()
        val variants = listOf(
            original.replaceFirst("\"v\":1", "\"v\":1,\"v\":1"),
            original.replaceFirst(""""v":1""", """"v":1,"\u0076":1"""),
            packet(f).put("extra", "unsupported").toString(),
            packet(f).put("accepted_ms", f.admittedAt).toString(),
            packet(f).put("accepted_ms", "0100011").toString(),
            packet(f).put("selection_epoch", "9223372036854775808").toString(),
            packet(f).put("reviewed_signature", Profile03ExecutionFixture.b64(ByteArray(63))).toString(),
            packet(f).put("envelope", Profile03ExecutionFixture.b64(ByteArray(557))).toString(),
            packet(f).put("reviewed_intent", Profile03ExecutionFixture.b64(f.intentBytes.copyOf().apply { this[lastIndex] = 6 })).toString(),
            packet(f).apply { remove("interval_permission") }.toString(),
            packet(f).put("interval_permission", JSONObject.NULL).toString(),
            packet(f).apply { getJSONObject("interval_permission").put("request_id", java.util.UUID(0, 999)) }.toString(),
            original + "{}",
        )
        for (variant in variants) assertThrows(Exception::class.java) {
            Profile03FetchPacket.decode(variant.toByteArray(Charsets.UTF_8), f.grant)
        }
    }
    @Test fun redirectsCookiesCacheWrongMediaRefusalAndTransportFailureNeverRetry() = Profile03ExecutionFixture().use { f ->
        for (mode in listOf("redirect", "cookie", "cache", "type", "refused", "timeout", "oversized")) {
            var calls = 0
            val client = OkHttpClient.Builder().addInterceptor { chain ->
                calls++
                if (mode == "timeout") throw java.io.IOException("synthetic private diagnostic")
                val code = when (mode) { "redirect" -> 302; "refused" -> 404; else -> 200 }
                val type = if (mode == "type") "text/plain" else "application/json"
                val body = if (mode == "oversized") " ".repeat(Profile03Json.MAX_BYTES + 1) else packet(f).toString()
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(code).message("synthetic")
                    .header("Cache-Control", if (mode == "cache") "max-age=60" else "no-store")
                    .apply { if (mode == "cookie") header("Set-Cookie", "synthetic=discard") }
                    .body(body.toResponseBody(type.toMediaType())).build()
            }.build()
            assertNull(mode, SealedEnvelope03Client("wss://example.test/v1/device-stream", client,
                { signature(f, it) }, {}).fetch(f.grant))
            assertEquals(mode, 1, calls)
        }
    }
    @Test fun signatureOrSessionLossBeforeWireAndAfterReadCannotPublishAPacket() = Profile03ExecutionFixture().use { f ->
        var calls = 0
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            calls++
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Cache-Control", "no-store").body(packet(f).toString().toResponseBody("application/json".toMediaType())).build()
        }.build()
        assertNull(SealedEnvelope03Client("wss://example.test/v1/device-stream", client, { ByteArray(70) }, {}).fetch(f.grant))
        assertEquals(0, calls)
        var checks = 0
        assertNull(SealedEnvelope03Client("wss://example.test/v1/device-stream", client,
            { signature(f, it) }, { check(++checks < 2) }).fetch(f.grant))
        assertEquals(0, calls)
        checks = 0
        assertNull(SealedEnvelope03Client("wss://example.test/v1/device-stream", client,
            { signature(f, it) }, { check(++checks < 3) }).fetch(f.grant))
        assertEquals(1, calls)
    }
    @Test fun jsonRejectsUnpairedSurrogatesMalformedUtf8LenientTokensAndUnboundedInputs() {
        for (input in listOf("""{"v":1,"x":"\ud800"}""".toByteArray(),
            "{\"v\":01}".toByteArray(), "{\"v\":1.0}".toByteArray(), "{\"v\":1e0}".toByteArray(),
            "{\"v\":null}".toByteArray(), "{'v':1}".toByteArray(), "{\"v\":1,}".toByteArray(),
            byteArrayOf(123, 34, 120, 34, 58, 34, 0xc3.toByte(), 0x28, 34, 125),
            ByteArray(Profile03Json.MAX_BYTES + 1))) {
            assertThrows(Exception::class.java) { Profile03Json.objectValue(input) }
        }
    }
}
