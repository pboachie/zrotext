// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.Protocol
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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class GatewaySummaryClientTest {
    private val device = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val other = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private val token = "ztk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
    private fun body() = JSONObject().put("scope", "device").put("device_id", device.toString()).put("timezone", "UTC")
        .put("day_start_ms", 0L).put("day_end_ms", 86_400_000L).put("observed_at_ms", 1_000L)
        .put("max_age_ms", 30_000L).put("count_bound", 1_000L)
        .put("submitted_today", JSONObject().put("value", 0).put("capped", false))
        .put("pending", JSONObject().put("value", 1_000).put("capped", true))
        .put("in_flight", JSONObject().put("value", 1).put("capped", false))
    private fun refused(json: JSONObject) {
        try { GatewaySummaryParser.parse(json.toString(), device); fail("invalid summary accepted") }
        catch (_: IllegalArgumentException) { }
    }
    private fun response(code: Int = 200, text: String = body().toString(), type: String = "application/json") =
        Response.Builder().request(GatewaySummaryClient.request("https://example.test", token, device))
            .protocol(Protocol.HTTP_1_1).code(code).message("synthetic")
            .body(text.toResponseBody(type.toMediaType())).build()
    @Test fun explicitReadRequestHasOnlySelectedDeviceAndSeparateApiRealm() {
        val request = GatewaySummaryClient.request("https://example.test", token, device)
        assertEquals("GET", request.method)
        assertEquals("/v1/message-summary", request.url.encodedPath)
        assertEquals(setOf("device_id"), request.url.queryParameterNames)
        assertEquals(device.toString(), request.url.queryParameter("device_id"))
        assertEquals("Bearer $token", request.header("Authorization"))
        assertNull(request.header("Cookie"))
        assertEquals("no-store", request.header("Cache-Control"))
        for (credential in listOf("ztd_", "ztp_", "zts_", "ztw_", "")) {
            try { GatewaySummaryClient.request("https://example.test", credential + token.removePrefix("ztk_"), device); fail("foreign realm accepted") }
            catch (_: IllegalArgumentException) { }
        }
    }
    @Test fun originCannotRedirectCredentialIntoAPathQueryOrUserInfo() {
        for (origin in listOf("http://example.test", "wss://example.test", "https://example.test/path", "https://example.test/?scope=all", "https://example.test/#fragment", "https://user@example.test")) {
            try { GatewaySummaryClient.request(origin, token, device); fail("unsafe origin accepted") }
            catch (_: IllegalArgumentException) { }
        }
        try { GatewaySummaryClient.request("https://example.test", token, UUID(0, 0)); fail("nil device accepted") }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun parserPreservesTrueZeroAndCappedWriterEvidence() {
        val snapshot = GatewaySummaryParser.parse(body().toString(), device)
        assertEquals("0", snapshot.submittedToday.label())
        assertEquals("1000+ (capped)", snapshot.pending.label())
        assertEquals(30_000L, snapshot.remainingMs)
        assertEquals(device, snapshot.device)
    }
    @Test fun foreignAccountScopeDeviceAndTimezoneAreRefused() {
        refused(body().put("scope", "account").put("device_id", JSONObject.NULL))
        refused(body().put("device_id", other.toString()))
        refused(body().put("timezone", "local"))
        refused(body().put("body", "must not render"))
    }
    @Test fun countBooleansIntegersAndCapAreStrict() {
        for (value in listOf(-1, 1_001, "1", 1.5, JSONObject.NULL)) refused(body().put("pending", JSONObject().put("value", value).put("capped", false)))
        refused(body().put("pending", JSONObject().put("value", 1).put("capped", true)))
        refused(body().put("pending", JSONObject().put("value", 1).put("capped", "false")))
        refused(body().put("pending", JSONObject().put("value", 1).put("capped", false).put("extra", true)))
        refused(body().put("count_bound", 999))
    }
    @Test fun utcDayAndFreshnessBoundsCannotWiden() {
        refused(body().put("max_age_ms", 30_001))
        refused(body().put("day_end_ms", 86_400_001))
        refused(body().put("observed_at_ms", 86_400_000))
        refused(body().put("day_start_ms", -1))
        refused(body().put("day_start_ms", "0"))
        val atRollover = GatewaySummaryParser.parse(body().put("observed_at_ms", 86_399_999).toString(), device)
        assertEquals(1L, atRollover.remainingMs)
    }
    @Test fun responseFailureDoesNotExposeServerBodyOrFollowRedirect() {
        for ((code, expected) in listOf(401 to GatewaySummaryClient.Failure.UNAUTHORIZED, 403 to GatewaySummaryClient.Failure.FORBIDDEN, 302 to GatewaySummaryClient.Failure.UNAVAILABLE, 503 to GatewaySummaryClient.Failure.UNAVAILABLE)) {
            response(code, "synthetic diagnostic must not escape").use {
                assertEquals(GatewaySummaryClient.Result.Refused(expected), GatewaySummaryClient.decode(it, device))
            }
        }
    }
    @Test fun oversizedMalformedAndWrongContentTypeAreRefused() {
        for (reply in listOf(response(text = " ".repeat(4097)), response(text = "not json"), response(type = "text/html"), response(text = body().put("device_id", other.toString()).toString()))) {
            reply.use { assertEquals(GatewaySummaryClient.Result.Refused(GatewaySummaryClient.Failure.INVALID_RESPONSE), GatewaySummaryClient.decode(it, device)) }
        }
        response().use { assertTrue(GatewaySummaryClient.decode(it, device) is GatewaySummaryClient.Result.Success) }
    }
}
