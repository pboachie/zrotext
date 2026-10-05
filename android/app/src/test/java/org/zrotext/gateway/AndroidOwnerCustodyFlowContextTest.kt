// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.json.JSONObject
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AndroidOwnerCustodyFlowContextTest {
    @Test fun contextProtocolPreservesStringAndIntegerTypesAndRejectsDuplicates() {
        val parsed = readAndroidOwnerStrictPublicObject("{\"v\":1,\"time\":\"2000\",\"scope\":{\"generation\":1}}")
        assertTrue(parsed.get("v") is Long); assertTrue(parsed.get("time") is String)
        for (text in listOf("{\"v\":1,\"v\":2}", "{\"scope\":{\"session\":\"a\",\"session\":\"b\"}}",
            "{\"v\":1.0}", "{\"v\":01}", "{\"v\":-1}", "{\"v\":true}", "{\"v\":1}ignored", "{\"v\":1", "{\"v\":1,}"))
            assertThrows(Exception::class.java) { readAndroidOwnerStrictPublicObject(text) }
    }
    @Test fun publicProposalBytesAreCanonicalBoundedAndIndependentFromRootToken() {
        val proposal = AndroidOwnerCustodyFixture.challenge()
        val text = java.util.Base64.getEncoder().encodeToString(proposal)
        assertArrayEquals(proposal, decodeAndroidOwnerPublicProposal(text, 663))
        for (bad in listOf(text + "\n", text.dropLast(1), "ZTRK1-AAAA", java.util.Base64.getEncoder().encodeToString(AndroidOwnerCustodyFixture.token)))
            assertThrows(Exception::class.java) { decodeAndroidOwnerPublicProposal(bad, 663) }
        assertThrows(IllegalArgumentException::class.java) { decodeAndroidOwnerPublicProposal(text, proposal.size - 1) }
    }
    @Test fun privateArchiveReaderAcceptsOnlyExactNonzero32AndClearsItsBufferOnReadFailure() {
        val retained = ByteArray(32) { 6 }
        val read = readAndroidOwnerArchiveRecoveryFile(retained.inputStream())
        assertArrayEquals(retained, read); read.fill(0)
        for (bytes in listOf(ByteArray(32), ByteArray(31) { 6 }, ByteArray(33) { 6 }, AndroidOwnerCustodyFixture.token))
            assertThrows(Exception::class.java) { readAndroidOwnerArchiveRecoveryFile(bytes.inputStream()) }
        var managed: ByteArray? = null
        val interrupted = object : java.io.InputStream() {
            override fun read(): Int = error("Unused")
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (managed != null) throw java.io.IOException("Synthetic interruption")
                managed = buffer; retained.copyInto(buffer, offset, 0, 16); return 16
            }
        }
        assertThrows(java.io.IOException::class.java) { readAndroidOwnerArchiveRecoveryFile(interrupted) }
        assertTrue(checkNotNull(managed).all { it == 0.toByte() })
    }
    @Test fun lineChallengeIsOnlyBoundedLookupSelectorWithExactPurposeAndNonzeroIdentity() {
        val flow = AndroidOwnerCustodyFlowFixture; val proposal = flow.proposal()
        assertEquals(flow.challenge, androidOwnerLineChallengeSelector(proposal))
        val domain = "ZTSE/line/owner-key/register/v1\u0000".toByteArray()
        val offset = domain.size + 5 * 16 + 8
        for (invalid in listOf(proposal.copyOfRange(0, offset + 15), proposal.copyOf().also { it[0] = 0 },
            proposal.copyOf().also { it.fill(0, offset, offset + 16) }, ByteArray(1025)))
            assertThrows(Exception::class.java) { androidOwnerLineChallengeSelector(invalid) }
        assertThrows(Exception::class.java) { readAndroidOwnerStrictPublicObject("{\"receipt\":null}") }
        assertEquals(JSONObject.NULL, readAndroidOwnerStrictPublicObject("{\"receipt\":null}", true).get("receipt"))
    }
    private fun liveLineContext(mutate: (JSONObject) -> Unit = {}): Pair<AndroidOwnerCustodyRegisteredFlowContext, MutableList<okhttp3.Request>> {
        val root = AndroidOwnerCustodyFixture; val flow = AndroidOwnerCustodyFlowFixture
        val requests = mutableListOf<okhttp3.Request>()
        fun token(prefix: String) = prefix + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 6 })
        val context = AndroidOwnerCustodyOwnerContext(AndroidOwnerContextCookieSource {
            "__Host-zrotext_session=${token("zts_")}; __Host-zrotext_csrf=${token("ztc_")}"
        }, { 100L }, AndroidOwnerContextHttp { request ->
            requests += request
            val body = if (request.url.encodedPath == "/v1/auth/session") JSONObject()
                .put("account_id", root.account.toString()).put("user_id", root.user.toString()).put("session_id", root.session.toString())
                .put("role", "owner").put("server_now_ms", "2000")
            else JSONObject().put("receipt", JSONObject.NULL).put("pending", flow.pending()).also(mutate)
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
                .header("Cache-Control", "no-store").body(body.toString().toResponseBody("application/json".toMediaType())).build()
        })
        return AndroidOwnerCustodyRegisteredFlowContext(context) to requests
    }
    @Test fun originalLineContextUsesExistingAuthenticatedStatusAndBindsExactBytesAndIndependentSelection() {
        val root = AndroidOwnerCustodyFixture; val flow = AndroidOwnerCustodyFlowFixture
        val (context, requests) = liveLineContext()
        val expected = context.current(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), root.kit.identity, flow.selection)
        assertEquals(flow.scope().toString(), String(expected.bytes()))
        val status = requests.single { it.url.encodedPath.endsWith("/status") }
        assertEquals("/v1/owner/conversation/sealed-line/owner-key/${flow.challenge}/status", status.url.encodedPath)
        assertEquals("POST", status.method); assertNull(status.header("Authorization"))
        val body = okio.Buffer().also { checkNotNull(status.body).writeTo(it) }.readUtf8()
        assertEquals(setOf("expected_session_id"), JSONObject(body).keys().asSequence().toSet())
        assertEquals(root.session.toString(), JSONObject(body).getString("expected_session_id"))
        assertEquals(3, requests.count { it.url.encodedPath == "/v1/auth/session" })
        assertFalse(requests.any { it.url.encodedPath.contains("android-proposal") })
    }
    @Test fun lineStatusCannotPromoteAbsentConsumedForeignOrChangedPublicContext() {
        val root = AndroidOwnerCustodyFixture; val flow = AndroidOwnerCustodyFlowFixture
        val changes: List<(JSONObject) -> Unit> = listOf(
            { it.put("pending", JSONObject.NULL) }, { it.put("receipt", JSONObject()) },
            { it.getJSONObject("pending").put("session_id", flow.challenge.toString()) },
            { it.getJSONObject("pending").put("account_id", flow.device.toString()) },
            { it.getJSONObject("pending").put("root_fingerprint_hex", "00".repeat(32)) },
            { it.getJSONObject("pending").put("proposal_b64", java.util.Base64.getEncoder().encodeToString(flow.proposal().also { b -> b[0] = 0 })) },
            { it.getJSONObject("pending").put("expires_ms", "2000") },
            { it.getJSONObject("pending").put("server_now_ms", 2000) }
        )
        for (change in changes) {
            val (context, _) = liveLineContext(change)
            assertThrows(Exception::class.java) { context.current(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), root.kit.identity, flow.selection) }
        }
        val (context, _) = liveLineContext()
        assertThrows(Exception::class.java) { context.current(AndroidOwnerCustodyFlowKind.LINE, flow.proposal(), root.kit.identity,
            flow.selection.copy(device = flow.challenge)) }
    }
}
