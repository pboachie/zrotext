// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import okhttp3.Protocol
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

/** Managed lifecycle/framing fixture. Real AEAD/signatures are tested in the native crate. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AndroidReviewRootCustodyControllerTest {
    private val f = AndroidOwnerCustodyFixture
    private val events = ArrayList<String>()
    private var root = JSONObject().put("kind", "no_root_history")
    private var revision = "1"
    private var existing = false
    private var created = 0
    private var signed = 0
    private var recovered = 0
    private var afterSign: () -> Unit = {}
    private var atSign: () -> Unit = {}
    private var stored: ByteArray? = null
    private fun id(n: Long) = UUID(0, n)
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun hash(bytes: ByteArray) = b64(AndroidOwnerCustodyKit.hash(bytes))
    private fun candidate(session: UUID) = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ByteBuffer.allocate(48).putLong(session.mostSignificantBits).putLong(session.leastSignificantBits).put(ByteArray(32) { 9 }).array())
    private fun token() = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 3 })
    private fun cookies() = "__Host-ztrw-browser=" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64) { 4 }) +
        "; __Host-ztrw-broker=" + candidate(id(8)) + "; __Host-ztrw-owner=" + candidate(f.session) +
        "; __Host-ztrw-broker-csrf=" + token() + "; __Host-ztrw-owner-csrf=" + token()
    private fun contextBody() = JSONObject().put("version", 1).put("realm", id(1)).put("database_commitment_b64", b64(ByteArray(32) { 2 }))
        .put("config_digest_b64", b64(ByteArray(32) { 3 })).put("config_revision", revision).put("origin", f.origin).put("account", f.account)
        .put("owner_user", f.user).put("review_owner_session", f.session).put("broker_principal", id(5)).put("credential_id", id(6))
        .put("credential_revision", "1").put("broker_session", id(8)).put("auth_event", id(9)).put("issued_ms", "500")
        .put("absolute_expiry_ms", "100000").put("idle_deadline_ms", "90000").put("server_now_ms", "2000")
        .put("capabilities", JSONArray(listOf("bootstrap_session", "root_issue", "root_complete", "root_receipt", "root_custody_export")))
        .put("locator_retained",false).put("root_state", root)
    private val context = AndroidReviewWorkspaceOwnerContext(AndroidReviewContextCookies { cookies() }, { 100 }, AndroidReviewContextHttp {
        events += "https"
        val request=okio.Buffer();checkNotNull(it.body).writeTo(request)
        val result=contextBody().put("request_id",JSONObject(request.readUtf8()).getString("request_id"))
        Response.Builder().request(it).protocol(Protocol.HTTP_1_1).code(200).message("synthetic")
            .header("Cache-Control", "no-store").body(result.toString().toResponseBody("application/json".toMediaType())).build()
    })
    private val oldNative = object : AndroidOwnerCustodyNativePort {
        override val available = true
        override fun create(account: ByteArray, origin: String): Array<ByteArray> {
            created++; require(account.contentEquals(f.kit.identity.accountBytes()) && origin == f.origin)
            return arrayOf(f.kit.backup(), f.kit.card(), f.token, f.kit.identity.fingerprintBytes(), f.kit.pin)
        }
        override fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity): Boolean {
            events += "recover"; recovered++; return token.contentEquals(f.token) && kit.identity == expected
        }
        override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
            authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long = error("Ordinary authority forbidden")
        override fun review(handle: Long): ByteArray = error("Ordinary review forbidden")
        override fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> =
            error("Ordinary signer forbidden")
        override fun close(handle: Long) {}
        override fun closeAll() {}
    }
    private val native = object : AndroidReviewRootCustodyNativePort {
        override val available = true
        private var unsigned = ByteArray(0)
        override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
            authority: AndroidReviewWorkspaceAuthority, elapsed: Long): Long {
            unsigned = challenge.copyOf(); require(authority.account == expected.account); return 1
        }
        override fun review(handle: Long) = unsigned.copyOf()
        override fun sign(handle: Long, token: ByteArray, authority: AndroidReviewWorkspaceAuthority, elapsed: Long): Array<ByteArray> {
            events += "sign"; signed++; require(token.contentEquals(f.token)); atSign(); afterSign()
            return arrayOf(ByteArray(64) { 1 }, ByteArray(64) { 2 })
        }
        override fun close(handle: Long) {}
        override fun closeAll() {}
    }
    private val store = object : AndroidReviewRootKitStore {
        override fun hasExisting(context: AndroidReviewWorkspaceAuthority) = existing
        override fun put(kit: AndroidOwnerCustodyKit, context: AndroidReviewWorkspaceAuthority, permitted: () -> Boolean) {
            check(permitted()); stored?.let { require(AndroidOwnerCustodyKit.decode(it).matches(kit)) }; stored = kit.encode(); existing = true
        }
    }
    private fun controller() = AndroidReviewRootCustodyController(f.origin, context, native, oldNative, store, { 100 })
    private fun pending(): JSONObject {
        val unsigned = f.challenge()
        val statement = "ZTSE/root-custody/v1\u0000".toByteArray() + ByteBuffer.allocate(4).putInt(unsigned.size).array() +
            unsigned + AndroidOwnerCustodyKit.hash(f.kit.backup()) + AndroidOwnerCustodyKit.hash(f.kit.card()) + f.kit.identity.fingerprintBytes()
        return JSONObject().put("kind", "pending_enrollment").put("challenge_id", AndroidOwnerCustodyReview.parse(unsigned).challengeId)
            .put("root_pin_b64", b64(f.kit.pin)).put("root_fingerprint_b64", b64(f.kit.identity.fingerprintBytes()))
            .put("encrypted_backup_sha256_b64", hash(f.kit.backup())).put("public_card_sha256_b64", hash(f.kit.card()))
            .put("unsigned_enrollment_sha256_b64", hash(unsigned)).put("custody_statement_sha256_b64", hash(statement)).put("expires_ms", "61000")
    }
    private fun recover(c: AndroidReviewRootCustodyController) = c.recover(f.kit.backup(), f.kit.card(), f.kit.identity, true) { events += "token"; f.token }
    private fun review(c: AndroidReviewRootCustodyController) { recover(c); root = pending(); c.review(f.challenge(), f.kit.identity) }

    @Test fun genuineKitWorkflowRequiresExternalRecoveryAndDisplaysBothPublicationCommitments() {
        val c = controller(); c.create(); assertEquals(1, created); assertFalse(c.snapshot().kit.recoveryVerified)
        c.reveal(); c.confirmTokenRecorded(); c.exportReadback(f.kit.backup())
        assertFalse(c.snapshot().kit.recoveryVerified); assertEquals(0, recovered)
        review(c)
        val display = checkNotNull(c.snapshot().review)
        assertEquals(f.kit.identity.fingerprint, display.fingerprint)
        assertEquals(AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(f.kit.backup())), display.backupSha256)
        assertEquals(AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(f.kit.card())), display.cardSha256)
        assertEquals(UUID.fromString("44444444-4444-4444-8444-444444444444"), display.bundle)
        events.clear(); val secret = f.token
        c.sign(true) { events += "token"; secret }
        assertEquals(listOf("https", "token", "sign", "https"), events)
        assertTrue(secret.all { it == 0.toByte() }); assertEquals(1, signed); assertNotNull(c.snapshot().signatures)
        assertThrows(IllegalStateException::class.java) { c.sign(true) { error("Must not read token twice") } }
    }
    @Test fun pendingHistoryEnrolledUnavailableAndRetainedLocalKitNeverGenerateReplacement() {
        for (state in listOf(pending(), JSONObject().put("kind", "history"), JSONObject().put("kind", "unavailable"),
            JSONObject().put("kind", "enrolled").put("root_pin_b64", b64(f.kit.pin)).put("root_fingerprint_b64", b64(f.kit.identity.fingerprintBytes())).put("generation", "1"))) {
            root = state
            assertThrows(IllegalArgumentException::class.java) { controller().create() }
        }
        root = JSONObject().put("kind", "no_root_history"); existing = true
        assertThrows(IllegalArgumentException::class.java) { controller().create() }; assertEquals(0, created)
    }
    @Test fun missingRetentionOrIndependentFingerprintNeverReadsToken() {
        val c = controller()
        assertThrows(IllegalArgumentException::class.java) { c.recover(f.kit.backup(), f.kit.card(), f.kit.identity, false) { error("secret") } }
        assertThrows(IllegalArgumentException::class.java) { c.recover(f.kit.backup(), f.kit.card(), f.kit.identity.copy(fingerprint = "55".repeat(32)), true) { error("secret") } }
        assertEquals(0, recovered)
    }
    @Test fun pendingCustodyBundleSubstitutionCannotOpenNativeReview() {
        val c = controller(); recover(c); root = pending().put("public_card_sha256_b64", b64(ByteArray(32) { 9 }))
        assertThrows(IllegalArgumentException::class.java) { c.review(f.challenge(), f.kit.identity) }
        assertNull(c.snapshot().review)
    }
    @Test fun configAbaAfterSignSuppressesPublicHandoffAndKeepsFailureHonest() {
        val c = controller(); review(c); afterSign = { revision = "3" }
        assertThrows(IllegalStateException::class.java) { c.sign(true) { f.token } }
        assertEquals(1, signed); assertNull(c.snapshot().signatures); assertFalse(c.snapshot().kit.recoveryVerified)
    }
    @Test fun lifecycleLossAfterRecoveryAndBeforeOutputSuppressesSignatures() {
        val c = controller(); review(c); atSign = { c.contextLost() }
        assertThrows(IllegalStateException::class.java) { c.sign(true) { f.token } }
        assertNull(c.snapshot().signatures); assertFalse(c.snapshot().busy)
    }
    @Test fun declinedConsentNeverReadsTokenAndBurnsReview() {
        val c = controller(); review(c)
        assertThrows(IllegalArgumentException::class.java) { c.sign(false) { error("secret") } }
        assertNull(c.snapshot().review); assertEquals(0, signed)
    }
}
