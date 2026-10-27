// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room/production progression with a synthetic provider. No real Keystore operation,
 * pairing, network connection, installed pin or capture authority is established here. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ProtectionOriginProviderStepsTest {
    private val vector = javaClass.classLoader!!.getResourceAsStream("device-protection-origin-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private val p get() = vector.getJSONObject("parameters")
    private fun bytes(key: String) = java.util.Base64.getUrlDecoder().decode(p.getString(key))
    private val command get() = ProtectionSetupCommand(setupId = p.getString("setup_id"), openingId = p.getString("opening_id"),
        commandId = p.getString("command_id"), accountId = p.getString("account_id"), deviceId = p.getString("device_id"),
        originSha256 = hashBytes(bytes("origin_digest")), enrolledSigningKeyId = hashBytes(bytes("enrolled_key_id")), requestedMs = 2_990_000)
    private fun <T> database(body: (SmsJournalDatabase) -> T): T {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        try { return body(db) } finally { db.close() }
    }
    private fun opened(db: SmsJournalDatabase): Pair<ProtectionSetupCommand, ProtectionOriginWire.Opening> {
        val dao = db.protectionSetup(); val sent = dao.openingWillBeSubmitted(dao.reserveCommand(command) {}) {}
        val fields = linkedMapOf<String, Any>("account_id" to command.accountId, "device_id" to command.deviceId,
            "source_pairing_id" to p.getString("source_pairing_id"), "origin_digest" to p.getString("origin_digest"),
            "enrolled_point" to p.getString("enrolled_point"), "enrolled_key_id" to p.getString("enrolled_key_id"),
            "opening_nonce" to p.getString("opening_nonce"), "created_ms" to "2995000", "pairing_created_ms" to "2980000",
            "pairing_claimed_ms" to "2981000", "pairing_approved_ms" to "2982000", "pairing_expires_ms" to "2983000")
        val opening = ProtectionOriginWire.retainedOpening(ProtectionOriginJson.render(fields), command, bytes("enrolled_point"))
        val raw = opening.bytes()
        return dao.retainOpeningCandidate(sent, sent.openingId, encode(raw), hash(raw)) {} to opening
    }
    private inner class Provider : ProtectionOriginProviderPort {
        val calls = mutableListOf<String>()
        var afterReturn: () -> Unit = {}
        var aliasesPresent = false
        var afterAliasCheck: () -> Unit = {}
        var throwInside = false
        override fun aliasesMatchRetained(rows: List<ProtectionSetupProvider>) {
            check(!aliasesPresent && rows.none { it.evidenceB64url == null }); afterAliasCheck()
        }
        override fun generate(kind: String, probeContext: ByteArray): ByteArray {
            calls += kind
            check(!throwInside)
            assertArrayEquals(ProtectionOriginProof.Association.decode(java.util.Base64.getUrlDecoder()
                .decode(vector.getString("association"))).probeContext(bytes("opening_nonce")), probeContext)
            return result(kind).also { afterReturn() }
        }
        override fun requireResult(kind: String, expected: ByteArray, probeContext: ByteArray) { assertArrayEquals(result(kind), expected) }
        private fun result(kind: String) = bytes(when (kind) {
            "canary" -> "canary_point"; "suppression_hmac" -> "hmac_probe"
            "journal_aes" -> "journal_aes_probe"; else -> "withdrawal_aes_probe"
        })
    }
    @Test fun pauseDuringProviderKeepsExactReturnedResultAndStartsNoNextOperation() = database { db ->
        val (original, opening) = opened(db); var foreground = true
        val provider = Provider().apply { afterReturn = { foreground = false } }
        val steps = ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }
        assertThrows(IllegalStateException::class.java) { steps.complete(original, opening) { check(foreground) } }
        assertEquals(listOf("canary"), provider.calls)
        val retained = db.protectionSetup().providers().single()
        assertEquals(encode(bytes("canary_point")), retained.evidenceB64url)
        assertNull(db.protectionOrigins().installed()); assertNull(db.protectionOrigins().protection())
        assertTrue(db.protectionOrigins().attempts().isEmpty())
    }
    @Test fun unknownProviderCannotBeRepeatedByAnotherExplicitAction() = database { db ->
        val (original, opening) = opened(db); val provider = Provider().apply { throwInside = true }
        val steps = ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }
        assertThrows(IllegalStateException::class.java) { steps.complete(original, opening) {} }
        provider.throwInside = false
        assertThrows(IllegalStateException::class.java) { steps.complete(original, opening) {} }
        assertEquals(listOf("canary"), provider.calls)
        assertNull(db.protectionSetup().providers().single().evidenceB64url)
    }
    @Test fun oldAliasWithoutOriginalResultRefusesBeforeAProviderBurn() = database { db ->
        val (original, opening) = opened(db); val provider = Provider().apply { aliasesPresent = true }
        assertThrows(IllegalStateException::class.java) {
            ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }.complete(original, opening) {}
        }
        assertTrue(db.protectionSetup().providers().isEmpty()); assertTrue(provider.calls.isEmpty())
    }
    @Test fun withdrawnAliasInspectionCannotEnterGeneration() = database { db ->
        val (original, opening) = opened(db); var foreground = true
        val provider = Provider().apply { afterAliasCheck = { foreground = false } }
        assertThrows(IllegalStateException::class.java) {
            ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }.complete(original, opening) { check(foreground) }
        }
        assertTrue(db.protectionSetup().providers().isEmpty()); assertTrue(provider.calls.isEmpty())
    }
    @Test fun freshDecisionVerifiesOriginalResultAndCompletesOnlyTheRemainingProviders() = database { db ->
        val (original, opening) = opened(db); var foreground = true
        val provider = Provider().apply { afterReturn = { foreground = false } }
        val steps = ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }
        assertThrows(IllegalStateException::class.java) { steps.complete(original, opening) { check(foreground) } }
        foreground = true; provider.afterReturn = {}
        val rows = steps.complete(original, opening) { check(foreground) }
        assertEquals(ProtectionSetupProvider.KINDS, provider.calls)
        assertEquals(4, rows.size); assertTrue(rows.all { it.evidenceB64url != null })
        assertNull(db.protectionOrigins().installed()); assertNull(db.captures03().counter(original.accountId, original.deviceId))
    }
    @Test fun pauseThenResumeCannotReviveTheDecisionBlockedInsideProvider() = database { db ->
        val (original, opening) = opened(db)
        val foreground = ConversationInterval03Foreground().apply { update(true) }
        val decision = foreground.decision()
        val provider = Provider().apply { afterReturn = { foreground.update(false); foreground.update(true) } }
        assertThrows(IllegalStateException::class.java) {
            ProtectionOriginProviderSteps(db.protectionSetup(), provider) { 3_000_001 }.complete(original, opening) { check(decision.isCurrent()) }
        }
        assertFalse(decision.isCurrent()); assertTrue(foreground.decision().isCurrent())
        assertEquals(listOf("canary"), provider.calls); assertNotNull(db.protectionSetup().providers().single().evidenceB64url)
        assertNull(db.protectionOrigins().installed()); foreground.close()
    }
    private fun encode(value: ByteArray) = Profile03ElectionEncoding.encode(value)
    private fun hashBytes(value: ByteArray) = Draft02OutboundPreparation.hex(value)
    private fun hash(value: ByteArray) = hashBytes(ProtectionOriginProof.sha(value))
}
