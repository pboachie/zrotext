// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ManifestSuccessorTest {
    @Test fun independentProducerEnrollRenewAfterExpiryAndReplacePreserveEveryExactPrefix() {
        val v = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-manifest-install-01.json")!!.use { JSONObject(it.bufferedReader().readText()) }
        fun bytes(j: JSONObject, key: String) = Profile03ExecutionFixture.unhex(j.getString(key))
        fun id(key: String) = UUID.fromString(v.getString(key))
        val old = v.getJSONObject("prior02"); val first = v.getJSONObject("first03")
        val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(bytes(v, "root_pin_hex"), ReviewedIntent03.uuid(id("account_id")),
            bytes(v, "root_fingerprint_hex"), 1, 1, bytes(old, "semantic_sha256"), ByteArray(32), Profile03ExecutionFixture.sha(bytes(old, "signed_hex")), old.getString("accepted_ms").toLong())
        var authority = Draft03ManifestAuthority.verifyFrom02(bytes(first, "signed_hex"), bytes(old, "signed_hex"), checkpoint, first.getString("accepted_ms").toLong())
        var accepted = first.getString("accepted_ms").toLong()
        val scope = Profile03ManifestSuccessor.Scope(id("account_id"), id("device_id"), id("line_id"), id("binding_id"), id("election_challenge_id"), 2,
            bytes(v, "root_fingerprint_hex"), bytes(v, "election_commitment_hex"), bytes(v, "election_bundle_sha256_hex"), bytes(v, "configured_origin_sha256"),
            listOf(bytes(v, "independently_selected_enrollment_point_hex"), bytes(v, "distinct_original_sealed_approval_point_hex")))
        var prefix = scope.base(authority, accepted); assertArrayEquals(bytes(v, "base_ancestry_sha256_hex"), prefix)
        val entries = v.getJSONArray("successors")
        for (index in 0 until entries.length()) {
            val row = entries.getJSONObject(index)
            val statement = Profile03ManifestSuccessor.Statement.decode(bytes(row, "statement_hex"))
            assertArrayEquals(bytes(row, "transcript_sha256"), Profile03ExecutionFixture.sha(statement.transcript()))
            val entry = Profile03ManifestSuccessor.Entry(statement, bytes(row, "signature_hex"), bytes(row, "successor_signed_hex"), row.getString("accepted_ms").toLong())
            authority = Profile03ManifestSuccessor.verify(entry, authority, accepted, scope, row.getString("accepted_ms").toLong())
            prefix = Profile03ManifestSuccessor.step(prefix, entry); accepted = entry.acceptedMs
            assertArrayEquals(bytes(row, "ancestry_sha256_hex"), prefix); assertArrayEquals(bytes(row, "successor_semantic_sha256"), authority.digest)
        }
    }
    @Test fun possessionCannotSelectAnotherOriginBindingRootOrChangedReceivedBytes(): Unit = Profile03ManifestTestFixture().use { f ->
        val entry = f.entries(1).single()
        for (at in listOf(0, 5, 8, 88, 104, 136, 152, 192, 224, 256, 288, 320, 352, 384, 416, 448, 512)) {
            val changed = entry.statement.bytes().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            assertTrue("packet offset $at", runCatching { Profile03ManifestSuccessor.verify(Profile03ManifestSuccessor.Entry(
                Profile03ManifestSuccessor.Statement.decode(changed), entry.signature(), entry.successor(), entry.acceptedMs), f.base.authority, f.base.acceptedMs, f.scope, 800_000) }.isFailure)
        }
        val signature = entry.signature().apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertTrue(runCatching { Profile03ManifestSuccessor.verify(Profile03ManifestSuccessor.Entry(entry.statement, signature, entry.successor(), entry.acceptedMs),
            f.base.authority, f.base.acceptedMs, f.scope, 800_000) }.isFailure)
        assertFalse(Profile03ManifestSuccessor.step(f.base.ancestry(), entry).contentEquals(Profile03ManifestSuccessor.step(f.base.ancestry(),
            Profile03ManifestSuccessor.Entry(entry.statement, entry.signature(), entry.successor(), entry.acceptedMs + 1))))
    }
    @Test fun additiveJsonDoesNotBroadenTheLegacyClosedGrammar() {
        val history = "{\"history\":{\"entries\":[],\"complete\":true}}".toByteArray()
        assertEquals(true, Profile03Json.nested(Profile03ManifestJson.objectValue(history), "history")["complete"])
        assertTrue(runCatching { Profile03Json.objectValue(history) }.isFailure)
        for (raw in listOf("{\"v\":1,\"v\":1}", "{\"complete\":true}tail", "{\"entries\":[[]]}", "{\"unknown\":[]}", "{\"v\":01}", "{\"complete\":null}", "{\"v\":1.0}"))
            assertTrue(raw, runCatching { Profile03ManifestJson.objectValue(raw.toByteArray()) }.isFailure)
    }
}
