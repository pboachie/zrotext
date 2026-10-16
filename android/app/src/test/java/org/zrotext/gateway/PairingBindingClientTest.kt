// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import java.util.UUID

/** SETUP-BIND-01, SETUP-TRUST-01, SETUP-RESUME-01, REC-APPROVAL, REC-KEYS, REC-REVOKED. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PairingBindingClientTest {
    private val account = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val pairing = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private val challenge = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    private val device = UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    private val fingerprint = "AB".repeat(32)
    private val nonce = ByteArray(32) { it.toByte() }
    private val nonceText = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
    private val locator = PairingLocator("https://gateway.example.test", pairing, fingerprint)

    private fun challengeJson() = JSONObject().put("schema_version", 1).put("account_id", account.toString())
        .put("pairing_id", pairing.toString()).put("challenge_id", challenge.toString())
        .put("challenge_nonce", nonceText).put("key_fingerprint", fingerprint)
    private fun result(status: String = "approved") = JSONObject().put("schema_version", 1)
        .put("status", status).put("account_id", account.toString()).put("pairing_id", pairing.toString())
        .put("device_id", if (status == "approved") device.toString() else JSONObject.NULL)
        .put("comparison_code", if (status in listOf("pending", "approved")) "12345678" else JSONObject.NULL)
        .put("key_fingerprint", fingerprint)

    @Test fun approvedDeviceIsCarriedForwardOnlyAfterDistinctExistingKeyProof() {
        val calls = mutableListOf<String>()
        var signatures = 0
        val client = PairingBindingClient({ fingerprint }, { a, p, c, f, n ->
            assertEquals(account, a); assertEquals(pairing, p); assertEquals(challenge, c)
            assertArrayEquals(ByteArray(32) { 0xab.toByte() }, f); assertArrayEquals(nonce, n)
            signatures++; byteArrayOf(1, 2, 3)
        }) { url, body ->
            calls += url
            if (calls.size == 1) {
                assertEquals(setOf("key_fingerprint"), body.keys().asSequence().toSet())
                assertEquals(fingerprint, body.getString("key_fingerprint")); challengeJson()
            } else {
                assertEquals(setOf("account_id", "challenge_id", "challenge_nonce", "signature_der"), body.keys().asSequence().toSet())
                assertEquals("AQID", body.getString("signature_der")); result()
            }
        }
        assertEquals(PairingBinding(PairingBindingStatus.APPROVED, device, "12345678"), client.read(locator))
        assertEquals(1, signatures)
        assertEquals(listOf("https://gateway.example.test/v1/enrollment/pairings/$pairing/binding/challenge",
            "https://gateway.example.test/v1/enrollment/pairings/$pairing/binding"), calls)
        assertEquals("wss://gateway.example.test/v1/device-stream", locator.streamEndpoint)
    }

    @Test fun missingOrReplacedOriginalKeyFailsBeforeAnyNetworkOrSigning() {
        var network = 0; var signatures = 0
        listOf<() -> String>({ error("No existing key") }, { "CD".repeat(32) }).forEach { existing ->
            val client = PairingBindingClient(existing, { _, _, _, _, _ -> signatures++; byteArrayOf() }) { _, _ -> network++; challengeJson() }
            assertThrows(IllegalStateException::class.java) { client.read(locator) }
        }
        assertEquals(0, network); assertEquals(0, signatures)
    }

    @Test fun keyChangedWhileCheckingCannotInstallApprovedIdentity() {
        var reads = 0
        val client = PairingBindingClient({ if (++reads < 3) fingerprint else "CD".repeat(32) }, { _, _, _, _, _ -> byteArrayOf(1) }) { url, _ ->
            if (url.endsWith("challenge")) challengeJson() else result()
        }
        assertThrows(IllegalStateException::class.java) { client.read(locator) }
    }

    @Test fun exactIdentityAndResponseShapeAreRequiredBeforeCarryForward() {
        listOf<(JSONObject) -> Unit>(
            { it.put("account_id", device.toString()) }, { it.put("pairing_id", device.toString()) },
            { it.put("key_fingerprint", "CD".repeat(32)) }, { it.put("device_id", JSONObject.NULL) },
            { it.put("schema_version", 2) }, { it.put("stream_url", "wss://other.example.test/v1/device-stream") },
            { it.put("comparison_code", "1234") }, { it.put("status", "ready") }
        ).forEach { mutate ->
            val response = result().also(mutate)
            val client = PairingBindingClient({ fingerprint }, { _, _, _, _, _ -> byteArrayOf(1) }) { url, _ ->
                if (url.endsWith("challenge")) challengeJson() else response
            }
            assertThrows(Exception::class.java) { client.read(locator) }
        }
    }

    @Test fun pendingAndTerminalResultsNeverReturnADeviceToStart() {
        mapOf("pending" to GatewaySetupRecovery.COMPARE, "expired" to GatewaySetupRecovery.EXPIRED,
            "cancelled" to GatewaySetupRecovery.CANCELLED, "awaiting_proof" to GatewaySetupRecovery.PROOF_REQUIRED,
            "proof_rejected" to GatewaySetupRecovery.PROOF_REQUIRED).forEach { (status, recovery) ->
            val client = PairingBindingClient({ fingerprint }, { _, _, _, _, _ -> byteArrayOf(1) }) { url, _ ->
                if (url.endsWith("challenge")) challengeJson() else result(status)
            }
            val observed = client.read(locator)
            assertNull(observed.deviceId)
            assertEquals(recovery, GatewaySetupRecovery.from(observed.status))
        }
    }

    @Test fun onlyExactCoarseTerminalFromOriginalChallengeAllowsExplicitReplacement() {
        assertEquals(PairingBindingStatus.EXPIRED, pairingBindingTerminal(409, "{\"code\":\"pairing_expired\"}"))
        assertEquals(PairingBindingStatus.CANCELLED, pairingBindingTerminal(409, "{\"code\":\"pairing_cancelled\"}"))
        for (body in listOf("{}", "{\"code\":\"not_found\"}", "{\"code\":\"pairing_expired\",\"device_id\":\"synthetic\"}",
                "{\"code\":\"unknown\",\"code\":\"pairing_expired\"}", "not json")) {
            assertNull(pairingBindingTerminal(409, body))
        }
        assertNull(pairingBindingTerminal(404, "{\"code\":\"pairing_expired\"}"))
        assertNull(pairingBindingTerminal(503, "{\"code\":\"pairing_cancelled\"}"))
        var signed = 0; var posts = 0
        val client = PairingBindingClient({ fingerprint }, { _, _, _, _, _ -> signed++; byteArrayOf(1) }) { _, _ ->
            posts++; throw PairingBindingTerminal(PairingBindingStatus.EXPIRED)
        }
        assertEquals(PairingBinding(PairingBindingStatus.EXPIRED, null, null), client.read(locator))
        assertEquals(1, posts); assertEquals(0, signed)
    }

    @Test fun slowOrNonMonotonicStatusCannotInstallADevice() {
        for (late in listOf(60_001L, -1L)) {
            var at = 100L
            var posts = 0
            val client = PairingBindingClient({ fingerprint }, { _, _, _, _, _ -> at += late; byteArrayOf(1) },
                elapsed = { at }) { _, _ -> posts++; challengeJson() }
            assertThrows(IllegalStateException::class.java) { client.read(locator) }
            assertEquals("Expired proof must not reach binding read", 1, posts)
        }
    }

    @Test fun serverFixtureMatchesAndroidTranscriptBytes() {
        val bytes = PairingBindingProof.bytes(UUID.fromString("01010101-0101-0101-0101-010101010101"),
            UUID.fromString("02020202-0202-0202-0202-020202020202"),
            UUID.fromString("0001a318-5c50-0303-8303-030303030303"), ByteArray(32) { it.toByte() }, ByteArray(32) { (it + 32).toByte() })
        assertEquals("5A524F544558542D50414952494E472D42494E44494E472D563100" +
            "0101010101010101010101010101010102020202020202020202020202020202" +
            "0001A3185C5003038303030303030303" +
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", EnrollmentProof.hexUpper(bytes))
    }

    @Test fun bindingTranscriptIsDomainSeparatedAndHasExactRawUuidOrder() {
        val bytes = PairingBindingProof.bytes(account, pairing, challenge, ByteArray(32) { 0xab.toByte() }, nonce)
        assertEquals(139, bytes.size)
        val expected = "5A524F544558542D50414952494E472D42494E44494E472D563100" +
            "AAAAAAAAAAAA4AAA8AAAAAAAAAAAAAAA" + "BBBBBBBBBBBB4BBB8BBBBBBBBBBBBBBB" +
            "CCCCCCCCCCCC4CCC8CCCCCCCCCCCCCCC" + "AB".repeat(32) +
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        assertEquals(expected, EnrollmentProof.hexUpper(bytes))
        assertFalse(bytes.contentEquals(EnrollmentProof.enrollmentBytes(account, pairing, ByteArray(32), nonce)))
    }
}
