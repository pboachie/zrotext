// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class AndroidPairingQrPayloadTest {
    private val origin = "https://owner.invalid"
    private val pairingId = "11111111-1111-4111-8111-111111111111"
    private val token = "ztp_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
    private fun raw(origin: String = this.origin, id: String = pairingId, token: String = this.token) =
        "{\"type\":\"zrotext-pairing\",\"v\":1,\"origin\":\"$origin\",\"pairing_id\":\"$id\",\"token\":\"$token\"}"
    private fun refused(value: String) {
        val error = assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.parse(value) }
        assertEquals("Pairing QR payload refused", error.message)
        assertFalse(error.toString().contains(token))
    }

    @Test fun canonicalPayloadTransportsOnlyExistingClaimInputsOnce() {
        val payload = AndroidPairingQrPayload.parse(raw())
        assertEquals(origin, payload.origin)
        assertEquals(pairingId, payload.pairingId.toString())
        val inputs = payload.takeClaimInputs { true }
        assertEquals("AndroidPairingQrPayload(redacted)", payload.toString())
        assertFalse(inputs.toString().contains(token))
        inputs.use { server, id, secret -> assertEquals(origin, server); assertEquals(pairingId, id); assertEquals(token, secret) }
        assertThrows(IllegalStateException::class.java) { inputs.use { _, _, _ -> fail("one consumption only") } }
        assertThrows(IllegalStateException::class.java) { payload.takeClaimInputs { true } }
        payload.close(); inputs.close()
    }

    @Test fun canonicalByteInputAndManualFieldsShareTheSameValidation() {
        AndroidPairingQrPayload.parse(raw().toByteArray()).close()
        AndroidPairingQrPayload.manual(origin, pairingId, token).close()
        assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.manual(" $origin", pairingId, token) }
        assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.manual(origin, "1-1-1-1-1", token) }
        assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.manual(origin, pairingId, token + "=") }
    }

    @Test fun whitespaceAndReorderedKeysAreRefused() {
        for (candidate in listOf(" " + raw(), raw() + "\n", raw().replace(",", ", "), raw().replace("\"type\":\"zrotext-pairing\",\"v\":1", "\"v\":1,\"type\":\"zrotext-pairing\""))) refused(candidate)
    }

    @Test fun duplicateUnknownMissingKeysAndWrongPrimitiveTypesAreRefused() {
        for (candidate in listOf(raw().replace("\"v\":1", "\"v\":1,\"v\":1"), raw().replace("\"v\":1", "\"v\":1,\"extra\":true"), raw().replace("\"type\":\"zrotext-pairing\",", ""), raw().replace("\"v\":1", "\"v\":\"1\""), raw().replace("\"v\":1", "\"v\":true"), raw().replace("\"v\":1", "\"v\":1.0"), raw().replace("\"v\":1", "\"v\":2"), raw().replace("zrotext-pairing", "other-purpose"), raw().replace("\"origin\":\"$origin\"", "\"origin\":null"))) refused(candidate)
    }

    @Test fun jsonEscapesControlsUnicodeAndUrlsAreNeverAcceptedAsScannedActions() {
        for (candidate in listOf(raw().replace("owner.invalid", "owner\\u002einvalid"), raw().replace("owner.invalid", "owner\u0000.invalid"), raw().replace("owner.invalid", "öwner.invalid"), raw().replace("owner.invalid", "owner\ud800.invalid"), origin, "zrotext://pairing", raw() + raw())) refused(candidate)
    }

    @Test fun lowercaseCanonicalUuidIsRequired() {
        for (id in listOf("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "1-1-1-1-1", "00000000-0000-0000-0000-000000000000", "{${pairingId}}")) refused(raw(id = id))
    }

    @Test fun exactCanonicalBase64urlTokenIsRequired() {
        for (value in listOf(token + "=", token.dropLast(1), token + "A", token.replace("ztp_", "other_"), token.dropLast(1) + "_", "ztp_" + "+".repeat(43), "ztp_" + "/".repeat(43))) refused(raw(token = value))
    }

    @Test fun originMustBeExactCanonicalHttpsWithoutCredentialsOrUrlComponents() {
        for (value in listOf("http://owner.invalid", "HTTPS://owner.invalid", "https://Owner.invalid", "https://owner.invalid/", "https://owner.invalid/path", "https://owner.invalid?x=1", "https://owner.invalid#x", "https://person@owner.invalid", "https://person:pass@example.org:8443", "https://owner.invalid:443", "https://owner.invalid:08443", "https://owner.invalid:0", "https://%6fwner.invalid", "null", "https://owner.invalid\\other")) refused(raw(origin = value))
    }

    @Test fun canonicalNondefaultPortAndAsciiInternationalHostAreAccepted() {
        for (value in listOf("https://owner.invalid:8443", "https://xn--bcher-kva.invalid")) {
            val payload = AndroidPairingQrPayload.parse(raw(origin = value)); assertEquals(value, payload.origin); payload.close()
        }
    }

    @Test fun canonicalHostBoundaryAndUtf8CeilingAreEnforced() {
        val labels = listOf("x".repeat(63), "x".repeat(63), "x".repeat(63))
        val host = (labels + listOf("x".repeat(47), "owner", "invalid")).joinToString(".")
        assertEquals(253, host.length)
        val largestOrigin = "https://$host:65535"
        val valid = raw(origin = largestOrigin)
        assertEquals(421, valid.toByteArray().size)
        AndroidPairingQrPayload.parse(valid).close()
        AndroidPairingQrPayload.parse(valid.toByteArray()).close()
        val oversizedHost = (labels + listOf("x".repeat(48), "owner", "invalid")).joinToString(".")
        assertEquals(254, oversizedHost.length)
        refused(raw(origin = "https://$oversizedHost:65535"))
        // A canonical host cannot fill this whole wire ceiling. Retain independent
        // origin validation at 512 bytes and reject over-limit UTF-8 before decoding.
        assertEquals(512, AndroidPairingQrPayload.MAX_UTF8_BYTES)
        val prefixSize = 512 - raw().toByteArray().size
        val boundaryHost = (List(5) { "x".repeat(60) } + "x".repeat(prefixSize - 306) + listOf("owner", "invalid")).joinToString(".")
        val boundary = raw(origin = "https://$boundaryHost")
        assertEquals(512, boundary.toByteArray().size)
        refused(boundary)
        refused(boundary + " ")
        assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.parse(ByteArray(513) { 65 }) }
        assertThrows(IllegalArgumentException::class.java) { AndroidPairingQrPayload.parse(byteArrayOf(0xc3.toByte(), 0x28)) }
    }

    @Test fun closingOrWithdrawingApprovalPreventsAnyCredentialDelivery() {
        val payload = AndroidPairingQrPayload.parse(raw()); val inputs = payload.takeClaimInputs { false }
        assertThrows(IllegalStateException::class.java) { inputs.use { _, _, _ -> fail("approval withdrawn") } }
        inputs.close(); payload.close()
        val closed = AndroidPairingQrPayload.parse(raw()); closed.close()
        assertThrows(IllegalStateException::class.java) { closed.takeClaimInputs { true } }
    }
}
