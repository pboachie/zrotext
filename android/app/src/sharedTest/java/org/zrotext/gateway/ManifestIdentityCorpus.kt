// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest

/** Signature/identity corpus only: its owner-only fixture is not a complete authorized manifest. */
abstract class ManifestIdentityCorpus {
    private val vector = javaClass.classLoader!!.getResourceAsStream("ztse-manifest-identity-01.json")!!
        .bufferedReader().use { JSONObject(it.readText()) }
    private val unsigned = hex(vector.getString("unsignedHex"))
    private val point = hex(vector.getString("rootPublicPointHex"))
    private val label = "ZTSE/manifest/v2\u0000"

    @Test fun distinctCanonicalSignaturesShareUnsignedIdentity() {
        assertEquals("UNAPPROVED_TEST_ONLY", vector.getString("status"))
        assertEquals(2, vector.getInt("profile"))
        assertEquals("ZTSE/manifest/v2", vector.getString("signatureDomain"))
        assertEquals(300, unsigned.size)
        val signatures = vector.getJSONArray("signatures")
        assertEquals(2, signatures.length())
        val completeDigests = mutableListOf<ByteArray>()
        for (index in 0 until signatures.length()) {
            val entry = signatures.getJSONObject(index)
            assertTrue(entry.getBoolean("canonicalLowS"))
            assertTrue(entry.getBoolean("verifies"))
            val raw = hex(entry.getString("rawHex"))
            Draft02ManifestSignatures.verify(point, raw, label, unsigned)
            val complete = sha(unsigned + raw)
            assertArrayEquals(hex(entry.getString("completeSignedDigestHex")), complete)
            completeDigests.add(complete)
        }
        assertFalse(completeDigests[0].contentEquals(completeDigests[1]))
        assertArrayEquals(hex(vector.getString("semanticDigestHex")), sha(unsigned))
    }

    @Test fun highSTwinVerifiesOnlyWithoutCanonicalPolicy() {
        val twin = vector.getJSONObject("highSTwinOfA")
        assertTrue(twin.getBoolean("verifiesUnderPlainEcdsa"))
        assertEquals("reject", twin.getString("strictVerdict"))
        val raw = hex(twin.getString("rawHex"))
        assertTrue(Draft02ManifestSignatures.verifyPlain(point, raw, label, unsigned))
        rejected { Draft02ManifestSignatures.verify(point, raw, label, unsigned) }
    }

    @Test fun sharedDerCorpusUsesAndroidSignatureConverter() {
        val expected = hex(vector.getJSONArray("signatures").getJSONObject(0).getString("rawHex"))
        val cases = vector.getJSONArray("derCases")
        assertEquals(7, cases.length())
        for (index in 0 until cases.length()) {
            val entry = cases.getJSONObject(index)
            val der = hex(entry.getString("derHex"))
            when (entry.getString("expected")) {
                "accept" -> {
                    val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
                    assertArrayEquals(entry.getString("name"), expected, raw)
                    Draft02ManifestSignatures.verify(point, raw, label, unsigned)
                }
                "reject" -> rejected { Draft01SignaturePrimitive.canonicalRawFromDer(der) }
                else -> fail("Unknown fixture verdict")
            }
        }
    }

    @Test fun changedUnsignedBytesBreakSignatureAndIdentity() {
        val mutation = vector.getJSONObject("mutatedUnsigned")
        val changed = hex(mutation.getString("unsignedHex"))
        val raw = hex(vector.getJSONArray("signatures").getJSONObject(0).getString("rawHex"))
        assertFalse(mutation.getBoolean("signatureAVerifies"))
        assertArrayEquals(hex(mutation.getString("semanticDigestHex")), sha(changed))
        assertFalse(sha(unsigned).contentEquals(sha(changed)))
        rejected { Draft02ManifestSignatures.verify(point, raw, label, changed) }
    }

    private fun rejected(block: () -> Unit) {
        try { block() } catch (_: IllegalArgumentException) { return }
        fail("Expected malformed or unauthenticated bytes to be rejected")
    }
    private fun sha(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
