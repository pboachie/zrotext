// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.telephony.SmsManager
import org.junit.Assert.*
import org.junit.Test

/** Actual independent encrypted bytes; synthetic software recipient is not hardware custody evidence. */
abstract class SealedBodyCorpus {
    @Test fun independentEncryptedEnvelopeOpensAndConsumesCek() {
        val f = PreparationFixture()
        assertArrayEquals(PreparationFixture.hex("ed73a18a79a1c0658f4f4498b69dd6bfcbd6ad9746e014bfa6f02d71c7d4a682"), PreparationFixture.sha(f.bytes))
        assertEquals("CANDIDATE_SYNTHETIC_DECRYPTABLE", f.json.getString("status"))
        val proof = f.proof()
        val cek = f.softwareCek(proof)
        val clear = Draft02Body.open(proof, cek)
        try { assertEquals("Candidate sealed text ✓", String(clear)); assertTrue(cek.all { it == 0.toByte() }) }
        finally { clear.fill('\u0000') }
    }

    @Test fun validSignaturesCannotHideNonceCiphertextOrBodyAadChanges() {
        val f = PreparationFixture()
        for (name in listOf("wrongNonce", "wrongBody", "wrongBodyAad")) {
            val proof = f.proof(name) // Each malformed ciphertext is independently signed and authorized.
            val cek = f.softwareCek(proof) // Including changed-context HPKE wraps: body AAD must fail.
            assertThrows(Exception::class.java) { Draft02Body.open(proof, cek) }
            assertTrue(cek.all { it == 0.toByte() })
        }
    }

    @Test fun invalidUtf8NulAndBomFailAfterSuccessfulBodyAuthentication() {
        val f = PreparationFixture()
        for (name in listOf("malformedUtf8", "nul", "bom")) {
            val proof = f.proof(name)
            val cek = f.softwareCek(proof)
            assertThrows(Exception::class.java) { Draft02Body.open(proof, cek) }
            assertTrue(cek.all { it == 0.toByte() })
        }
        val wrongWidth = ByteArray(31) { 7 }
        assertThrows(Exception::class.java) { Draft02Body.open(f.proof(), wrongWidth) }
        assertTrue(wrongWidth.all { it == 0.toByte() })
    }

    @Test fun proofSlicesAreDefensiveAndContextIsRechecked() {
        val f = PreparationFixture()
        val proof = f.proof()
        val original = proof.parts()
        proof.parts().protected.fill(0)
        proof.parts().wrap.fill(0)
        assertArrayEquals(original.protected, proof.parts().protected)
        assertArrayEquals(original.wrap, proof.parts().wrap)
        proof.checkContext(f.authority(), f.request(), f.now)
        assertThrows(Exception::class.java) { proof.checkContext(f.authority(), f.request("wrongBodyAad"), f.now) }
        assertThrows(Exception::class.java) { proof.checkContext(f.authority(), f.request(), f.now + 20_000) }
    }

    @Test fun platformGsmExtensionAndUnicodeSegmentationDistinguishesSixFromSeven() {
        val f = PreparationFixture()
        val manager = SmsManager.getSmsManagerForSubscriptionId(3)
        for (prefix in listOf("gsm", "extension", "unicode")) {
            for (suffix in listOf("Six", "Seven")) {
                val proof = f.proof(prefix + suffix)
                val chars = Draft02Body.open(proof, f.softwareCek(proof))
                try {
                    if (suffix == "Six") assertEquals(6, Draft02OutboundPreparation.segmentCount(chars, manager::divideMessage))
                    else assertThrows(Exception::class.java) { Draft02OutboundPreparation.segmentCount(chars, manager::divideMessage) }
                } finally { chars.fill('\u0000') }
            }
        }
    }
}
