// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * JVM tests for the sealed-wrap framing rules the native HPKE receiver
 * enforces before any Keystore or native operation (binding condition 3 of
 * the #1003 provider selection: enc exactly 65 bytes, ciphertext at least
 * 17 bytes, nonempty and distinct info/AAD; API 28-30 refused at runtime).
 * These rules are mirrored in the native wrapper; the host and device
 * known-answer suites exercise the native copy.
 */
class HpkeWrapFramingTest {
    private val enc = ByteArray(65) { (it + 1).toByte() }
    private val ct = ByteArray(48) { (it + 2).toByte() }
    private val info = "ZTSE/wrap/v1\u0000".toByteArray(Charsets.US_ASCII) + ByteArray(32) { 7 }
    private val aad = "ZTSE/wrap-aad/v1\u0000".toByteArray(Charsets.US_ASCII) + ByteArray(32) { 9 }

    @Test fun validSealedWrapFramingIsAccepted() {
        HpkeWrapFraming.requireValid(enc, ct, info, aad)
        HpkeWrapFraming.requireApiFloor(31)
        HpkeWrapFraming.requireApiFloor(37)
    }

    @Test fun encapsulationMustBeExactlySixtyFiveBytes() {
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc.copyOf(64), ct, info, aad)
        }
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc + 0, ct, info, aad)
        }
    }

    @Test fun ciphertextMustCarryOnePlaintextBytePlusTheTag() {
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc, ct.copyOf(16), info, aad)
        }
        HpkeWrapFraming.requireValid(enc, ct.copyOf(17), info, aad)
    }

    @Test fun infoAndAadMustBothBeNonempty() {
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc, ct, ByteArray(0), aad)
        }
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc, ct, info, ByteArray(0))
        }
    }

    @Test fun infoAndAadMustBeDistinct() {
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc, ct, info, info.copyOf())
        }
        // Equal-length collision: a differently constructed array carrying
        // info's exact bytes is still equal and must be refused.
        val rebuilt = ByteArray(info.size) { info[it] }
        assertThrows(IllegalArgumentException::class.java) {
            HpkeWrapFraming.requireValid(enc, ct, info, rebuilt)
        }
    }

    @Test fun equalLengthDistinctInfoAndAadIsAccepted() {
        val sameLengthAad = ByteArray(info.size) { (it * 5).toByte() }
        assertEquals(info.size, sameLengthAad.size)
        HpkeWrapFraming.requireValid(enc, ct, info, sameLengthAad)
        HpkeWrapFraming.requireValid(enc, ct, info, aad)
    }

    @Test fun apiFloorRefusesTwentyEightThroughThirty() {
        for (api in 28..30) {
            assertThrows(IllegalArgumentException::class.java) {
                HpkeWrapFraming.requireApiFloor(api)
            }
        }
    }
}
