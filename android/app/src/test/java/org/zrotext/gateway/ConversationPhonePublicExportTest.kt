// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test

class ConversationPhonePublicExportTest {
    private val signer = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private val reader = hex("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
    private var now = 100L
    private var current = true
    private fun packet() = ConversationPhonePublicExport("01010101-0101-0101-0101-010101010101",
        "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 7,
        reader, signer, { check(current) }, { now })
    private fun denied(work: () -> Unit) { assertTrue(runCatching(work).isFailure) }
    @Test fun exactBrowserContractHasIndependentPythonFingerprintAndDefensivePublicBytes() {
        val export = packet()
        assertEquals(223, export.publicBytes().size)
        assertArrayEquals(hex("5a54504b01010101010101010101010101010101010202020202020202020202020202020203030303030303030303030303030303698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be0000000000000007047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"), export.publicBytes())
        assertEquals("25a995ac8751483479d0fff9ab0f7afaddc0822da0cca58ec179b622ef27907b", export.fingerprintHex)
        export.publicBytes().fill(0)
        assertEquals(90.toByte(), export.publicBytes()[0])
    }
    @Test fun deliberateSaveWritesOnlyExactPublicPacket() {
        val export = packet(); val output = ByteArrayOutputStream()
        export.write({}) { output }
        assertArrayEquals(export.publicBytes(), output.toByteArray())
    }
    @Test fun changedHostLineKeysOrPermissionsRefusesBeforeOpeningDestination() {
        val export = packet(); current = false; var opened = false
        denied { export.write({}) { opened = true; ByteArrayOutputStream() } }
        assertFalse(opened)
    }
    @Test fun expiryAndRegressingElapsedClockRefuseBeforeOpeningDestination() {
        val export = packet(); var opened = false
        now += 300_000
        denied { export.write({}) { opened = true; ByteArrayOutputStream() } }
        now = 99
        denied { export.write({}) { opened = true; ByteArrayOutputStream() } }
        assertFalse(opened)
    }
    @Test fun foregroundWithdrawalDuringDestinationOpeningWritesNoBytes() {
        val export = packet(); val output = ByteArrayOutputStream(); var foreground = true
        denied { export.write({ check(foreground) }) { foreground = false; output } }
        assertEquals(0, output.size())
    }
    @Test fun zeroScopeGenerationReusedAndMalformedPointsAreRefused() {
        denied { ConversationPhonePublicExport("00000000-0000-0000-0000-000000000000", "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 7, reader, signer, {}, { now }) }
        denied { ConversationPhonePublicExport("01010101-0101-0101-0101-010101010101", "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 0, reader, signer, {}, { now }) }
        denied { ConversationPhonePublicExport("01010101-0101-0101-0101-010101010101", "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 7, signer, signer, {}, { now }) }
        denied { ConversationPhonePublicExport("01010101-0101-0101-0101-010101010101", "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 7, ByteArray(65), signer, {}, { now }) }
    }
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
