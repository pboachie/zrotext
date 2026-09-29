// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MmsSendComposerTest {
    private fun hex(text: String) = text.replace(Regex("\\s"), "").lowercase()

    private fun bytes(text: String) = hex(text).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private fun image(size: Int = 13): ByteArray =
        bytes("89504E470D0A1A0A") + ByteArray(size - 8) { 'A'.code.toByte() }

    @Test fun composesASendReqInTheAospByteShape() {
        val request = MmsSpikeRequest("+15551234567", "Spike", "spike-1",
            "zrotext-spike.png", image())
        assertNull(MmsSendComposer.validationError(request))
        val pdu = MmsSendComposer.compose(request)
        assertEquals(hex("""
            8C 80
            98 73 70 69 6B 65 2D 31 00
            8D 92
            89 01 81
            97 18 EA 2B 31 35 35 35 31 32 33 34 35 36 37 2F 54 59 50 45 3D 50 4C 4D 4E 00
            96 07 EA 53 70 69 6B 65 00
            84 0C A3 89 69 6D 61 67 65 2F 70 6E 67 00
            01
            15 0D 14 A0 85 7A 72 6F 74 65 78 74 2D 73 70 69 6B 65 2E 70 6E 67 00
            89 50 4E 47 0D 0A 1A 0A 41 41 41 41 41
        """), pdu.toHex())
    }

    @Test fun omitsTheSubjectHeaderWhenEmpty() {
        val request = MmsSpikeRequest("+15551234567", "", "spike-1",
            "zrotext-spike.png", image())
        val pdu = MmsSendComposer.compose(request).toHex()
        assertTrue(pdu.startsWith(hex("8C 80 98 73 70 69 6B 65 2D 31 00 8D 92 89 01 81")))
        assertTrue(!pdu.contains(hex("96 07 EA")))
    }

    @Test fun encodesUtf8SubjectsWithTheCharsetPrefix() {
        val request = MmsSpikeRequest("+15551234567", "Späke", "spike-1",
            "zrotext-spike.png", image())
        val pdu = MmsSendComposer.compose(request).toHex()
        // Value length 8: charset byte, "S p 0xC3 0xA4 k e", NUL.
        assertTrue(pdu.contains(hex("96 08 EA 53 70 C3 A4 6B 65 00")))
    }

    @Test fun quotesASubjectWhoseFirstByteIsAboveAscii() {
        val request = MmsSpikeRequest("+15551234567", "Übung", "spike-1",
            "zrotext-spike.png", image())
        val pdu = MmsSendComposer.compose(request).toHex()
        // Value length 9: charset, quote, 0xC3 0x9C and four ASCII letters, NUL.
        assertTrue(pdu.contains(hex("96 09 EA 7F C3 9C 62 75 6E 67 00")))
    }

    @Test fun usesLengthQuoteAndMultibyteUintvarForLargeParts() {
        val name = "a".repeat(30)
        val imageData = image(300)
        val request = MmsSpikeRequest("+15551234567", "", "spike-1", name, imageData)
        val pdu = MmsSendComposer.compose(request)
        val hex = pdu.toHex()
        // Content-type value of 33 bytes needs length-quote 0x1F; the entry
        // header length becomes 35 and the 300-byte data length is 0x82 0x2C.
        assertTrue(hex.contains(hex("01 23 82 2C 1F 21 A0 85") + "61".repeat(30) + "00"))
        assertTrue(hex.endsWith(imageData.toHex()))
    }

    @Test fun rejectsInvalidRequests() {
        val valid = MmsSpikeRequest("+15551234567", "Spike", "spike-1",
            "zrotext-spike.png", image())
        assertNull(MmsSendComposer.validationError(valid))
        assertEquals("recipient must be +E.164",
            MmsSendComposer.validationError(valid.copy(recipientE164 = "15551234567")))
        assertEquals("recipient must be +E.164",
            MmsSendComposer.validationError(valid.copy(recipientE164 = "+15551234567890123456")))
        assertEquals("subject is longer than 64 characters or contains NUL",
            MmsSendComposer.validationError(valid.copy(subject = "x".repeat(65))))
        assertEquals("subject is longer than 64 characters or contains NUL",
            MmsSendComposer.validationError(valid.copy(subject = "a\u0000b")))
        assertEquals("transaction id must be 1-64 ASCII letters, digits, or hyphens",
            MmsSendComposer.validationError(valid.copy(transactionId = "spike_1")))
        assertEquals("transaction id must be 1-64 ASCII letters, digits, or hyphens",
            MmsSendComposer.validationError(valid.copy(transactionId = "")))
        assertEquals("image name must be a simple 1-40 character file name",
            MmsSendComposer.validationError(valid.copy(imageName = "../escape.png")))
        assertEquals("image name must be a simple 1-40 character file name",
            MmsSendComposer.validationError(valid.copy(imageName = ".hidden")))
        assertEquals("image is empty or larger than 300000 bytes",
            MmsSendComposer.validationError(valid.copy(imageData = ByteArray(0))))
        assertEquals("image is empty or larger than 300000 bytes",
            MmsSendComposer.validationError(valid.copy(imageData = ByteArray(300_001))))
        assertEquals("attachment does not start with the PNG signature",
            MmsSendComposer.validationError(valid.copy(imageData = ByteArray(64))))
    }
}
