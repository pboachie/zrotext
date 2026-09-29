// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.Inflater

class SyntheticSpikeImageTest {
    private class Chunk(val type: String, val data: ByteArray)

    private fun parse(png: ByteArray): List<Chunk> {
        assertEquals("89504e470d0a1a0a",
            png.copyOfRange(0, 8).joinToString("") { "%02x".format(it) })
        val chunks = ArrayList<Chunk>()
        var offset = 8
        while (offset < png.size) {
            val length = (png[offset].toInt() and 0xFF shl 24) or (png[offset + 1].toInt() and 0xFF shl 16) or
                (png[offset + 2].toInt() and 0xFF shl 8) or (png[offset + 3].toInt() and 0xFF)
            val type = String(png, offset + 4, 4, Charsets.US_ASCII)
            val data = png.copyOfRange(offset + 8, offset + 8 + length)
            val crc = (png[offset + 8 + length].toLong() and 0xFF shl 24) or
                (png[offset + 9 + length].toLong() and 0xFF shl 16) or
                (png[offset + 10 + length].toLong() and 0xFF shl 8) or
                (png[offset + 11 + length].toLong() and 0xFF)
            val expected = CRC32()
            expected.update(png, offset + 4, 4 + length)
            assertEquals("CRC of $type", expected.value, crc)
            chunks.add(Chunk(type, data))
            offset += 12 + length
        }
        return chunks
    }

    @Test fun buildsAValidOnePixelPngWithTheRequestedColor() {
        val chunks = parse(SyntheticSpikeImage.png(0x3366CC))
        assertEquals(listOf("IHDR", "IDAT", "IEND"), chunks.map { it.type })
        val ihdr = chunks[0].data
        assertEquals(13, ihdr.size)
        assertEquals(1, readUInt32(ihdr, 0)) // width
        assertEquals(1, readUInt32(ihdr, 4)) // height
        assertEquals(8, ihdr[8].toInt()) // bit depth
        assertEquals(2, ihdr[9].toInt()) // color type: truecolor RGB
        val inflater = Inflater()
        inflater.setInput(chunks[1].data)
        val scanline = ByteArray(16)
        val inflated = inflater.inflate(scanline)
        inflater.end()
        assertEquals(4, inflated) // filter byte plus RGB
        assertEquals(0, scanline[0].toInt()) // no filter
        assertEquals(0x33, scanline[1].toInt() and 0xFF)
        assertEquals(0x66, scanline[2].toInt() and 0xFF)
        assertEquals(0xCC, scanline[3].toInt() and 0xFF)
    }

    private fun readUInt32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF shl 24) or (bytes[offset + 1].toInt() and 0xFF shl 16) or
            (bytes[offset + 2].toInt() and 0xFF shl 8) or (bytes[offset + 3].toInt() and 0xFF)
}
