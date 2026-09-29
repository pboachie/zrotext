// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater

/**
 * A 1x1 opaque PNG built chunk by chunk with CRC32 and Deflater, so the spike
 * never trusts a pasted byte blob. No Android dependency: JVM tests decode it.
 */
internal object SyntheticSpikeImage {
    fun png(rgb: Int = 0x3366CC): ByteArray {
        require(rgb in 0..0xFFFFFF)
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
        val ihdr = ByteArrayOutputStream()
        writeUInt32(ihdr, 1) // width
        writeUInt32(ihdr, 1) // height
        ihdr.write(8) // bit depth
        ihdr.write(2) // color type: truecolor RGB
        ihdr.write(0) // compression: deflate
        ihdr.write(0) // filter: none
        ihdr.write(0) // interlace: none
        chunk(out, "IHDR", ihdr.toByteArray())
        val scanline = byteArrayOf(0, (rgb shr 16).toByte(), (rgb shr 8).toByte(), rgb.toByte())
        val deflater = Deflater()
        deflater.setInput(scanline)
        deflater.finish()
        val compressed = ByteArray(64)
        val idat = ByteArrayOutputStream()
        while (!deflater.finished()) {
            val n = deflater.deflate(compressed)
            idat.write(compressed, 0, n)
        }
        deflater.end()
        chunk(out, "IDAT", idat.toByteArray())
        chunk(out, "IEND", ByteArray(0))
        return out.toByteArray()
    }

    private fun chunk(out: ByteArrayOutputStream, type: String, data: ByteArray) {
        writeUInt32(out, data.size)
        val typeBytes = type.toByteArray(Charsets.US_ASCII)
        val crc = CRC32()
        crc.update(typeBytes)
        crc.update(data)
        out.write(typeBytes)
        out.write(data)
        writeUInt32(out, crc.value.toInt())
    }

    private fun writeUInt32(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
