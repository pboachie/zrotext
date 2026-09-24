// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Test-only draft-01 receiver. It checks bounded syntax and opens the selected device wrap using
 * a non-exportable Keystore key. It checks the signature against a caller-pinned test point, but
 * does NOT authenticate that point through a manifest, grant or replay state. It must never be
 * called by the production gateway or radio path.
 */
internal object Draft01KeystoreReceiver {
    private const val WRAP_SIZE = 146
    private const val MIN_ENVELOPE = 557
    private const val MAX_ENVELOPE = 34_213
    private val BODY_LABEL = "ZTSE/body/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val INFO_LABEL = "ZTSE/wrap/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val AAD_LABEL = "ZTSE/wrap-aad/v1\u0000".toByteArray(Charsets.US_ASCII)

    internal data class Expected(
        val accountId: ByteArray, val deviceId: ByteArray, val lineId: ByteArray,
        val peer: String, val manifestDigest: ByteArray, val deviceKeyId: ByteArray,
        val signerPoint: ByteArray
    )

    internal data class Wrap(val role: Int, val keyId: ByteArray, val enc: ByteArray, val ct: ByteArray)

    internal data class Parsed(
        val protected: ByteArray, val header: ByteArray, val bodyNonce: ByteArray,
        val bodyCt: ByteArray, val deviceWrap: Wrap,
        val accountId: ByteArray, val deviceId: ByteArray, val lineId: ByteArray,
        val peer: String, val manifestDigest: ByteArray
    )

    fun openOutbound(envelope: ByteArray, expected: Expected, keyStore: DevicePayloadKeyStore): String {
        val parsed = parseOutbound(envelope)
        require(expected.accountId.size == 16 && expected.deviceId.size == 16 &&
            expected.lineId.size == 16 && expected.manifestDigest.size == 32 &&
            expected.deviceKeyId.size == 32 && expected.signerPoint.size == 65) {
            "Invalid pinned draft identity"
        }
        require(same(parsed.accountId, expected.accountId) &&
            same(parsed.deviceId, expected.deviceId) && same(parsed.lineId, expected.lineId) &&
            same(parsed.manifestDigest, expected.manifestDigest) && parsed.peer == expected.peer &&
            same(parsed.deviceWrap.keyId, expected.deviceKeyId)) { "Draft identity mismatch" }
        require(Draft01SignaturePrimitive.verifyOutboundParsed(
            envelope, expected.signerPoint, Draft01SignaturePrimitive.LowSPolicy.ALLOW_BOTH_FOR_INTEROP
        )) { "Draft origin signature invalid" }
        val cek = openDeviceWrap(parsed, keyStore)
        try {
            check(cek.size == 32) { "Invalid content-key width" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, parsed.bodyNonce))
            cipher.updateAAD(BODY_LABEL + parsed.header + parsed.protected)
            val clear = cipher.doFinal(parsed.bodyCt)
            try {
                require(clear.isNotEmpty() && clear.size <= 32_768 && !clear.contains(0.toByte()) &&
                    !(clear.size >= 3 && clear[0] == 0xef.toByte() && clear[1] == 0xbb.toByte() &&
                        clear[2] == 0xbf.toByte())) { "Invalid draft text bounds" }
                return Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(clear)).toString()
            } finally { clear.fill(0) }
        } finally { cek.fill(0) }
    }

    fun parseOutbound(envelope: ByteArray): Parsed {
        require(envelope.size in MIN_ENVELOPE..MAX_ENVELOPE) { "Draft envelope bound" }
        require(envelope.copyOfRange(0, 8).contentEquals(byteArrayOf(0x5a, 0x54, 0x53, 0x45, 1, 1, 0, 0))) {
            "Draft magic, profile, kind or flags"
        }
        val protectedLen = u16(envelope, 8)
        require(protectedLen in 157..170) { "Draft protected bound" }
        val protectedEnd = 10 + protectedLen
        val protected = envelope.copyOfRange(10, protectedEnd)
        val peerLen = protected[153].toInt() and 0xff
        require(peerLen in 3..16 && protectedLen == 154 + peerLen) { "Draft protected shape" }
        val peerBytes = protected.copyOfRange(154, protected.size)
        signedU64(protected, 64) // keyset_version must fit all supported signed storage types.
        require(peerBytes[0] == '+'.code.toByte() && peerBytes[1] in '1'.code.toByte()..'9'.code.toByte() &&
            peerBytes.drop(2).all { it in '0'.code.toByte()..'9'.code.toByte() }) { "Draft peer" }
        require(protected[152] == 1.toByte()) { "Draft intent" }
        val observedMs = signedU64(protected, 136)
        val expiresMs = signedU64(protected, 144)
        require(expiresMs > observedMs && expiresMs - observedMs <= 900_000) { "Draft expiry" }
        val bodyLength = u32(envelope, protectedEnd + 12)
        require(bodyLength in 17..32_784) { "Draft body bound" }
        val bodyEnd = protectedEnd + 16 + bodyLength
        require(bodyEnd < envelope.size) { "Truncated draft body" }
        val count = envelope[bodyEnd].toInt() and 0xff
        require(count in 2..8 && bodyEnd + 1 + count * WRAP_SIZE + 64 == envelope.size) {
            "Draft wrap count or trailing bytes"
        }
        var deviceWrap: Wrap? = null
        var archiveCount = 0
        var previous: Wrap? = null
        for (index in 0 until count) {
            val start = bodyEnd + 1 + index * WRAP_SIZE
            val role = envelope[start].toInt() and 0xff
            require(role in 1..3) { "Draft wrap role" }
            val wrap = Wrap(role, envelope.copyOfRange(start + 1, start + 33),
                envelope.copyOfRange(start + 33, start + 98),
                envelope.copyOfRange(start + 98, start + WRAP_SIZE))
            DevicePayloadKeyStore.decodePoint(wrap.enc)
            if (previous != null) {
                require(wrap.role > previous.role ||
                    (wrap.role == previous.role && compareUnsigned(wrap.keyId, previous.keyId) > 0)) {
                    "Draft wrap order or duplicate"
                }
            }
            if (role == 1) {
                require(deviceWrap == null) { "Duplicate device recipient" }
                deviceWrap = wrap
            }
            if (role == 2) archiveCount++
            previous = wrap
        }
        require(deviceWrap != null && archiveCount == 1) { "Draft recipient set" }
        return Parsed(protected, envelope.copyOfRange(0, 10),
            envelope.copyOfRange(protectedEnd, protectedEnd + 12),
            envelope.copyOfRange(protectedEnd + 16, bodyEnd), deviceWrap,
            protected.copyOfRange(0, 16), protected.copyOfRange(32, 48),
            protected.copyOfRange(48, 64), String(peerBytes, Charsets.US_ASCII),
            protected.copyOfRange(72, 104))
    }

    internal fun wrapInfo(parsed: Parsed): ByteArray = INFO_LABEL +
        MessageDigest.getInstance("SHA-256").digest(parsed.protected) +
        byteArrayOf(parsed.deviceWrap.role.toByte()) + parsed.deviceWrap.keyId

    internal fun wrapAad(parsed: Parsed): ByteArray = AAD_LABEL + parsed.protected +
        byteArrayOf(parsed.deviceWrap.role.toByte()) + parsed.deviceWrap.keyId

    internal fun openDeviceWrap(parsed: Parsed, keyStore: DevicePayloadKeyStore,
                                info: ByteArray = wrapInfo(parsed), aad: ByteArray = wrapAad(parsed)): ByteArray {
        val dh = keyStore.agreeExisting(parsed.deviceWrap.enc, parsed.deviceWrap.keyId)
        try {
            val shared = M2KeystoreHpkeProofTest.HpkeOneShot.kemSecret(
                dh, parsed.deviceWrap.enc, keyStore.existingPublic().point)
            return try { M2KeystoreHpkeProofTest.HpkeOneShot.open(shared, parsed.deviceWrap.ct, info, aad) }
            finally { shared.fill(0) }
        } finally { dh.fill(0) }
    }

    private fun same(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
    private fun u16(bytes: ByteArray, offset: Int): Int =
        ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xffff
    private fun u32(bytes: ByteArray, offset: Int): Int {
        val n = ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xffff_ffffL
        require(n <= Int.MAX_VALUE) { "Oversized draft length" }
        return n.toInt()
    }
    private fun signedU64(bytes: ByteArray, offset: Int): Long =
        ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.BIG_ENDIAN).long.also {
            require(it >= 0) { "Draft timestamp exceeds signed range" }
        }
    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return 0
    }
}
