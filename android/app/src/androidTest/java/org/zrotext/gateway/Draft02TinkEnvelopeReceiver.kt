// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import com.google.crypto.tink.hybrid.HpkeParameters
import com.google.crypto.tink.hybrid.HpkePublicKey
import com.google.crypto.tink.hybrid.internal.HpkeHelperForAndroidKeystore
import com.google.crypto.tink.util.Bytes
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Test-only profile-02 outbound receiver. No production route or real manifest store calls it. */
internal object Draft02TinkEnvelopeReceiver {
    private const val WRAP_SIZE = 146
    private val bodyLabel = "ZTSE/body/v2\u0000".toByteArray(Charsets.US_ASCII)
    private val infoLabel = "ZTSE/wrap/v2\u0000".toByteArray(Charsets.US_ASCII)
    private val signLabel = "ZTSE/sign/v2\u0000".toByteArray(Charsets.US_ASCII)
    private val keyLabel = "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    /** A synthetic, caller-pinned authorization view, not an owner-signature-verified manifest. */
    internal data class TrustedView(
        val accountId: ByteArray, val deviceId: ByteArray, val lineId: ByteArray,
        val peer: String, val manifestDigest: ByteArray, val keysetVersion: Long,
        val signerPoint: ByteArray, val deviceKeyId: ByteArray, val archiveKeyId: ByteArray,
        val ownerSignatureAccepted: Boolean = true,
        val signerAuthorizedForOutbound: Boolean = true,
        val deviceCurrentlyAuthorized: Boolean = true
    )

    internal data class Wrap(val role: Int, val keyId: ByteArray, val enc: ByteArray, val ct: ByteArray)
    internal data class Parsed(
        val envelope: ByteArray, val header: ByteArray, val protected: ByteArray,
        val nonce: ByteArray, val bodyCt: ByteArray, val unsignedLength: Int,
        val deviceWrap: Wrap, val archiveWrap: Wrap,
        val accountId: ByteArray, val messageId: ByteArray, val deviceId: ByteArray,
        val lineId: ByteArray, val keysetVersion: Long, val manifestDigest: ByteArray,
        val signerKeyId: ByteArray, val peer: String
    )

    /** In-memory single-process test double. Durable replay and concurrent admission remain open. */
    internal class ReplayJournal {
        private val seen = HashMap<String, ByteArray>()

        @Synchronized fun check(accountId: ByteArray, messageId: ByteArray, unsigned: ByteArray) {
            val key = (accountId + messageId).toHex()
            val prior = seen[key] ?: return
            val hash = MessageDigest.getInstance("SHA-256").digest(unsigned)
            require(!MessageDigest.isEqual(prior, hash)) { "Duplicate draft-02 message" }
            error("Conflicting draft-02 message identity")
        }

        @Synchronized fun record(accountId: ByteArray, messageId: ByteArray, unsigned: ByteArray) {
            check(accountId, messageId, unsigned)
            seen[(accountId + messageId).toHex()] = MessageDigest.getInstance("SHA-256").digest(unsigned)
        }
    }

    fun openOutbound(envelope: ByteArray, trusted: TrustedView, keyStore: DevicePayloadKeyStore,
                     replay: ReplayJournal): String {
        val parsed = parseOutbound(envelope)
        require(trusted.ownerSignatureAccepted && trusted.signerAuthorizedForOutbound &&
            trusted.deviceCurrentlyAuthorized) { "Draft-02 manifest authorization denied" }
        require(trusted.accountId.size == 16 && trusted.deviceId.size == 16 &&
            trusted.lineId.size == 16 && trusted.manifestDigest.size == 32 &&
            trusted.deviceKeyId.size == 32 && trusted.archiveKeyId.size == 32 &&
            trusted.signerPoint.size == 65) { "Invalid trusted view" }
        require(same(parsed.accountId, trusted.accountId) &&
            same(parsed.deviceId, trusted.deviceId) && same(parsed.lineId, trusted.lineId) &&
            same(parsed.manifestDigest, trusted.manifestDigest) &&
            parsed.keysetVersion == trusted.keysetVersion && parsed.peer == trusted.peer &&
            same(parsed.deviceWrap.keyId, trusted.deviceKeyId) &&
            same(parsed.archiveWrap.keyId, trusted.archiveKeyId)) { "Draft-02 trusted view mismatch" }
        require(verifySignature(parsed, trusted.signerPoint)) { "Draft-02 origin signature invalid" }
        replay.check(parsed.accountId, parsed.messageId, envelope.copyOfRange(0, parsed.unsignedLength))
        val cek = openDeviceWrap(parsed, keyStore)
        try {
            check(cek.size == 32) { "Invalid CEK width" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, parsed.nonce))
            cipher.updateAAD(bodyLabel + parsed.header + parsed.protected)
            val clear = cipher.doFinal(parsed.bodyCt)
            try {
                require(clear.isNotEmpty() && clear.size <= 32_768 && !clear.contains(0.toByte()) &&
                    !(clear.size >= 3 && clear[0] == 0xef.toByte() && clear[1] == 0xbb.toByte() &&
                        clear[2] == 0xbf.toByte())) { "Invalid draft-02 text" }
                val text = Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(clear)).toString()
                replay.record(parsed.accountId, parsed.messageId,
                    envelope.copyOfRange(0, parsed.unsignedLength))
                return text
            } finally { clear.fill(0) }
        } finally { cek.fill(0) }
    }

    fun parseOutbound(input: ByteArray): Parsed {
        require(input.size in 557..34_213) { "Draft-02 envelope bound" }
        val envelope = input.copyOf()
        require(envelope.copyOfRange(0, 8).contentEquals(
            byteArrayOf(0x5a, 0x54, 0x53, 0x45, 2, 1, 0, 0))) { "Draft-02 header" }
        val protectedLen = u16(envelope, 8)
        require(protectedLen in 157..170) { "Draft-02 protected bound" }
        val protectedEnd = 10 + protectedLen
        val protected = envelope.copyOfRange(10, protectedEnd)
        val peerLen = protected[153].toInt() and 0xff
        require(peerLen in 3..16 && protectedLen == 154 + peerLen) { "Draft-02 protected shape" }
        val peerBytes = protected.copyOfRange(154, protected.size)
        require(peerBytes[0] == '+'.code.toByte() && peerBytes[1] in '1'.code.toByte()..'9'.code.toByte() &&
            peerBytes.drop(2).all { it in '0'.code.toByte()..'9'.code.toByte() }) { "Draft-02 peer" }
        val keysetVersion = signedU64(protected, 64)
        val observed = signedU64(protected, 136)
        val expires = signedU64(protected, 144)
        require(protected[152] == 1.toByte() && expires > observed && expires - observed <= 900_000) {
            "Draft-02 intent/expiry"
        }
        val bodyLength = u32(envelope, protectedEnd + 12)
        require(bodyLength in 17..32_784) { "Draft-02 body bound" }
        val bodyEnd = protectedEnd + 16 + bodyLength
        require(bodyEnd < envelope.size) { "Draft-02 truncated body" }
        val count = envelope[bodyEnd].toInt() and 0xff
        require(count in 2..8 && bodyEnd + 1 + count * WRAP_SIZE + 64 == envelope.size) {
            "Draft-02 wrap count or trailing bytes"
        }
        var device: Wrap? = null
        var archive: Wrap? = null
        var previous: Wrap? = null
        for (index in 0 until count) {
            val start = bodyEnd + 1 + index * WRAP_SIZE
            val role = envelope[start].toInt() and 0xff
            require(role in 1..3) { "Draft-02 wrap role" }
            val wrap = Wrap(role, envelope.copyOfRange(start + 1, start + 33),
                envelope.copyOfRange(start + 33, start + 98),
                envelope.copyOfRange(start + 98, start + WRAP_SIZE))
            DevicePayloadKeyStore.decodePoint(wrap.enc)
            if (previous != null) {
                require(role > previous.role ||
                    (role == previous.role && compareUnsigned(wrap.keyId, previous.keyId) > 0)) {
                    "Draft-02 wrap order/duplicate"
                }
            }
            if (role == 1) {
                require(device == null) { "Duplicate device wrap" }
                device = wrap
            }
            if (role == 2) {
                require(archive == null) { "Duplicate archive wrap" }
                archive = wrap
            }
            previous = wrap
        }
        require(device != null && archive != null) { "Draft-02 recipient set" }
        return Parsed(envelope, envelope.copyOfRange(0, 10), protected,
            envelope.copyOfRange(protectedEnd, protectedEnd + 12),
            envelope.copyOfRange(protectedEnd + 16, bodyEnd), envelope.size - 64,
            device, archive, protected.copyOfRange(0, 16), protected.copyOfRange(16, 32),
            protected.copyOfRange(32, 48), protected.copyOfRange(48, 64), keysetVersion,
            protected.copyOfRange(72, 104), protected.copyOfRange(104, 136),
            String(peerBytes, Charsets.US_ASCII))
    }

    internal fun wrapInfo(parsed: Parsed): ByteArray = infoLabel + parsed.header + parsed.protected +
        byteArrayOf(parsed.deviceWrap.role.toByte()) + parsed.deviceWrap.keyId

    internal fun openDeviceWrap(parsed: Parsed, keyStore: DevicePayloadKeyStore,
                                info: ByteArray = wrapInfo(parsed)): ByteArray {
        require(parsed.deviceWrap.ct.size == 48) { "Invalid draft-02 wrap ciphertext" }
        val public = keyStore.existingPublic()
        val dh = keyStore.agreeExisting(parsed.deviceWrap.enc, parsed.deviceWrap.keyId)
        try {
            val params = HpkeParameters.builder()
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .build()
            val key = HpkePublicKey.create(params, Bytes.copyFrom(public.point), null)
            return HpkeHelperForAndroidKeystore.create(key)
                .decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(
                    parsed.deviceWrap.enc, dh, parsed.deviceWrap.ct, 0, info)
        } finally { dh.fill(0) }
    }

    private fun verifySignature(parsed: Parsed, pinnedPoint: ByteArray): Boolean {
        val point = DevicePayloadKeyStore.decodePoint(pinnedPoint)
        val signerId = MessageDigest.getInstance("SHA-256").digest(keyLabel + byteArrayOf(1, 1) + pinnedPoint)
        if (!same(signerId, parsed.signerKeyId)) return false
        val raw = parsed.envelope.copyOfRange(parsed.unsignedLength, parsed.envelope.size)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        if (r.signum() == 0 || r >= order || s.signum() == 0 || s >= order) return false
        // Q6 remains open: this proof permits both valid high-s and low-s Web Crypto signatures.
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(point)
            update(signLabel)
            update(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(parsed.unsignedLength).array())
            update(parsed.envelope, 0, parsed.unsignedLength)
            verify(rawToDer(raw))
        }
    }

    private fun rawToDer(raw: ByteArray): ByteArray {
        fun integer(offset: Int): ByteArray {
            var first = offset
            while (first < offset + 31 && raw[first] == 0.toByte()) first++
            val magnitude = raw.copyOfRange(first, offset + 32)
            val positive = if ((magnitude[0].toInt() and 0x80) != 0) byteArrayOf(0) + magnitude else magnitude
            return byteArrayOf(2, positive.size.toByte()) + positive
        }
        val fields = integer(0) + integer(32)
        return byteArrayOf(0x30, fields.size.toByte()) + fields
    }

    private fun same(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
    private fun u16(bytes: ByteArray, at: Int): Int =
        ByteBuffer.wrap(bytes, at, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xffff
    private fun u32(bytes: ByteArray, at: Int): Int {
        val value = ByteBuffer.wrap(bytes, at, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xffff_ffffL
        require(value <= Int.MAX_VALUE) { "Draft-02 body length overflow" }
        return value.toInt()
    }
    private fun signedU64(bytes: ByteArray, at: Int): Long =
        ByteBuffer.wrap(bytes, at, 8).order(ByteOrder.BIG_ENDIAN).long.also {
            require(it >= 0) { "Draft-02 u64 exceeds signed storage" }
        }
    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return 0
    }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
