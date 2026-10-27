// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Test injection is explicit; the sole production sender is the pinned wolfSSL bridge. */
internal fun interface Profile03InboundWrapSealer {
    fun seal(point: ByteArray, cek: ByteArray, info: ByteArray, aad: ByteArray, current: () -> Unit): ByteArray
}

/** Produces unsigned PUBLIC ciphertext only. The actual receiver must durably reserve the
 * genuine capture/positive sequence and exact unsigned bytes before existing-hardware signing,
 * then add the distinct reviewed CaptureIntent03 before upload. None is inferred here. */
internal class Profile03InboundSealer internal constructor(private val wraps: Profile03InboundWrapSealer) {
    constructor() : this(Profile03InboundWrapSealer { point, cek, info, aad, current ->
        WolfHpkePublicSender().seal(point, cek, info, aad, current)
    })
    fun seal(body: CharArray, authority: Draft03ManifestAuthority,
        request: Draft03ManifestAuthority.InboundRequest, observed: Long, sequence: Long,
        deadline: Long, trustedNow: () -> Long, ramCurrent: () -> Unit): Draft03InboundEnvelope.Unsigned {
        HpkeWrapFraming.requireApiFloor(Build.VERSION.SDK_INT)
        require(sequence > 0 && body.size in 1..32_768)
        val chars = body.copyOf() // Capture the explicit source text before any admission/time wait.
        var latest = 0L
        fun current(): Draft03ManifestAuthority.InboundContext {
            ramCurrent()
            val now = trustedNow(); require(now > 0 && now >= latest); latest = now
            return authority.inboundContext(request, observed, now, deadline).also { ramCurrent() }
        }
        val initial: Draft03ManifestAuthority.InboundContext
        val encoded = try {
            initial = current()
            Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(chars))
        } finally { chars.fill('\u0000') }
        val clear = try { ByteArray(encoded.remaining()).also { encoded.get(it) } }
            finally { if (encoded.hasArray()) encoded.array().fill(0) }
        val key = ByteArray(32); val nonce = ByteArray(12)
        try {
            val checkedText = Draft02Body.decodeText(clear) // Shared strict UTF8/noNUL/noBOM rule, no02 wire/parser.
            checkedText.fill('\u0000')
            val random = SecureRandom(); random.nextBytes(key); random.nextBytes(nonce)
            val protected = ByteBuffer.allocate(169 + request.peer().size).put(request.account()).put(request.event())
                .put(request.device()).put(request.line()).putLong(initial.version).put(initial.digest()).put(request.signer())
                .putLong(observed).put(request.event()).putLong(sequence).put(request.peer().size.toByte()).put(request.peer()).array()
            val header = byteArrayOf(90, 84, 83, 69, 3, 2, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            current()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(ascii("ZTSE/body/v3\u0000") + header + protected)
            val encrypted = cipher.doFinal(clear); current()
            val selected = request.readers()
            val sealed = selected.map { reader ->
                val context = current()
                val point = authority.inboundReaderPoint(context, reader, latest)
                current()
                val suffix = header + protected + byteArrayOf(reader.role.toByte()) + reader.keyId
                val info = ascii("ZTSE/wrap/v3\u0000") + suffix
                val aad = ascii("ZTSE/wrap-aad/v3\u0000") + suffix
                val inputKey = key.copyOf()
                val wrapped = try { wraps.seal(point, inputKey, info, aad) { current(); Unit } }
                    finally { inputKey.fill(0) }
                current()
                require(wrapped.size == 113); DevicePayloadKeyStore.decodePoint(wrapped.copyOfRange(0, 65))
                byteArrayOf(reader.role.toByte()) + reader.keyId + wrapped
            }.fold(ByteArray(0)) { previous, next -> previous + next }
            current()
            val bytes = header + protected + nonce + ByteBuffer.allocate(4).putInt(encrypted.size).array() +
                encrypted + byteArrayOf(selected.size.toByte()) + sealed
            return Draft03InboundEnvelope.unsigned(bytes, authority, request, observed, sequence, latest, deadline)
                .also { current() }
        } finally { clear.fill(0); key.fill(0); nonce.fill(0) }
    }
    override fun toString() = "Profile03InboundSealer(unsigned-public-encryption-only)"
    companion object { private fun ascii(s: String) = s.toByteArray(Charsets.US_ASCII) }
}
