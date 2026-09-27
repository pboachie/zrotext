// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Body authentication only. This does not acquire a key or authorize admission, persistence or SMS. */
internal object Draft02Body {
    /** Consumes and clears the CEK even on failure. The caller owns and must clear returned chars. */
    fun open(envelope: Draft02OutboundEnvelope, cek: ByteArray): CharArray {
        try {
            require(cek.size == 32) { "Body key width" }
            val parts = envelope.parts()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, parts.nonce))
            cipher.updateAAD("ZTSE/body/v2\u0000".toByteArray(Charsets.US_ASCII) + parts.header + parts.protected)
            val clear = cipher.doFinal(parts.body)
            try {
                require(clear.size in 1..32_768 && !clear.contains(0.toByte()) &&
                    !(clear.size >= 3 && clear[0] == 0xef.toByte() && clear[1] == 0xbb.toByte() &&
                        clear[2] == 0xbf.toByte())) { "Body text encoding" }
                val decoded = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(clear))
                return try { CharArray(decoded.remaining()).also { decoded.get(it) } }
                finally { if (decoded.hasArray()) decoded.array().fill('\u0000') }
            } finally { clear.fill(0) }
        } finally { cek.fill(0) }
    }
}
