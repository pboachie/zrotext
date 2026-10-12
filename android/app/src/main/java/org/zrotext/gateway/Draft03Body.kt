// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Body authentication only; no key acquisition, replay grant, persistence or SMS authority. */
internal object Draft03Body {
    /**
     * Consumes and clears [cek] on every outcome. The caller owns the returned chars
     * and must clear them. Provider-internal key/plaintext copies are outside this guarantee.
     * Public proof/time comparison does not replace a live installed-binding or grant check.
     */
    fun open(envelope: Draft03OutboundEnvelope, authority: Draft03ManifestAuthority,
             request: Draft03ManifestAuthority.Request, nowMs: Long, cek: ByteArray): CharArray {
        var key: ByteArray? = null
        try {
            require(cek.size == 32) { "Body key width" }
            val ownedKey = cek.copyOf()
            key = ownedKey
            val parts = envelope.parts(authority, request, nowMs)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(ownedKey, "AES"), GCMParameterSpec(128, parts.nonce))
            cipher.updateAAD(parts.bodyAad)
            val clear = cipher.doFinal(parts.body)
            try {
                return Draft02Body.decodeText(clear)
            } finally {
                clear.fill(0)
            }
        } finally {
            key?.fill(0)
            cek.fill(0)
        }
    }
}
