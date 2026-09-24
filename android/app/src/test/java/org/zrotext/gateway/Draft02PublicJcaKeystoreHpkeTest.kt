// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Independent RFC 9180 Appendix A.3.1 P-256 base-mode known-answer values. */
class Draft02PublicJcaKeystoreHpkeTest {
    @Test fun rfc9180P256BaseModeKeyScheduleAndAead() {
        val params = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(
            BigInteger("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2", 16),
            params))
        val enc = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325" +
            "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        val recipientPoint = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a" +
            "826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        val publicKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(
            ECPoint(BigInteger(1, enc.copyOfRange(1, 33)), BigInteger(1, enc.copyOfRange(33, 65))),
            params))
        val dh = KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(publicKey, true)
            generateSecret()
        }
        try {
            val shared = Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh, enc, recipientPoint)
            try {
                assertArrayEquals(hex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8"), shared)
                val material = Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(shared,
                    hex("4f6465206f6e2061204772656369616e2055726e"))
                try {
                    assertArrayEquals(hex("868c066ef58aae6dc589b6cfdd18f97e"), material.key)
                    assertArrayEquals(hex("4e0bc5018beba4bf004cca59"), material.nonce)
                    fun open(aad: ByteArray): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "AES"),
                            GCMParameterSpec(128, material.nonce))
                        updateAAD(aad)
                        doFinal(hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" +
                            "9076ac232e3ab2523f39513434"))
                    }
                    assertArrayEquals(hex("4265617574792069732074727574682c20747275746820626561757479"),
                        open(hex("436f756e742d30")))
                    assertThrows(GeneralSecurityException::class.java) { open(hex("436f756e742d31")) }
                } finally { material.clear() }
            } finally { shared.fill(0) }
        } finally { dh.fill(0) }
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
