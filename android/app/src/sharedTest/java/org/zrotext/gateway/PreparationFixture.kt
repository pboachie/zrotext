// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Public synthetic software key only; never substituted for the shipping Keystore entry. */
internal class PreparationFixture {
    val bytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("candidate02-preparation.json")).use { it.readBytes() }
    val json = JSONObject(bytes.toString(Charsets.UTF_8))
    val now = json.getLong("now")
    val account = ByteArray(16) { 1 }
    val device = ByteArray(16) { 2 }
    val line = ByteArray(16) { 3 }
    val message = ByteArray(16) { 4 }
    fun envelope(name: String = "normal") = hex(json.getJSONObject("cases").getString(name))
    fun authority() = Draft02ManifestAuthority.verify(hex(json.getString("rootPin")), hex(json.getString("manifest")),
        Draft02ManifestAuthority.Trust(account, hex(json.getString("rootFingerprint")), 1,
            Draft02ManifestAuthority.Position.genesis(ByteArray(32))), now)
    fun request(name: String = "normal") = Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.OUTBOUND,
        account, message.copyOf().apply { if (name == "wrongBodyAad") this[0] = (this[0].toInt() xor 1).toByte() },
        device, line, "+12".toByteArray(), hex(json.getString("signerKeyId")), listOf(
            Draft02ManifestAuthority.Reader(1, hex(json.getString("deviceKeyId"))),
            Draft02ManifestAuthority.Reader(2, hex(json.getString("archiveKeyId")))))
    fun proof(name: String = "normal") = Draft02OutboundEnvelope.verify(envelope(name), authority(), request(name)) { now }
    fun softwareCek(proof: Draft02OutboundEnvelope): ByteArray {
        val parts = proof.parts()
        val params = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1")); getParameterSpec(ECParameterSpec::class.java)
        }
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(
            BigInteger.valueOf(json.getLong("deviceScalar")), params))
        val dh = KeyAgreement.getInstance("ECDH").run {
            init(privateKey); doPhase(DevicePayloadKeyStore.decodePoint(parts.enc), true); generateSecret()
        }
        try {
            val secret = Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh, parts.enc, hex(json.getString("devicePoint")))
            try {
                val material = Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(secret,
                    Draft02PublicJcaKeystoreHpke.buildDeviceInfo(parts.header, parts.protected, 1, parts.keyId))
                try {
                    return Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "AES"), GCMParameterSpec(128, material.nonce))
                        updateAAD(byteArrayOf()); doFinal(parts.wrap)
                    }
                } finally { material.clear() }
            } finally { secret.fill(0) }
        } finally { dh.fill(0) }
    }
    fun grant(name: String = "normal") = Draft02OutboundPreparation.Grant(
        uuid(account), uuid(message), "51515151-5151-4151-8151-515151515151", uuid(device), uuid(line),
        1, 1, 1, 1, "61616161-6161-4161-8161-616161616161", "ab".repeat(32),
        Draft02OutboundPreparation.hex(proof(name).unsignedDigest), 1, 1,
        Draft02OutboundPreparation.hex(authority().digest), Draft02OutboundPreparation.hash("+12".toByteArray()),
        now + 15_000, 3, 7)
    fun current(grant: Draft02OutboundPreparation.Grant = grant(), time: Long = now) =
        Draft02OutboundPreparation.Current(grant, authority(), request(), time, 3, listOf(ActiveSimCard(3, 7)))
    fun binding() = LocalLineBinding(accountId = uuid(account), deviceId = uuid(device), lineId = uuid(line),
        generation = 1, subscriptionId = 3, installedAtMs = now - 1, cardId = 7)
    companion object {
        fun uuid(bytes: ByteArray) = Draft02OutboundPreparation.uuid(bytes)
        fun hex(text: String) = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
