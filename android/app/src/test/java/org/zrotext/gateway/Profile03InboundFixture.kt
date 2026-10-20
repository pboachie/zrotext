// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.KeyPair
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Synthetic, genuinely signed public role authorities. The software HPKE port is TEST ONLY:
 * no Keystore custody, installed113 permission, physical selection or provider acceptance. */
internal class Profile03InboundFixture(integrationScope: Int = 12, phoneState: Int = 1,
    phoneFrom: Long = 1, integrationState: Int = 1) {
    val root = Profile03ExecutionFixture.pair()
    val reader = Profile03ExecutionFixture.pair()
    val archive = Profile03ExecutionFixture.pair()
    val integration = Profile03ExecutionFixture.pair()
    val phone = Profile03ExecutionFixture.pair()
    val browser = Profile03ExecutionFixture.pair()
    val account = ByteArray(16) { 1 }; val device = ByteArray(16) { 2 }
    val line = ByteArray(16) { 3 }; val event = ByteArray(16) { 4 }
    val peer = "+12".toByteArray(Charsets.US_ASCII)
    val now = 100_020L; val observed = 100_010L; val deadline = 100_500L
    val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
    private val rows = row(1, reader, 4) + row(2, archive, 12) + row(3, integration, integrationScope, integrationState) +
        row(4, phone, 2, phoneState, phoneFrom) + row(5, browser, 1) + row(6, root, 0)
    private val old = manifest(2, 1, ByteArray(32))
    private val next = manifest(3, 2, unsigned(old))
    private val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(pin, account,
        sha(ascii("ZTSE/root-pin/v2\u0000") + pin), 1, 1, unsigned(old), ByteArray(32), sha(old), 100_000)
    val authority = Draft03ManifestAuthority.verifyFrom02(next, old, checkpoint, now)
    fun request(withIntegration: Boolean = false, signer: KeyPair = phone, targetPeer: ByteArray = peer,
        readers: List<Draft03ManifestAuthority.Reader>? = null) = Draft03ManifestAuthority.InboundRequest(
        account, event, device, line, targetPeer, id(signer, true), readers ?: listOf(Draft03ManifestAuthority.Reader(2, id(archive))) +
            if (withIntegration) listOf(Draft03ManifestAuthority.Reader(3, id(integration))) else emptyList())
    fun signed(proof: Draft03InboundEnvelope.Unsigned, key: KeyPair = phone) = proof.signed(
        Profile03ExecutionFixture.rawSign(key, proof.transcript()))
    private fun row(role: Int, key: KeyPair, scope: Int, state: Int = 1, from: Long = 1) =
        byteArrayOf(role.toByte()) + id(key, role > 3) + point(key) +
            (if (role == 1 || role == 4) device else ByteArray(16)) +
            (if (role in setOf(1, 4, 5)) line else ByteArray(16)) +
            ByteBuffer.allocate(2).putShort(scope.toShort()).array() + long(from) + long(900_000) + byteArrayOf(state.toByte())
    private fun manifest(profile: Int, version: Long, prior: ByteArray): ByteArray {
        val header = if (profile == 2) ascii("ZTMA") + byteArrayOf(2) else ascii("ZTMA") + byteArrayOf(3, 3, 2)
        val bytes = header + account + long(1) + long(version) + long(99_000) + long(900_000) + prior + point(root) + byteArrayOf(6) + rows
        return bytes + Profile03ExecutionFixture.rawSign(root, ReviewedIntent03.framed("ZTSE/manifest/v$profile", bytes))
    }
    /** Independently decapsulate the selected software test recipient and authenticate body03. */
    fun open(bytes: ByteArray, recipient: KeyPair, role: Int, aadLabel: String = "ZTSE/wrap-aad/v3\u0000",
        infoLabel: String = "ZTSE/wrap/v3\u0000"): ByteArray {
        val protectedEnd = 10 + (ByteBuffer.wrap(bytes, 8, 2).short.toInt() and 65535)
        val header = bytes.copyOfRange(0, 10); val protected = bytes.copyOfRange(10, protectedEnd)
        val bodyLength = ByteBuffer.wrap(bytes, protectedEnd + 12, 4).int
        val bodyEnd = protectedEnd + 16 + bodyLength
        val count = bytes[bodyEnd].toInt() and 255
        val at = (0 until count).map { bodyEnd + 1 + it * 146 }.single {
            bytes[it].toInt() == role && bytes.copyOfRange(it + 1, it + 33).contentEquals(id(recipient)) }
        val enc = bytes.copyOfRange(at + 33, at + 98)
        val suffix = header + protected + byteArrayOf(role.toByte()) + id(recipient)
        val key = hpke(recipient, enc, enc, point(recipient), ascii(infoLabel) + suffix,
            ascii(aadLabel) + suffix, bytes.copyOfRange(at + 98, at + 146), false)
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, bytes.copyOfRange(protectedEnd, protectedEnd + 12)))
                updateAAD(ascii("ZTSE/body/v3\u0000") + header + protected)
                doFinal(bytes.copyOfRange(protectedEnd + 16, bodyEnd))
            }
        } finally { key.fill(0) }
    }
    companion object {
        fun ascii(s: String) = Profile03ExecutionFixture.ascii(s)
        fun long(n: Long) = Profile03ExecutionFixture.long(n)
        fun sha(b: ByteArray) = Profile03ExecutionFixture.sha(b)
        fun unsigned(b: ByteArray) = Profile03ExecutionFixture.unsigned(b)
        fun point(k: KeyPair) = Profile03ExecutionFixture.point(k)
        fun id(k: KeyPair, signing: Boolean = false) = Profile03ExecutionFixture.keyId(k, signing)
        val softwareWrap = Profile03InboundWrapSealer { recipient, key, info, aad, current ->
            current(); val ephemeral = Profile03ExecutionFixture.pair(); val enc = point(ephemeral)
            val ct = hpke(ephemeral, recipient, enc, recipient, info, aad, key, true)
            current(); enc + ct
        }
        private fun hpke(own: KeyPair, peer: ByteArray, enc: ByteArray, recipient: ByteArray,
            info: ByteArray, aad: ByteArray, input: ByteArray, encrypt: Boolean): ByteArray {
            val dh = KeyAgreement.getInstance("ECDH").run { init(own.private); doPhase(DevicePayloadKeyStore.decodePoint(peer), true); generateSecret() }
            try {
                val shared = Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh, enc, recipient)
                try {
                    val material = Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(shared, info)
                    try {
                        return Cipher.getInstance("AES/GCM/NoPadding").run {
                            init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "AES"), GCMParameterSpec(128, material.nonce))
                            updateAAD(aad); doFinal(input)
                        }
                    } finally { material.clear() }
                } finally { shared.fill(0) }
            } finally { dh.fill(0) }
        }
    }
}
