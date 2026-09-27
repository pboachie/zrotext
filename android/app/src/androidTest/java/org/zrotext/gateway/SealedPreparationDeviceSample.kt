// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import com.google.crypto.tink.hybrid.HpkeParameters
import com.google.crypto.tink.hybrid.HpkePublicKey
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt
import com.google.crypto.tink.util.Bytes
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Test-only dynamic sender. Tink stays on androidTest, independent of the candidate receiver. */
internal class SealedPreparationDeviceSample(recipient: DevicePayloadPublic) {
    val fixture = PreparationFixture()
    private val root = pair()
    private val signer = pair()
    private val archive = point(pair())
    private val signerId = id(point(signer), false)
    private val archiveId = id(archive, true)
    private val pin = ascii("ZTRP") + byteArrayOf(2) + fixture.account + long(1) + point(root)
    private val now = fixture.now
    private val records = listOf(
        record(1, recipient.keyId, recipient.point, fixture.device, fixture.line, 4),
        record(2, archiveId, archive, ByteArray(16), ByteArray(16), 12),
        record(5, signerId, point(signer), ByteArray(16), fixture.line, 1),
        record(6, id(point(root), false), point(root), ByteArray(16), ByteArray(16), 0))
    private val manifestUnsigned = ascii("ZTMA") + byteArrayOf(2) + fixture.account + long(1) + long(1) +
        long(now - 1000) + long(now + 60_000) + ByteArray(32) + point(root) + byteArrayOf(4) +
        records.fold(byteArrayOf()) { a, b -> a + b }
    val authority = Draft02ManifestAuthority.verify(pin, signed(manifestUnsigned, root, "ZTSE/manifest/v2\u0000"),
        Draft02ManifestAuthority.Trust(fixture.account, PreparationFixture.sha(ascii("ZTSE/root-pin/v2\u0000") + pin), 1,
            Draft02ManifestAuthority.Position.genesis(ByteArray(32))), now)
    val request = Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.OUTBOUND, fixture.account,
        fixture.message, fixture.device, fixture.line, ascii("+12"), signerId, listOf(
            Draft02ManifestAuthority.Reader(1, recipient.keyId), Draft02ManifestAuthority.Reader(2, archiveId)))
    private val protected = fixture.account + fixture.message + fixture.device + fixture.line + long(1) +
        authority.digest + signerId + long(now) + long(now + 20_000) + byteArrayOf(1, 3) + ascii("+12")
    private val header = ascii("ZTSE") + byteArrayOf(2, 1, 0, 0) + short(protected.size)
    val envelope: ByteArray
    val proof: Draft02OutboundEnvelope
    val grant: Draft02OutboundPreparation.Grant

    init {
        val cek = ByteArray(32) { 0x42 }
        try {
            val nonce = ByteArray(12) { 0x24 }
            val body = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(ascii("ZTSE/body/v2\u0000") + header + protected)
                doFinal(ascii("Synthetic device preparation"))
            }
            val unsigned = header + protected + nonce + ByteBuffer.allocate(4).putInt(body.size).array() + body +
                byteArrayOf(2) + wrap(recipient.point, recipient.keyId, 1, cek) + wrap(archive, archiveId, 2, cek)
            envelope = signed(unsigned, signer, "ZTSE/sign/v2\u0000")
        } finally { cek.fill(0) }
        proof = Draft02OutboundEnvelope.verify(envelope, authority, request) { now }
        grant = fixture.grant().copy(unsignedDigest = Draft02OutboundPreparation.hex(proof.unsignedDigest),
            manifestDigest = Draft02OutboundPreparation.hex(authority.digest))
    }
    fun current(time: Long = now) = Draft02OutboundPreparation.Current(grant, authority, request, time, 3,
        listOf(ActiveSimCard(3, 7))) // Synthetic local bindings, never a claim about a real SIM or trusted UTC.
    private fun record(role: Int, keyId: ByteArray, point: ByteArray, device: ByteArray, line: ByteArray, scope: Int) =
        byteArrayOf(role.toByte()) + keyId + point + device + line + short(scope) + long(now - 1000) + long(now + 60_000) + byteArrayOf(1)
    private fun wrap(point: ByteArray, id: ByteArray, role: Int, cek: ByteArray): ByteArray {
        val params = HpkeParameters.builder().setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256).setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .setVariant(HpkeParameters.Variant.NO_PREFIX).build()
        val publicKey = HpkePublicKey.create(params, Bytes.copyFrom(point), null)
        val encrypted = HpkeEncrypt.create(publicKey).encrypt(cek,
            ascii("ZTSE/wrap/v2\u0000") + header + protected + role.toByte() + id)
        check(encrypted.size == 113)
        return byteArrayOf(role.toByte()) + id + encrypted
    }
    companion object {
        private fun pair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(pair: KeyPair) = DevicePayloadKeyStore.encodePoint(pair.public as ECPublicKey)
        private fun ascii(value: String) = value.toByteArray(Charsets.UTF_8)
        private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun short(value: Int) = ByteBuffer.allocate(2).putShort(value.toShort()).array()
        private fun id(point: ByteArray, kem: Boolean) = PreparationFixture.sha(ascii("ZTSE/key/v1\u0000") +
            (if (kem) byteArrayOf(0, 16) else byteArrayOf(1, 1)) + point)
        private fun signed(unsigned: ByteArray, pair: KeyPair, label: String): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private); update(ascii(label)); update(ByteBuffer.allocate(4).putInt(unsigned.size).array())
                update(unsigned); sign()
            }
            return unsigned + Draft01SignaturePrimitive.canonicalRawFromDer(der)
        }
    }
}
