// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Genuine public proofs and real body GCM; opaque fixture wraps do not establish HPKE opening. */
open class Draft03BodyCorpus {
    @Test fun genuineBodiesPreserveAsciiAndUnicodeWithoutNormalization() {
        val f = Fixture()
        for (text in listOf("body fixture", "e\u0301 / \u00e9 / \u65e5\u672c / \ud83d\ude00")) {
            val proof = f.proof(f.envelope(text.toByteArray(Charsets.UTF_8)))
            val key = f.key.copyOf()
            val clear = f.open(proof, key)
            try { assertArrayEquals(text.toCharArray(), clear) }
            finally { clear.fill('\u0000') }
            assertCleared(key)
        }
    }

    @Test fun plaintextByteBoundsAndTagOnlyFramingStayDistinct() {
        val f = Fixture()
        for (bytes in listOf(byteArrayOf(65), ByteArray(32_768) { 65 },
            "\u00e9".repeat(16_384).toByteArray(Charsets.UTF_8))) {
            val key = f.key.copyOf()
            val clear = f.open(f.proof(f.envelope(bytes)), key)
            try { assertArrayEquals(bytes.toString(Charsets.UTF_8).toCharArray(), clear) }
            finally { clear.fill('\u0000') }
            assertCleared(key)
        }
        // A real empty GCM ciphertext is tag-only16 and refuses at envelope framing.
        // Neither this case nor the oversized case calls Body.open or proves CEK clearing.
        denied { f.proof(f.envelope(ByteArray(0))) }
        denied { f.proof(f.envelope(ByteArray(32_769) { 65 })) }
    }

    @Test fun wrongKeyWidthsAndWrongEqualWidthKeyRefuseAndConsumeKeys() {
        val f = Fixture()
        val proof = f.proof(f.envelope(ascii("body")))
        for (width in listOf(0, 16, 31, 33)) {
            val key = ByteArray(width) { 7 }
            refuseClears(key) { f.open(proof, key) }
        }
        val wrong = f.key.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() }
        refuseClears(wrong) { f.open(proof, wrong) }
        assertText(f, proof, "body")
    }

    @Test fun validlyResignedBodyAndTagCorruptionRefuseGcm() {
        val f = Fixture()
        for (tag in listOf(false, true)) {
            val bytes = f.envelope(ascii("body"), bodyEdit = { body ->
                val at = if (tag) body.lastIndex else 0
                body[at] = (body[at].toInt() xor 1).toByte()
            })
            val proof = f.proof(bytes) // Outer signature is valid before the body-only negative.
            val key = f.key.copyOf()
            refuseClears(key) { f.open(proof, key) }
        }
    }

    @Test fun validlyResignedNonceChangeRefusesAndOriginalStillOpens() {
        val f = Fixture()
        val bytes = f.envelope(ascii("body"), nonceEdit = { it[0] = 42 })
        val proof = f.proof(bytes)
        val key = f.key.copyOf()
        refuseClears(key) { f.open(proof, key) }
        assertText(f, f.proof(f.envelope(ascii("body"))), "body")
    }

    @Test fun validOuterProofCannotSubstituteV2OrModifiedBodyAad() {
        val f = Fixture()
        val alternateAads: List<(ByteArray) -> ByteArray> = listOf(
            { aad -> ascii("ZTSE/body/v2\u0000") + aad.copyOfRange(13, aad.size) },
            { aad -> aad.copyOf().apply { this[13] = (this[13].toInt() xor 1).toByte() } },
            { aad -> aad.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() } }
        )
        for (aad in alternateAads) {
            val proof = f.proof(f.envelope(ascii("body"), aadEdit = aad))
            val key = f.key.copyOf()
            refuseClears(key) { f.open(proof, key) }
        }
    }

    @Test fun authenticatedMalformedUtf8BomAndNulRefuseAndConsumeKeys() {
        val f = Fixture()
        val invalid = listOf(byteArrayOf(0xc3.toByte(), 0x28),
            byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte(), 65), byteArrayOf(65, 0, 66))
        for (clear in invalid) {
            val proof = f.proof(f.envelope(clear))
            val key = f.key.copyOf()
            refuseClears(key) { f.open(proof, key) }
        }
    }

    @Test fun refusedTimeAuthorityAndRequestConsumeKeyOnParseableProof() {
        val f = Fixture()
        val proof = f.proof(f.envelope(ascii("body")))
        for (time in listOf(0L, f.now - 1, f.envelopeExpiry)) {
            val key = f.key.copyOf()
            refuseClears(key) { Draft03Body.open(proof, f.authority, f.request(), time, key) }
        }
        val other = Fixture()
        val changedAuthorityKey = f.key.copyOf()
        refuseClears(changedAuthorityKey) {
            Draft03Body.open(proof, other.authority, f.request(), f.now, changedAuthorityKey)
        }
        val changedRequestKey = f.key.copyOf()
        refuseClears(changedRequestKey) {
            Draft03Body.open(proof, f.authority, f.request(message = ByteArray(16) { 9 }), f.now, changedRequestKey)
        }
        assertText(f, proof, "body")
    }

    @Test fun verifiedCiphertextAndReturnedCharactersAreOwned() {
        val f = Fixture()
        val input = f.envelope(ascii("body"))
        val proof = f.proof(input)
        input.fill(0)
        proof.envelope.fill(0)
        val key = f.key.copyOf()
        val result = f.open(proof, key)
        assertCleared(key)
        assertArrayEquals("body".toCharArray(), result)
        result.fill('\u0000')
        assertTrue(result.all { it == '\u0000' })
        assertText(f, proof, "body")
    }

    @Test fun bodyOperationRequiresNewKeyButDoesNotMintReplayPermission() {
        val f = Fixture()
        val proof = f.proof(f.envelope(ascii("body")))
        val consumed = f.key.copyOf()
        val clear = f.open(proof, consumed)
        clear.fill('\u0000')
        assertCleared(consumed)
        refuseClears(consumed) { f.open(proof, consumed) }
        // This low-level body primitive has no journal or replay capability.
        assertText(f, proof, "body")
    }

    private fun assertText(f: Fixture, proof: Draft03OutboundEnvelope, text: String) {
        val key = f.key.copyOf()
        val clear = f.open(proof, key)
        try { assertArrayEquals(text.toCharArray(), clear) }
        finally { clear.fill('\u0000') }
        assertCleared(key)
    }
    private fun assertCleared(key: ByteArray) = assertTrue("Owned key must be cleared", key.all { it == 0.toByte() })
    private fun refuseClears(key: ByteArray, action: () -> Unit) {
        denied(action)
        assertCleared(key)
    }
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected refusal") } catch (_: Exception) { /* body/context must fail closed */ }
    }

    /** New synthetic fixture only; no private API exposure or production CEK/RNG hook. */
    private class Fixture {
        val now = 11_000L
        val envelopeExpiry = 12_000L
        val key = ByteArray(32) { (it + 1).toByte() }
        private val account = ByteArray(16) { 1 }
        private val device = ByteArray(16) { 2 }
        private val line = ByteArray(16) { 3 }
        private val root = pair()
        private val records = listOf(1, 2, 4, 5, 6).map { Record(it, if (it == 6) root else pair()) }
        private val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
        private val fingerprint = sha(ascii("ZTSE/root-pin/v2\u0000") + pin)
        private val old = sign(root, ascii("ZTMA") + byteArrayOf(2) + account + long(1) + long(1) +
            long(10_000) + long(100_000) + ByteArray(32) + point(root) + byteArrayOf(records.size.toByte()) +
            recordBytes(), "ZTSE/manifest/v2\u0000")
        private val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(pin, account, fingerprint,
            1, 1, sha(old.copyOfRange(0, old.size - 64)), ByteArray(32), sha(old), now)
        private val manifest = sign(root, ascii("ZTMA") + byteArrayOf(3, 3, 2) + account + long(1) + long(2) +
            long(10_000) + long(100_000) + sha(old.copyOfRange(0, old.size - 64)) + point(root) +
            byteArrayOf(records.size.toByte()) + recordBytes(), "ZTSE/manifest/v3\u0000")
        val authority = Draft03ManifestAuthority.verifyFrom02(manifest, old, checkpoint, now)

        fun request(message: ByteArray = ByteArray(16) { 4 }) = Draft03ManifestAuthority.Request(
            account, message, device, line, ascii("+12"), records.single { it.role == 5 }.id,
            records.filter { it.role <= 3 }.map { Draft03ManifestAuthority.Reader(it.role, it.id) })

        fun envelope(clear: ByteArray, aadEdit: (ByteArray) -> ByteArray = { it },
                     bodyEdit: (ByteArray) -> Unit = {}, nonceEdit: (ByteArray) -> Unit = {}): ByteArray {
            val signer = records.single { it.role == 5 }
            val peer = ascii("+12")
            val protected = account + ByteArray(16) { 4 } + device + line + long(authority.version) +
                authority.digest + signer.id + long(now) + long(envelopeExpiry) + byteArrayOf(1, peer.size.toByte()) + peer
            val header = ascii("ZTSE") + byteArrayOf(3, 1, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            val nonce = ByteArray(12) { 7 }
            val body = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(aadEdit(ascii("ZTSE/body/v3\u0000") + header + protected))
                doFinal(clear)
            }
            bodyEdit(body)
            nonceEdit(nonce)
            val readers = records.filter { it.role <= 3 }
            val wraps = readers.flatMap {
                (byteArrayOf(it.role.toByte()) + it.id + it.point + ByteArray(48) { 7 }).toList()
            }.toByteArray()
            val unsigned = header + protected + nonce + ByteBuffer.allocate(4).putInt(body.size).array() +
                body + byteArrayOf(readers.size.toByte()) + wraps
            return sign(signer.pair, unsigned, "ZTSE/sign/v3\u0000")
        }
        fun proof(bytes: ByteArray) = Draft03OutboundEnvelope.verify(bytes, authority, request()) { now }
        fun open(proof: Draft03OutboundEnvelope, key: ByteArray) = Draft03Body.open(proof, authority, request(), now, key)
        private fun recordBytes() = records.flatMap {
            val bound = it.role == 1 || it.role == 4
            (byteArrayOf(it.role.toByte()) + it.id + it.point + (if (bound) device else ByteArray(16)) +
                (if (bound || it.role == 5) line else ByteArray(16)) +
                ByteBuffer.allocate(2).putShort(intArrayOf(0, 4, 12, 4, 2, 1, 0)[it.role].toShort()).array() +
                long(10_000) + long(100_000) + byteArrayOf(1)).toList()
        }.toByteArray()
    }

    private class Record(val role: Int, val pair: KeyPair) {
        val point = point(pair)
        val id = sha(ascii("ZTSE/key/v1\u0000") + (if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)) + point)
    }
    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun pair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(pair: KeyPair) = (pair.public as ECPublicKey).w.let { byteArrayOf(4) + fixed(it.affineX) + fixed(it.affineY) }
        private fun fixed(value: BigInteger) = value.toByteArray().let { ByteArray(32 - minOf(32, it.size)) + it.takeLast(32).toByteArray() }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        private fun sign(pair: KeyPair, unsigned: ByteArray, label: String): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private); update(ascii(label)); update(ByteBuffer.allocate(4).putInt(unsigned.size).array())
                update(unsigned); sign()
            }
            val rLength = der[3].toInt() and 255
            val r = BigInteger(1, der.copyOfRange(4, 4 + rLength))
            val sAt = 4 + rLength
            val s = BigInteger(1, der.copyOfRange(sAt + 2, der.size))
            return unsigned + fixed(r) + fixed(if (s > ORDER.shiftRight(1)) ORDER - s else s)
        }
    }
}
