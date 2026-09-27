// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Signature/authorization only: ciphertext here is opaque, never opened or claimed decryptable. */
abstract class OutboundEnvelopeCorpus {
    @Test fun reviewedWebCryptoFixtureHashAndExactV2DomainMatch() {
        // Exact Git blob from main437d5438bc24a102d698e3a7f33a4f845e441c09, introduced by reviewed PR302:
        // protocol/v1/vectors/ztse-draft-02-signatures.json. Preserve bytes via narrow .gitattributes.
        val fixture = resource("candidate02-outbound-signatures.json")
        assertArrayEquals(hex("0f943d9c16c0e2717a869245e6f0dadb0113c34df40667e380cac61da3674b72"), sha(fixture))
        val json = JSONObject(fixture.toString(Charsets.UTF_8))
        assertEquals("UNAPPROVED_DRAFT_02_SIGNATURE_ONLY", json.getString("status"))
        val point = hex(json.getString("signerPublicPointHex"))
        val old = JSONObject(resource("ztse-draft-01.json").toString(Charsets.UTF_8))
        val unsigned = hex(old.getJSONObject("outbound").getString("unsignedHex"))
        unsigned[4] = 2
        sha(ascii("ZTSE/key/v1\u0000") + byteArrayOf(1, 1) + point).copyInto(unsigned, 114)
        val signatures = json.getJSONObject("outbound")
        assertTrue(Draft02OutboundEnvelope.signatureMatches(unsigned + hex(signatures.getString("signatureV2Hex")), point))
        assertFalse(Draft02OutboundEnvelope.signatureMatches(unsigned + hex(signatures.getString("wrongDomainSignatureV1Hex")), point))
    }

    @Test fun verifiedManifestAndExactOutboundBytesProduceCiphertextOnlyIdentity() {
        val sample = Sample()
        val envelope = sample.envelope()
        val verified = sample.verify(envelope)
        assertArrayEquals(envelope, verified.envelope)
        assertArrayEquals(sha(envelope.copyOfRange(0, envelope.size - 64)), verified.unsignedDigest)
        // Randomized canonical signatures of the same unsigned bytes retain one replay identity.
        assertArrayEquals(verified.unsignedDigest, sample.verify(sample.envelope()).unsignedDigest)
        assertEquals("Draft02OutboundEnvelope(verified-ciphertext)", verified.toString())
        assertTrue(Draft02OutboundEnvelope.signatureMatches(envelope, sample.signer.point))
    }

    @Test fun callerAndResultArraysCannotChangeVerifiedBytesOrContext() {
        val sample = Sample()
        val envelope = sample.envelope()
        val expected = envelope.copyOf()
        val peer = ascii("+12")
        val request = sample.request(peer = peer)
        peer.fill(0)
        val result = Draft02OutboundEnvelope.verify(envelope, sample.authority(), request) {
            envelope.fill(0) // Happens after the verifier must have taken its owned snapshot.
            sample.now
        }
        result.envelope.fill(0)
        result.unsignedDigest.fill(0)
        assertArrayEquals(expected, result.envelope)
        assertArrayEquals(sha(expected.copyOfRange(0, expected.size - 64)), result.unsignedDigest)
    }

    @Test fun malformedBoundsOffsetsFlagsPointsAndSignedRangeAreRejected() {
        val sample = Sample()
        val valid = sample.envelope()
        val bodyAt = 167
        val wrapAt = bodyAt + 16 + 17 + 1
        val malformed = listOf(ByteArray(0), valid.copyOf(556), ByteArray(34_214), valid + byteArrayOf(0),
            valid.copyOf().apply { this[4] = 1 }, valid.copyOf().apply { this[5] = 2 },
            valid.copyOf().apply { this[7] = 1 }, valid.copyOf().apply { this[9] = 0 },
            valid.copyOf().apply { this[163] = 16 }, valid.copyOf().apply { this[164] = 0 },
            valid.copyOf().apply { ByteBuffer.wrap(this).putLong(74, Long.MIN_VALUE) },
            valid.copyOf().apply { ByteBuffer.wrap(this).putLong(146, Long.MIN_VALUE) },
            valid.copyOf().apply { ByteBuffer.wrap(this).putInt(bodyAt + 12, -1) },
            valid.copyOf().apply { this[wrapAt + 33] = 0 }, valid.copyOf().apply { this[wrapAt - 1] = 8 },
            valid.copyOf().apply { this[wrapAt + 146] = 1 })
        malformed.forEach { denied { sample.verify(it) } }
    }

    @Test fun highSZeroScalarsWrongDomainAndAnySignedCiphertextMutationAreRejected() {
        val sample = Sample()
        val valid = sample.envelope()
        val high = valid.copyOf()
        fixed(ORDER - BigInteger(1, high.copyOfRange(high.size - 32, high.size))).copyInto(high, high.size - 32)
        denied { sample.verify(high) }
        denied { sample.verify(valid.copyOf().apply { fill(0, size - 64, size - 32) }) }
        denied { sample.verify(valid.copyOf().apply { fill(0, size - 32, size) }) }
        denied { sample.verify(sample.envelope(domain = "ZTSE/sign/v1\u0000")) }
        for (offset in listOf(167, 183, 203, 300, valid.size - 65, valid.lastIndex)) {
            denied { sample.verify(valid.copyOf().apply { this[offset] = (this[offset].toInt() xor 1).toByte() }) }
        }
    }

    @Test fun independentlySignedWrongRouteManifestAndReadersDoNotGainAuthority() {
        val sample = Sample(integrations = 1)
        val offsets = listOf(10, 26, 42, 58, 81, 82, 114, 166, 202)
        for (offset in offsets) {
            val altered = sample.envelope(edit = { it[offset] = (it[offset].toInt() xor if (offset == 81) 2 else 1).toByte() })
            // Each mutant is freshly signed, so semantic/context checks must independently reject it.
            if (offset != 114) assertTrue(Draft02OutboundEnvelope.signatureMatches(altered, sample.signer.point))
            denied { sample.verify(altered) }
        }
        val extraReader = sample.envelope()
        val omitted = sample.request(readers = sample.readers().filter { it.role != 3 })
        denied { Draft02OutboundEnvelope.verify(extraReader, sample.authority(), omitted) { sample.now } }
        val wrongPeer = sample.request(peer = ascii("+13"))
        denied { Draft02OutboundEnvelope.verify(extraReader, sample.authority(), wrongPeer) { sample.now } }
    }

    @Test fun revokedExpiredOrWrongLineManifestSignerCannotAuthorizeCiphertext() {
        val sample = Sample()
        val signerAt = 151 + sample.keys.indexOf(sample.signer) * 149
        val variants: List<(ByteArray) -> Unit> = listOf(
            { it[signerAt + 148] = 2 },
            { ByteBuffer.wrap(it).putLong(signerAt + 140, sample.now) },
            { it[signerAt + 114] = 9 }
        )
        for (edit in variants) {
            val manifest = sample.manifest(edit = edit)
            val authority = sample.authority(manifest)
            val envelope = sample.envelope(manifest = manifest)
            assertTrue(Draft02OutboundEnvelope.signatureMatches(envelope, sample.signer.point))
            denied { Draft02OutboundEnvelope.verify(envelope, authority, sample.request()) { sample.now } }
        }
    }

    @Test fun envelopeExpiryFutureTimeAndFinalClockChecksAreExclusiveAndOverflowSafe() {
        val sample = Sample()
        val valid = sample.envelope()
        denied { sample.verify(valid, now = sample.now + 20_000) }
        denied { sample.verify(sample.envelope(observed = sample.now + 300_001, expires = sample.now + 310_001)) }
        sample.verify(sample.envelope(observed = sample.now + 300_000, expires = sample.now + 310_000))
        denied { sample.verify(sample.envelope(observed = Long.MAX_VALUE - 20, expires = Long.MAX_VALUE)) }
        denied { sample.verify(sample.envelope(observed = sample.now, expires = sample.now + 900_001)) }
        for (finalNow in listOf(sample.now - 1, sample.now + 20_000)) {
            var count = 0
            denied { Draft02OutboundEnvelope.verify(valid, sample.authority(), sample.request()) {
                if (count++ == 0) sample.now else finalNow
            } }
        }
    }

    @Test fun manifestAndSignerFreshnessAreRecheckedAfterSignatureWork() {
        val sample = Sample()
        val envelope = sample.envelope(expires = sample.issued + 120_000)
        val authority = sample.authority()
        var calls = 0
        denied { Draft02OutboundEnvelope.verify(envelope, authority, sample.request()) {
            if (calls++ == 0) sample.now else sample.issued + 60_000
        } }
    }

    @Test fun maximumBodyAndSixExplicitIntegrationReadersRemainBounded() {
        val sample = Sample(integrations = 6)
        val peer = byteArrayOf('+'.code.toByte()) + ByteArray(15) { '1'.code.toByte() }
        val envelope = sample.envelope(bodySize = 32_784, peer = peer)
        assertEquals(34_213, envelope.size)
        val request = sample.request(peer = peer)
        assertEquals(34_213, Draft02OutboundEnvelope.verify(envelope, sample.authority(), request) { sample.now }.envelope.size)
        denied { sample.verify(sample.envelope(bodySize = 16)) }
        denied { sample.verify(sample.envelope(bodySize = 32_785)) }
    }

    private fun resource(name: String) = javaClass.classLoader!!.getResourceAsStream(name)!!.use { it.readBytes() }
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { }
    }

    private class Sample(integrations: Int = 0) {
        val account = ByteArray(16) { 1 }; val device = ByteArray(16) { 2 }; val line = ByteArray(16) { 3 }
        val issued = 1_893_456_000_000L; val now = issued + 1_000
        private val root = pair()
        val keys = (listOf(1, 2) + List(integrations) { 3 } + listOf(4, 5, 6)).map {
            Record(it, if (it == 6) root else pair())
        }.sortedWith(compareBy<Record> { it.role }.thenBy { BigInteger(1, it.id) })
        val signer get() = keys.single { it.role == 5 }
        private val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
        private val normalManifest by lazy { manifest() }
        fun manifest(edit: (ByteArray) -> Unit = {}): ByteArray {
            val header = ascii("ZTMA") + byteArrayOf(2) + account + long(1) + long(1) + long(issued) +
                long(issued + 60_000) + ByteArray(32) + point(root) + keys.size.toByte()
            val records = keys.flatMap { key ->
                val deviceBound = key.role == 1 || key.role == 4
                (byteArrayOf(key.role.toByte()) + key.id + key.point + (if (deviceBound) device else ByteArray(16)) +
                    (if (deviceBound || key.role == 5) line else ByteArray(16)) +
                    ByteBuffer.allocate(2).putShort(intArrayOf(0, 4, 12, 4, 2, 1, 0)[key.role].toShort()).array() +
                    long(issued) + long(issued + 60_000) + byteArrayOf(1)).toList()
            }.toByteArray()
            val unsigned = header + records
            edit(unsigned)
            return signed(unsigned, root, "ZTSE/manifest/v2\u0000")
        }
        fun authority(manifest: ByteArray = normalManifest) = Draft02ManifestAuthority.verify(pin, manifest,
            Draft02ManifestAuthority.Trust(account, sha(ascii("ZTSE/root-pin/v2\u0000") + pin), 1,
                Draft02ManifestAuthority.Position.genesis(ByteArray(32))), now)
        fun readers() = keys.filter { it.role <= 3 }.map { Draft02ManifestAuthority.Reader(it.role, it.id) }
        fun request(peer: ByteArray = ascii("+12"), readers: List<Draft02ManifestAuthority.Reader> = readers()) =
            Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.OUTBOUND, account, ByteArray(16) { 4 },
                device, line, peer, signer.id, readers)
        fun verify(envelope: ByteArray, now: Long = this.now) = Draft02OutboundEnvelope.verify(envelope, authority(), request()) { now }
        fun envelope(manifest: ByteArray = normalManifest, bodySize: Int = 17, peer: ByteArray = ascii("+12"),
                     observed: Long = now, expires: Long = now + 20_000, domain: String = "ZTSE/sign/v2\u0000",
                     edit: (ByteArray) -> Unit = {}): ByteArray {
            val protected = account + ByteArray(16) { 4 } + device + line + long(1) +
                sha(manifest.copyOfRange(0, manifest.size - 64)) + signer.id + long(observed) + long(expires) +
                byteArrayOf(1, peer.size.toByte()) + peer
            val header = ascii("ZTSE") + byteArrayOf(2, 1, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array()
            val readers = keys.filter { it.role <= 3 }
            val wraps = readers.flatMap { (byteArrayOf(it.role.toByte()) + it.id + it.point + ByteArray(48) { 7 }).toList() }.toByteArray()
            val unsigned = header + protected + ByteArray(12) { 8 } + ByteBuffer.allocate(4).putInt(bodySize).array() +
                ByteArray(bodySize) { 9 } + readers.size.toByte() + wraps
            edit(unsigned)
            return signed(unsigned, signer.pair, domain)
        }
    }
    private class Record(val role: Int, val pair: KeyPair) {
        val point = point(pair)
        val id = sha(ascii("ZTSE/key/v1\u0000") + (if (role <= 3) byteArrayOf(0, 16) else byteArrayOf(1, 1)) + point)
    }
    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun pair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(pair: KeyPair) = (pair.public as ECPublicKey).w.let { byteArrayOf(4) + fixed(it.affineX) + fixed(it.affineY) }
        private fun fixed(value: BigInteger) = value.toByteArray().let { ByteArray(32 - minOf(32, it.size)) + it.takeLast(32).toByteArray() }
        private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun hex(value: String) = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        private fun signed(unsigned: ByteArray, pair: KeyPair, label: String): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private); update(ascii(label)); update(ByteBuffer.allocate(4).putInt(unsigned.size).array()); update(unsigned); sign()
            }
            return unsigned + Draft01SignaturePrimitive.canonicalRawFromDer(der)
        }
    }
}
