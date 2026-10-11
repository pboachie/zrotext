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
import java.util.Base64

/** Shared public-verification corpus. Synthetic signed framing cases never claim HPKE opening. */
abstract class Draft03AuthorityEnvelopeCorpus {
    @Test fun actualSdkCiphertextMatchesFreshCommonSubsetAndExactWrapContexts() {
        val f = fixture()
        val now = f.getLong("now_ms")
        val pin = f.bytes("root_pin_b64")
        val old = f.bytes("manifest02_b64")
        val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(pin, f.bytes("account_id_b64"),
            f.bytes("root_fingerprint_b64"), 1, 1, f.bytes("manifest02_digest_b64"),
            f.bytes("original_anchor_digest_b64"), f.bytes("manifest02_sha256_b64"), f.getLong("historical_comparison_ms"))
        // This genuinely SDK-produced case is fresh02 too: common Android/SDK/Rust subset.
        Draft02ManifestAuthority.verify(pin, old, Draft02ManifestAuthority.Trust(f.bytes("account_id_b64"),
            f.bytes("root_fingerprint_b64"), 1, Draft02ManifestAuthority.Position.current(1, f.bytes("manifest02_digest_b64"))), now)
        val authority = Draft03ManifestAuthority.verifyFrom02(f.bytes("manifest03_b64"), old, checkpoint, now)
        assertArrayEquals(f.bytes("manifest03_digest_b64"), authority.digest)
        val readers = f.getJSONArray("readers")
        val request = Draft03ManifestAuthority.Request(f.bytes("account_id_b64"), f.bytes("message_id_b64"),
            f.bytes("device_id_b64"), f.bytes("line_id_b64"), f.bytes("peer_b64"), f.bytes("signer_key_id_b64"),
            (0 until readers.length()).map { readers.getJSONObject(it).let { row ->
                Draft03ManifestAuthority.Reader(row.getInt("role"), row.bytes("key_id_b64"))
            } })
        val verified = Draft03OutboundEnvelope.verify(f.bytes("envelope_b64"), authority, request) { now }
        assertArrayEquals(f.bytes("unsigned_sha256_b64"), verified.unsignedDigest)
        assertArrayEquals(f.bytes("envelope_sha256_b64"), verified.envelopeDigest)
        val parts = verified.parts(authority, request, now)
        assertArrayEquals(f.bytes("device_info_b64"), parts.info)
        assertArrayEquals(f.bytes("device_aad_b64"), parts.aad)
        assertArrayEquals(f.bytes("body_aad_b64"), parts.bodyAad)
        assertTrue(parts.info.isNotEmpty() && parts.aad.isNotEmpty())
        assertFalse(parts.info.contentEquals(parts.aad))
        assertFalse(parts.info.contentEquals(ascii("ZTSE/wrap/v2\u0000") + parts.header + parts.protected + byteArrayOf(1) + parts.keyId))
        assertEquals(65, parts.enc.size); assertEquals(48, parts.wrap.size)
        val next = Draft03ManifestAuthority.verifySuccessor(f.bytes("successor03_b64"), authority, now)
        assertArrayEquals(f.bytes("successor03_digest_b64"), next.digest)
        val alternate = Draft03ManifestAuthority.verifyCurrent(f.bytes("current_alternate03_b64"), authority, now)
        assertArrayEquals(authority.digest, alternate.digest)
        assertFalse(authority.signedBytes.contentEquals(alternate.signedBytes))
        denied { Draft03ManifestAuthority.verifySuccessor(old, authority, now) }
        denied { Draft02ManifestAuthority.verify(pin, f.bytes("manifest03_b64"), Draft02ManifestAuthority.Trust(
            f.bytes("account_id_b64"), f.bytes("root_fingerprint_b64"), 1, Draft02ManifestAuthority.Position.genesis(ByteArray(32))), now) }
    }

    @Test fun expired02IsOnlyHistoricalEvidenceAndRequiresOriginalCheckpoint() {
        val s = Sample()
        val old = s.old(expires = 12_000)
        val checkpoint = s.checkpoint(old)
        val fresh = s.manifest(old)
        val authority = Draft03ManifestAuthority.verifyFrom02(fresh, old, checkpoint, 20_000)
        authority.context(s.request(), 20_000)
        denied { Draft02ManifestAuthority.verify(s.pin, old, s.oldTrust(old), 20_000) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, s.checkpoint(old, at = 12_000), 20_000) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, s.checkpoint(old, evidence = ByteArray(32)), 20_000) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old + byteArrayOf(0), checkpoint, 20_000) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, checkpoint, s.expires) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, checkpoint, s.now - 1) }
        denied { s.checkpoint(old, anchor = ByteArray(32) { 1 }) }
        denied { s.checkpoint(old, generation = 2) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, s.checkpoint(old, fingerprint = ByteArray(32)), 20_000) }
        denied { Draft03ManifestAuthority.verifyFrom02(fresh, old, s.checkpoint(old, account = ByteArray(16) { 9 }), 20_000) }
    }

    @Test fun expired03CanContinueChainWithoutRevivingCurrentPermission() {
        val s = Sample()
        val firstBytes = s.manifest(expires = 12_000)
        val first = s.verify(firstBytes)
        val nextBytes = s.manifest(version = 3, previous = first.digest, predecessor = 3, issued = 19_000, expires = 30_000)
        val next = Draft03ManifestAuthority.verifySuccessor(nextBytes, first, 20_000)
        next.context(s.request(), 20_000)
        denied { first.context(s.request(), 20_000) }
        denied { Draft03ManifestAuthority.verifyCurrent(firstBytes, first, 20_000) }
        denied { Draft03ManifestAuthority.verifySuccessor(nextBytes, first, s.now - 1) }
        denied { Draft03ManifestAuthority.verifySuccessor(s.manifest(version = 4, previous = first.digest, predecessor = 3), first, 20_000) }
        denied { Draft03ManifestAuthority.verifySuccessor(s.manifest(version = 3, predecessor = 3), first, 20_000) }
        denied { Draft03ManifestAuthority.verifySuccessor(s.manifest(version = 3, previous = first.digest), first, 20_000) }
    }

    @Test fun alternateCurrentSignatureDoesNotReplaceOriginalEvidenceOrAcceptFork() {
        val s = Sample()
        val original = s.manifest()
        val accepted = s.verify(original)
        val alternate = s.sign(s.root, original.copyOfRange(0, original.size - 64), "ZTSE/manifest/v3\u0000")
        assertFalse(original.contentEquals(alternate))
        val current = Draft03ManifestAuthority.verifyCurrent(alternate, accepted, s.now)
        assertArrayEquals(accepted.digest, current.digest)
        assertArrayEquals(original, accepted.signedBytes)
        assertArrayEquals(alternate, current.signedBytes)
        denied { Draft03ManifestAuthority.verifyCurrent(s.manifest(edit = { ByteBuffer.wrap(it).putLong(39, s.issued + 1) }), accepted, s.now) }
        denied { Draft03ManifestAuthority.verifyCurrent(s.manifest(version = 3, predecessor = 3), accepted, s.now) }
        denied { Draft03ManifestAuthority.verifyCurrent(alternate.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }, accepted, s.now) }
    }

    @Test fun correctlySignedInvalidRoleSubjectsScopesAndPointAliasesRefuse() {
        val s = Sample()
        val bad: List<(ByteArray) -> Unit> = listOf(
            { it[153] = 0 }, { it[153 + 131] = 8 }, { it[153 + 148] = 0 },
            { it.fill(0, 153 + 98, 153 + 114) }, { it[153 + 149 + 98] = 1 },
            { it[153 + 1] = (it[153 + 1].toInt() xor 1).toByte() },
            { ByteBuffer.wrap(it).putLong(153 + 132, s.now + 1).putLong(153 + 140, s.now) },
            { it[153 + 149 + 148] = 2 }, { it[153 + 5 * 149 + 148] = 2 },
            { it.copyOfRange(153 + 1, 153 + 98).copyInto(it, 153 + 149 + 1) },
            { val first = it.copyOfRange(153, 302); it.copyOfRange(302, 451).copyInto(it, 153); first.copyInto(it, 302) }
        )
        for (edit in bad) denied { s.verify(s.manifest(edit = edit)) }
    }

    @Test fun chainDiscriminatorsGenesisGenerationAndOverflowAreExplicit() {
        val s = Sample()
        for (edit in listOf<(ByteArray) -> Unit>(
            { it[4] = 2 }, { it[5] = 2 }, { it[6] = 0 }, { it[6] = 3 },
            { ByteBuffer.wrap(it).putLong(23, 2) }, { ByteBuffer.wrap(it).putLong(31, 1) },
            { ByteBuffer.wrap(it).putLong(31, 3) }, { it.fill(0, 55, 87) }
        )) denied { s.verify(s.manifest(edit = edit)) }
        val last02 = s.old(version = Long.MAX_VALUE)
        denied { Draft03ManifestAuthority.verifyFrom02(s.manifest(last02, version = Long.MAX_VALUE), last02, s.checkpoint(last02), s.now) }
    }

    @Test fun strictScalarsCurvesDomainsAndManifestBoundsRefuse() {
        val s = Sample()
        val valid = s.manifest()
        for (bad in listOf(ByteArray(365), valid + byteArrayOf(0), ByteArray(9754),
            highS(valid), valid.copyOf().apply { fill(0, size - 64, size) },
            s.manifest(label = "ZTSE/manifest/v2\u0000"),
            s.manifest(edit = { it[87] = 0 }), s.manifest(edit = { it[153 + 33] = 0 }),
            s.manifest(edit = { it[152] = 0 }), s.manifest(edit = { it[23] = 0x80.toByte() })
        )) denied { s.verify(bad) }
        denied { s.verify(now = 0) }
        denied { s.verify(now = s.issued - 300_001) }
        fun futureManifest(issued: Long) = s.manifest(issued = issued, expires = 600_000, edit = {
            repeat(s.keys.size) { i -> ByteBuffer.wrap(it).putLong(153 + i * 149 + 140, 600_000) }
        })
        s.verify(futureManifest(s.now + 300_000))
        denied { s.verify(futureManifest(s.now + 300_001)) }
        val high = s.manifest(issued = Long.MAX_VALUE - 100, expires = Long.MAX_VALUE, edit = {
            repeat(s.keys.size) { i -> ByteBuffer.wrap(it).putLong(153 + i * 149 + 132, Long.MAX_VALUE - 100)
                .putLong(153 + i * 149 + 140, Long.MAX_VALUE) }
        })
        val authority = s.verify(high, now = Long.MAX_VALUE - 50)
        authority.context(s.request(), Long.MAX_VALUE - 50)
        denied { authority.context(s.request(), Long.MAX_VALUE) }
        denied { s.verify(s.manifest(expires = s.issued + 86_400_001)) }
    }

    @Test fun exactRoutingReaderRolesAndFullDeadlineMustMatchFreshAuthority() {
        val s = Sample()
        val authority = s.verify()
        val bytes = s.envelope(authority)
        s.verifyEnvelope(bytes, authority)
        for (request in listOf(s.request(account = ByteArray(16) { 8 }), s.request(device = ByteArray(16) { 8 }),
            s.request(line = ByteArray(16) { 8 }), s.request(message = ByteArray(16) { 8 }),
            s.request(peer = ascii("+13")), s.request(signer = ByteArray(32)),
            s.request(readers = s.readers().reversed()), s.request(readers = s.readers().take(2)),
            s.request(readers = listOf(s.readers()[0], s.readers()[0], s.readers()[1])))) {
            denied { Draft03OutboundEnvelope.verify(bytes, authority, request) { s.now } }
        }
        for (record in listOf(0, 1, 2, 4)) {
            val short = s.verify(s.manifest(edit = { ByteBuffer.wrap(it).putLong(153 + record * 149 + 140, s.now + 5) }))
            short.context(s.request(), s.now)
            denied { s.verifyEnvelope(s.envelope(short), short) }
            denied {
                val revoked = s.verify(s.manifest(edit = { it[153 + record * 149 + 148] = 2 }))
                revoked.context(s.request(), s.now)
            }
        }
    }

    @Test fun outboundFramingSignatureAndExactEofRefuseMalformedCiphertext() {
        val s = Sample()
        val authority = s.verify()
        val bytes = s.envelope(authority)
        val pEnd = 10 + (ByteBuffer.wrap(bytes, 8, 2).short.toInt() and 65535)
        val bodyEnd = pEnd + 16 + 17
        for (bad in listOf(ByteArray(556), ByteArray(34_214), bytes + byteArrayOf(0), bytes.copyOf(bytes.size - 1),
            highS(bytes), bytes.copyOf().apply { fill(0, size - 64, size) },
            s.envelope(authority, label = "ZTSE/sign/v2\u0000"))) denied { s.verifyEnvelope(bad, authority) }
        val edits: List<(ByteArray) -> Unit> = listOf(
            { it[4] = 2 }, { it[5] = 2 }, { it[6] = 1 }, { it[9] = 1 },
            { it.fill(0, 10, 26) }, { it[10 + 153] = 2 }, { it[10 + 155] = 48 },
            { ByteBuffer.wrap(it).putLong(10 + 136, 0) }, { ByteBuffer.wrap(it).putLong(10 + 144, s.now) },
            { ByteBuffer.wrap(it).putInt(pEnd + 12, 16) }, { it[bodyEnd] = 9 },
            { it[bodyEnd + 1] = 2 }, { it[bodyEnd + 1 + 33] = 0 },
            { it[10 + 64] = 0x80.toByte() }
        )
        for (edit in edits) denied { s.verifyEnvelope(s.envelope(authority, edit = edit), authority) }
    }

    @Test fun clockIsRecheckedAfterSignatureAndCannotRegressOrExpire() {
        val s = Sample()
        val authority = s.verify()
        val bytes = s.envelope(authority)
        for (last in listOf(s.now - 1, s.now + 1000, s.expires)) {
            var calls = 0
            denied { Draft03OutboundEnvelope.verify(bytes, authority, s.request()) { if (calls++ == 0) s.now else last } }
            assertEquals(2, calls)
        }
        val captured = Draft03OutboundEnvelope.verify(bytes, authority, s.request()) { s.now + 10 }
        captured.parts(authority, s.request(), s.now + 10)
        // Authority was verified at s.now. It cannot rejuvenate this later envelope proof.
        denied { captured.parts(authority, s.request(), s.now + 9) }
        val longLived = s.verify(s.manifest(expires = 400_000, edit = {
            repeat(s.keys.size) { i -> ByteBuffer.wrap(it).putLong(153 + i * 149 + 140, 400_000) }
        }))
        val future = s.envelope(longLived, observed = s.now + 300_001, expires = s.now + 301_000)
        denied { s.verifyEnvelope(future, longLived) }
    }

    @Test fun inputsAndOutputsAreOwnedBeforeExternalClockAndAfterVerification() {
        val s = Sample()
        val old = s.old()
        val evidence = sha(old)
        val pin = s.pin.copyOf()
        val checkpoint = s.checkpoint(old, pin = pin, evidence = evidence)
        pin.fill(0); evidence.fill(0)
        val manifest = s.manifest(old)
        val authority = Draft03ManifestAuthority.verifyFrom02(manifest, old, checkpoint, s.now)
        val digest = authority.digest
        manifest.fill(0); old.fill(0); authority.digest.fill(0); authority.rootPoint.fill(0); authority.signedBytes.fill(0)
        val peer = ascii("+12")
        val readerId = s.keys[0].id.copyOf()
        val readers = s.readers().toMutableList().apply { this[0] = Draft03ManifestAuthority.Reader(1, readerId) }
        val request = s.request(peer = peer, readers = readers)
        val bytes = s.envelope(authority)
        val verified = Draft03OutboundEnvelope.verify(bytes, authority, request) {
            bytes.fill(0); peer.fill(0); readerId.fill(0); readers.clear(); s.now
        }
        assertArrayEquals(digest, authority.digest)
        val expected = verified.parts(authority, request, s.now).info
        verified.envelope.fill(0); verified.unsignedDigest.fill(0); verified.envelopeDigest.fill(0)
        val parts = verified.parts(authority, request, s.now)
        for (part in listOf(parts.header, parts.protected, parts.nonce, parts.body, parts.keyId, parts.enc, parts.wrap, parts.info, parts.aad, parts.bodyAad)) part.fill(0)
        assertArrayEquals(expected, verified.parts(authority, request, s.now).info)
        denied { verified.parts(authority, request, s.now + 1000) }
    }

    @Test fun maximumReaderSetAndCiphertextBoundsStayBounded() {
        val s = Sample(integrations = 6)
        val authority = s.verify()
        val maximumPeer = byteArrayOf(43) + ByteArray(15) { 49 }
        val bytes = s.envelope(authority, bodySize = 32_784, peer = maximumPeer)
        assertEquals(34_213, bytes.size)
        val request = s.request(peer = maximumPeer)
        Draft03OutboundEnvelope.verify(bytes, authority, request) { s.now }
        denied { s.request(readers = s.readers() + s.readers()[0]) }
    }

    private fun fixture() = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-sdk-outbound-01.json")!!.use {
        JSONObject(it.readBytes().toString(Charsets.UTF_8))
    }
    private fun JSONObject.bytes(name: String) = Base64.getDecoder().decode(getString(name))
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected refusal") } catch (_: IllegalArgumentException) { /* fail closed */ }
    }

    private class Sample(integrations: Int = 1) {
        val account = ByteArray(16) { 1 }; val device = ByteArray(16) { 2 }; val line = ByteArray(16) { 3 }
        val issued = 10_000L; val now = 11_000L; val expires = 100_000L
        val root = pair()
        val keys = (listOf(1, 2) + List(integrations) { 3 } + listOf(4, 5, 6)).map { role -> Record(role, if (role == 6) root else pair()) }
            .sortedWith(compareBy<Record> { it.role }.thenBy { BigInteger(1, it.id) })
        val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
        val fingerprint = sha(ascii("ZTSE/root-pin/v2\u0000") + pin)
        fun old(version: Long = 1, expires: Long = this.expires): ByteArray = sign(root,
            ascii("ZTMA") + byteArrayOf(2) + account + long(1) + long(version) + long(issued) + long(expires) +
                ByteArray(32) + point(root) + byteArrayOf(keys.size.toByte()) + records(), "ZTSE/manifest/v2\u0000")
        fun oldTrust(old: ByteArray) = Draft02ManifestAuthority.Trust(account, fingerprint, 1,
            Draft02ManifestAuthority.Position.current(ByteBuffer.wrap(old, 29, 8).long, sha(old.copyOfRange(0, old.size - 64))))
        fun checkpoint(old: ByteArray, at: Long = now, pin: ByteArray = this.pin, account: ByteArray = this.account,
                       fingerprint: ByteArray = this.fingerprint, generation: Long = 1,
                       anchor: ByteArray = ByteArray(32), evidence: ByteArray = sha(old)) =
            Draft03ManifestAuthority.Accepted02Checkpoint(pin, account, fingerprint, generation, ByteBuffer.wrap(old, 29, 8).long,
                sha(old.copyOfRange(0, old.size - 64)), anchor, evidence, at)
        fun manifest(old: ByteArray = old(), version: Long = 2,
                     previous: ByteArray = sha(old.copyOfRange(0, old.size - 64)), predecessor: Int = 2,
                     issued: Long = this.issued, expires: Long = this.expires,
                     label: String = "ZTSE/manifest/v3\u0000", edit: (ByteArray) -> Unit = {}): ByteArray {
            val unsigned = ascii("ZTMA") + byteArrayOf(3, 3, predecessor.toByte()) + account + long(1) + long(version) +
                long(issued) + long(expires) + previous + point(root) + byteArrayOf(keys.size.toByte()) + records()
            edit(unsigned)
            return sign(root, unsigned, label)
        }
        fun verify(bytes: ByteArray = manifest(), now: Long = this.now) = old().let {
            Draft03ManifestAuthority.verifyFrom02(bytes, it, checkpoint(it), now)
        }
        fun readers() = keys.filter { it.role <= 3 }.map { Draft03ManifestAuthority.Reader(it.role, it.id) }
        fun request(account: ByteArray = this.account, message: ByteArray = ByteArray(16) { 4 },
                    device: ByteArray = this.device, line: ByteArray = this.line, peer: ByteArray = ascii("+12"),
                    signer: ByteArray = keys.single { it.role == 5 }.id, readers: List<Draft03ManifestAuthority.Reader> = readers()) =
            Draft03ManifestAuthority.Request(account, message, device, line, peer, signer, readers)
        fun envelope(authority: Draft03ManifestAuthority, observed: Long = now, expires: Long = now + 1000,
                     bodySize: Int = 17, peer: ByteArray = ascii("+12"), label: String = "ZTSE/sign/v3\u0000",
                     edit: (ByteArray) -> Unit = {}): ByteArray {
            val signer = keys.single { it.role == 5 }
            val protected = account + ByteArray(16) { 4 } + device + line + long(authority.version) + authority.digest +
                signer.id + long(observed) + long(expires) + byteArrayOf(1, peer.size.toByte()) + peer
            val unsigned = ascii("ZTSE") + byteArrayOf(3, 1, 0, 0) + ByteBuffer.allocate(2).putShort(protected.size.toShort()).array() +
                protected + ByteArray(12) + ByteBuffer.allocate(4).putInt(bodySize).array() + ByteArray(bodySize) { 9 } +
                byteArrayOf(readers().size.toByte()) + keys.filter { it.role <= 3 }.flatMap {
                    (byteArrayOf(it.role.toByte()) + it.id + it.point + ByteArray(48) { 7 }).toList()
                }.toByteArray()
            edit(unsigned)
            return sign(signer.pair, unsigned, label)
        }
        fun verifyEnvelope(bytes: ByteArray, authority: Draft03ManifestAuthority) =
            Draft03OutboundEnvelope.verify(bytes, authority, request()) { now }
        private fun records() = keys.flatMap {
            val bound = it.role == 1 || it.role == 4
            (byteArrayOf(it.role.toByte()) + it.id + it.point + (if (bound) device else ByteArray(16)) +
                (if (bound || it.role == 5) line else ByteArray(16)) +
                ByteBuffer.allocate(2).putShort(intArrayOf(0, 4, 12, 4, 2, 1, 0)[it.role].toShort()).array() +
                long(issued) + long(expires) + byteArrayOf(1)).toList()
        }.toByteArray()
        fun sign(pair: KeyPair, unsigned: ByteArray, label: String): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private); update(ascii(label)); update(ByteBuffer.allocate(4).putInt(unsigned.size).array()); update(unsigned); sign()
            }
            val rLength = der[3].toInt() and 255
            val r = BigInteger(1, der.copyOfRange(4, 4 + rLength))
            val sAt = 4 + rLength
            val s = BigInteger(1, der.copyOfRange(sAt + 2, der.size))
            return unsigned + fixed(r) + fixed(if (s > ORDER.shiftRight(1)) ORDER - s else s)
        }
    }
    private class Record(val role: Int, val pair: KeyPair) {
        val point = point(pair)
        val id = sha(ascii("ZTSE/key/v1\u0000") + (if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)) + point)
    }
    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun pair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(pair: KeyPair) = (pair.public as ECPublicKey).w.let { byteArrayOf(4) + fixed(it.affineX) + fixed(it.affineY) }
        private fun fixed(value: BigInteger): ByteArray = value.toByteArray().let { ByteArray(32 - minOf(32, it.size)) + it.takeLast(32).toByteArray() }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun highS(bytes: ByteArray) = bytes.copyOf().apply {
            fixed(ORDER - BigInteger(1, copyOfRange(size - 32, size))).copyInto(this, size - 32)
        }
    }
}
