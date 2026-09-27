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

/** One corpus executes against the dormant runtime implementation on JVM and Android. */
abstract class ManifestAuthorityCorpus {
    private val position get() = Draft02ManifestAuthority.Position.genesis(ByteArray(32))

    @Test fun pinnedCrossClientGenesisAndRotatedManifestMatchDigests() {
        val genesis = fixture("draft02-genesis.json")
        verifyFixture(genesis, "", position)
        val rotation = fixture("draft02-rotation.json")
        verifyFixture(rotation, "old_", position)
        verifyFixture(rotation, "new_", Draft02ManifestAuthority.Position.genesis(rotation.bytes("transition_anchor_digest_b64")))
        // The anchor is supplied by the caller; this module never accepts the transition itself.
        denied { verifyFixture(rotation, "new_", position) }
    }

    @Test fun explicitCurrentAndSuccessorRejectForkGapAndOverflow() {
        val sample = Sample()
        val first = sample.verify()
        sample.verify(position = Draft02ManifestAuthority.Position.current(1, first.digest))
        denied { sample.verify(position = Draft02ManifestAuthority.Position.current(1, ByteArray(32))) }
        val successor = sample.manifest(version = 2, previous = first.digest)
        sample.verify(successor, Draft02ManifestAuthority.Position.after(1, first.digest))
        denied { sample.verify(successor, position) }
        denied { sample.verify(sample.manifest(version = 3, previous = first.digest), Draft02ManifestAuthority.Position.after(1, first.digest)) }
        denied { sample.verify(successor, Draft02ManifestAuthority.Position.after(Long.MAX_VALUE, first.digest)) }
        denied { sample.verify(position = Draft02ManifestAuthority.Position.after(1, first.digest)) }
    }

    @Test fun independentAccountRootGenerationAndAnchorAreRequired() {
        val sample = Sample()
        for (trust in listOf(
            Draft02ManifestAuthority.Trust(ByteArray(16) { 9 }, sample.fingerprint, 1, position),
            Draft02ManifestAuthority.Trust(sample.account, ByteArray(32), 1, position),
            Draft02ManifestAuthority.Trust(sample.account, sample.fingerprint, 2, position),
            Draft02ManifestAuthority.Trust(sample.account, sample.fingerprint, 1,
                Draft02ManifestAuthority.Position.genesis(ByteArray(32) { 1 }))
        )) denied { Draft02ManifestAuthority.verify(sample.pin, sample.manifest(), trust, sample.now) }
        denied { Draft02ManifestAuthority.Trust(ByteArray(16), sample.fingerprint, 1, position) }
        denied { Draft02ManifestAuthority.Position.current(0, ByteArray(32)) }
        denied { Draft02ManifestAuthority.Position.genesis(ByteArray(31)) }
    }

    @Test fun parserRejectsBoundsTrailingBytesProfilesAndInvalidPoints() {
        val sample = Sample()
        val valid = sample.manifest()
        for (bad in listOf(ByteArray(0), valid.copyOf(363), valid + byteArrayOf(0), ByteArray(9752),
            valid.copyOf().apply { this[4] = 1 }, valid.copyOf().apply { this[150] = 65 },
            valid.copyOf().apply { this[150] = 0 }, valid.copyOf().apply { this[85] = 0 },
            valid.copyOf().apply { this[184] = 0 }, valid.copyOf().apply { this[29] = 0x80.toByte() }
        )) denied { sample.verify(bad) }
        denied { Draft02ManifestAuthority.verify(sample.pin + byteArrayOf(0), valid, sample.trust(), sample.now) }
    }

    @Test fun correctlySignedMalformedRoleRecordsAreRejected() {
        val sample = Sample()
        val invalidEdits: List<(ByteArray) -> Unit> = listOf(
            { it[151] = 0 }, { it[151 + 131] = 8 }, { it[151 + 148] = 0 },
            { it.fill(0, 151 + 98, 151 + 114) }, { it[151 + 1] = (it[151 + 1].toInt() xor 1).toByte() },
            { ByteBuffer.wrap(it).putLong(151 + 132, sample.now + 50).putLong(151 + 140, sample.now) },
            { it[151 + 149 + 148] = 2 }, // No active archive.
            { it[151 + 4 * 149 + 148] = 2 }, // Owner revoked.
            { it[151 + 149 + 98] = 1 } // Archive has a device subject.
        )
        for (edit in invalidEdits) denied { sample.verify(sample.manifest(edit = edit)) }
        denied { sample.verify(sample.manifest(edit = { bytes ->
            val first = bytes.copyOfRange(151, 300)
            bytes.copyOfRange(300, 449).copyInto(bytes, 151)
            first.copyInto(bytes, 300)
        })) }
        denied { sample.verify(sample.manifest(edit = { bytes ->
            bytes.copyOfRange(151 + 1, 151 + 98).copyInto(bytes, 300 + 1)
        })) }
    }

    @Test fun strictLowSAndManifestDomainAreRequired() {
        val sample = Sample()
        val bytes = sample.manifest()
        val s = BigInteger(1, bytes.copyOfRange(bytes.size - 32, bytes.size))
        fixed(ORDER - s).copyInto(bytes, bytes.size - 32)
        denied { sample.verify(bytes) }
        denied { sample.verify(sample.manifest(label = "ZTSE/root-transition/v2\u0000")) }
        denied { sample.verify(sample.manifest().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }) }
        denied { sample.verify(sample.manifest().apply { fill(0, size - 64, size) }) }
    }

    @Test fun timeBoundsAndLargeSignedTimesDoNotOverflow() {
        val sample = Sample()
        denied { sample.verify(now = 0) }
        denied { sample.verify(now = -1) }
        denied { sample.verify(now = sample.expires) }
        denied { sample.verify(now = sample.issued - 300_001) }
        sample.verify(now = sample.issued - 300_000)
        denied { sample.verify(sample.manifest(edit = { ByteBuffer.wrap(it).putLong(45, sample.issued + 86_400_001) })) }
        denied { sample.verify(sample.manifest(edit = { ByteBuffer.wrap(it).putLong(45, sample.issued) })) }
        val high = sample.manifest(edit = { ByteBuffer.wrap(it).putLong(37, Long.MAX_VALUE - 100)
            .putLong(45, Long.MAX_VALUE)
            .putLong(151 + 4 * 149 + 132, Long.MAX_VALUE - 100)
            .putLong(151 + 4 * 149 + 140, Long.MAX_VALUE) })
        sample.verify(high, now = Long.MAX_VALUE - 50)
        denied { sample.verify(high, now = Long.MAX_VALUE) }
    }

    @Test fun outboundAndInboundContextsSelectExactSignerAndReaders() {
        val sample = Sample()
        val authority = sample.verify()
        val outbound = authority.context(sample.request(), sample.now)
        assertArrayEquals(sample.keys[3].point, outbound.signerPoint)
        assertArrayEquals(sample.keys[3].id, outbound.signerKeyId)
        assertArrayEquals(byteArrayOf(43, 49, 50), outbound.peer)
        assertEquals(1, outbound.version)
        assertArrayEquals(authority.digest, outbound.manifestDigest)
        val inbound = authority.context(sample.request(inbound = true), sample.now)
        assertArrayEquals(sample.keys[2].point, inbound.signerPoint)
        assertEquals(1, inbound.readers.size)
        val integrations = Sample(integrations = 6)
        assertEquals(8, integrations.verify().context(integrations.request(), integrations.now).readers.size)
        val inboundKeys = integrations.manifest(edit = { bytes ->
            repeat(6) { ByteBuffer.wrap(bytes).putShort(151 + (it + 2) * 149 + 130, 12) }
        })
        assertEquals(7, integrations.verify(inboundKeys).context(integrations.request(inbound = true), integrations.now).readers.size)
    }

    @Test fun contextRejectsWrongTenantDeviceLineSignerAndReaderSet() {
        val sample = Sample()
        val authority = sample.verify()
        val reader = sample.readers()
        for (request in listOf(
            sample.request(account = ByteArray(16) { 7 }), sample.request(device = ByteArray(16) { 7 }),
            sample.request(line = ByteArray(16) { 7 }), sample.request(signer = ByteArray(32)),
            sample.request(readers = reader.reversed()), sample.request(readers = listOf(reader[0])),
            sample.request(readers = listOf(reader[1])), sample.request(readers = reader + reader[1]),
            sample.request(readers = listOf(reader[0], Draft02ManifestAuthority.Reader(2, ByteArray(32)))),
            sample.request(inbound = true, readers = reader), sample.request(inbound = true, device = ByteArray(16) { 7 })
        )) denied { authority.context(request, sample.now) }
        denied { sample.request(device = ByteArray(16)) }
        denied { sample.request(readers = emptyList()) }
        for (peer in listOf(ByteArray(0), byteArrayOf(43, 48, 49), byteArrayOf(43, 49, 65), ByteArray(17))) {
            denied { sample.request(peer = peer) }
        }
        val excess = Sample(integrations = 7)
        denied { excess.request() }
        val integrated = Sample(integrations = 1)
        denied { integrated.verify().context(integrated.request(inbound = true), integrated.now) }
        val wrongScope = integrated.manifest(edit = { ByteBuffer.wrap(it).putShort(151 + 2 * 149 + 130, 8) })
        denied { integrated.verify(wrongScope).context(integrated.request(), integrated.now) }
    }

    @Test fun contextRechecksSignedKeyStateValidityAndManifestExpiry() {
        val sample = Sample()
        // Keys outlive the manifest so a missing manifest recheck cannot hide behind key expiry.
        val authority = sample.verify(sample.manifest(edit = { bytes ->
            repeat(sample.keys.size) { ByteBuffer.wrap(bytes).putLong(151 + it * 149 + 140, sample.expires + 60_000) }
        }))
        denied { authority.context(sample.request(), sample.expires) }
        for (record in listOf(0, 3)) {
            for (edit in listOf<(ByteArray) -> Unit>(
                { it[151 + record * 149 + 148] = 2 },
                { ByteBuffer.wrap(it).putLong(151 + record * 149 + 140, sample.now) },
                { ByteBuffer.wrap(it).putLong(151 + record * 149 + 132, sample.now + 1) }
            )) {
                val changed = sample.verify(sample.manifest(edit = edit))
                denied { changed.context(sample.request(), sample.now) }
            }
        }
    }

    @Test fun inputsOutputsAndReaderCollectionsCannotMutateVerifiedAuthority() {
        val sample = Sample()
        val manifest = sample.manifest()
        val pin = sample.pin.copyOf()
        val account = sample.account.copyOf()
        val fingerprint = sample.fingerprint.copyOf()
        val anchor = ByteArray(32)
        val trust = Draft02ManifestAuthority.Trust(account, fingerprint, 1,
            Draft02ManifestAuthority.Position.genesis(anchor))
        account.fill(0); fingerprint.fill(0); anchor.fill(1)
        val authority = Draft02ManifestAuthority.verify(pin, manifest, trust, sample.now)
        val digest = authority.digest.copyOf()
        pin.fill(0); manifest.fill(0); authority.digest.fill(0); authority.accountId.fill(0)
        assertArrayEquals(digest, authority.digest)
        val device = sample.device.copyOf()
        val peer = byteArrayOf(43, 49, 50)
        val keyId = sample.keys[0].id.copyOf()
        val selected = mutableListOf(Draft02ManifestAuthority.Reader(1, keyId), sample.readers()[1])
        val request = sample.request(device = device, peer = peer, readers = selected)
        device.fill(0); peer.fill(0); keyId.fill(0); selected.clear()
        val context = authority.context(request, sample.now)
        context.signerPoint.fill(0); context.manifestDigest.fill(0); context.deviceId.fill(0)
        context.readers[0].keyId.fill(0)
        context.peer.fill(0); context.signerKeyId.fill(0)
        assertArrayEquals(sample.keys[3].point, context.signerPoint)
        assertArrayEquals(digest, context.manifestDigest)
        assertArrayEquals(sample.device, context.deviceId)
        assertArrayEquals(sample.keys[0].id, context.readers[0].keyId)
        assertArrayEquals(byteArrayOf(43, 49, 50), context.peer)
        assertArrayEquals(sample.keys[3].id, context.signerKeyId)
        assertEquals("Draft02ManifestAuthority(verified)", authority.toString())
    }

    @Test fun ownerOnlySignatureIdentityCorpusIsNotFullManifestAuthority() {
        val identity = fixture("ztse-manifest-identity-01.json")
        // This resource belongs to the low-level signature corpus; do not use it as a trust bootstrap.
        assertTrue(identity.length() > 0)
        val sample = Sample()
        val ownerOnly = sample.manifest().let { bytes ->
            val unsigned = bytes.copyOfRange(0, 151) + bytes.copyOfRange(151 + 4 * 149, 151 + 5 * 149)
            unsigned[150] = 1
            sample.sign(unsigned)
        }
        denied { sample.verify(ownerOnly) }
    }

    private fun verifyFixture(json: JSONObject, prefix: String, expected: Draft02ManifestAuthority.Position) {
        val pin = json.bytes(prefix + "root_pin_b64")
        val trust = Draft02ManifestAuthority.Trust(pin.copyOfRange(5, 21), json.bytes(prefix + "root_fingerprint_b64"),
            ByteBuffer.wrap(pin, 21, 8).long, expected)
        val verified = Draft02ManifestAuthority.verify(pin, json.bytes(prefix + "manifest_b64"), trust, json.getLong("now_ms"))
        assertArrayEquals(json.bytes(prefix + "semantic_manifest_digest_b64"), verified.digest)
    }
    private fun fixture(name: String): JSONObject = javaClass.classLoader!!.getResourceAsStream(name)!!.use {
        JSONObject(it.readBytes().toString(Charsets.UTF_8))
    }
    private fun JSONObject.bytes(name: String) = Base64.getDecoder().decode(getString(name))
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { /* fail closed */ }
    }

    private class Sample(integrations: Int = 0) {
        val account = ByteArray(16) { 1 }
        val device = ByteArray(16) { 2 }
        val line = ByteArray(16) { 3 }
        val issued = 1_893_456_000_000L
        val now = issued + 1_000
        val expires = issued + 60_000
        private val root = keyPair()
        val keys = (listOf(1, 2) + List(integrations) { 3 } + listOf(4, 5, 6))
            .map { role -> Record(role, if (role == 6) root else keyPair()) }
            .sortedWith(compareBy<Record> { it.role }.thenBy { BigInteger(1, it.id) })
        val pin = ascii("ZTRP") + byteArrayOf(2) + account + long(1) + point(root)
        val fingerprint = sha(ascii("ZTSE/root-pin/v2\u0000") + pin)
        fun trust(position: Draft02ManifestAuthority.Position = Draft02ManifestAuthority.Position.genesis(ByteArray(32))) =
            Draft02ManifestAuthority.Trust(account, fingerprint, 1, position)
        fun verify(bytes: ByteArray = manifest(), position: Draft02ManifestAuthority.Position = Draft02ManifestAuthority.Position.genesis(ByteArray(32)),
                   now: Long = this.now) = Draft02ManifestAuthority.verify(pin, bytes, trust(position), now)
        fun manifest(version: Long = 1, previous: ByteArray = ByteArray(32),
                     label: String = "ZTSE/manifest/v2\u0000", edit: (ByteArray) -> Unit = {}): ByteArray {
            val header = ascii("ZTMA") + byteArrayOf(2) + account + long(1) + long(version) + long(issued) +
                long(expires) + previous + point(root) + byteArrayOf(keys.size.toByte())
            val unsigned = header + keys.flatMap { key ->
                val deviceBound = key.role == 1 || key.role == 4
                (byteArrayOf(key.role.toByte()) + key.id + key.point + (if (deviceBound) device else ByteArray(16)) +
                    (if (deviceBound || key.role == 5) line else ByteArray(16)) +
                    ByteBuffer.allocate(2).putShort(intArrayOf(0, 4, 12, 4, 2, 1, 0)[key.role].toShort()).array() +
                    long(issued) + long(expires) + byteArrayOf(1)).toList()
            }.toByteArray()
            edit(unsigned)
            return sign(unsigned, label)
        }
        fun sign(unsigned: ByteArray, label: String = "ZTSE/manifest/v2\u0000"): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(root.private); update(ascii(label)); update(ByteBuffer.allocate(4).putInt(unsigned.size).array())
                update(unsigned); sign()
            }
            val rLength = der[3].toInt() and 0xff
            val r = BigInteger(1, der.copyOfRange(4, 4 + rLength))
            val sAt = 4 + rLength
            val s = BigInteger(1, der.copyOfRange(sAt + 2, der.size))
            return unsigned + fixed(r) + fixed(if (s > ORDER.shiftRight(1)) ORDER - s else s)
        }
        fun readers() = keys.filter { it.role <= 3 }.map { Draft02ManifestAuthority.Reader(it.role, it.id) }
        fun request(inbound: Boolean = false, account: ByteArray = this.account, device: ByteArray = this.device,
                    line: ByteArray = this.line, peer: ByteArray = byteArrayOf(43, 49, 50),
                    signer: ByteArray = keys.single { it.role == if (inbound) 4 else 5 }.id,
                    readers: List<Draft02ManifestAuthority.Reader> = if (inbound) readers().filter { it.role != 1 } else readers()) =
            Draft02ManifestAuthority.Request(if (inbound) Draft02ManifestAuthority.Direction.INBOUND else Draft02ManifestAuthority.Direction.OUTBOUND,
                account, ByteArray(16) { 4 }, device, line, peer, signer, readers)
    }
    private class Record(val role: Int, pair: KeyPair) {
        val point = point(pair)
        val id = sha(ascii("ZTSE/key/v1\u0000") + (if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)) + point)
    }
    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun keyPair() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(pair: KeyPair): ByteArray = (pair.public as ECPublicKey).w.let { byteArrayOf(4) + fixed(it.affineX) + fixed(it.affineY) }
        private fun fixed(value: BigInteger): ByteArray = value.toByteArray().let { ByteArray(32 - minOf(32, it.size)) + it.takeLast(32).toByteArray() }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
