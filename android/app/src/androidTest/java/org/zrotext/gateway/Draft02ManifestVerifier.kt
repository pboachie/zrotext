// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.Signature

/** Test-only exact-byte Manifest02 verifier. No production caller or persistent trust store. */
internal object Draft02ManifestVerifier {
    private const val DAY_MS = 86_400_000L
    private const val SKEW_MS = 300_000L
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val zero16 = ByteArray(16)
    private val zero32 = ByteArray(32)
    private val keyLabel = "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII)

    internal data class Trust(
        val accountId: ByteArray, val generation: Long, val rootPoint: ByteArray,
        val version: Long, val digest: ByteArray, val anchorDigest: ByteArray
    )
    internal data class Key(
        val role: Int, val id: ByteArray, val point: ByteArray, val deviceId: ByteArray,
        val lineId: ByteArray, val scope: Int, val fromMs: Long, val untilMs: Long, val state: Int
    )
    internal data class Manifest(
        val accountId: ByteArray, val generation: Long, val version: Long,
        val digest: ByteArray, val issuedMs: Long, val expiresMs: Long,
        val keys: List<Key>, val nextTrust: Trust
    )

    /** expectedFingerprint is supplied by a separately compared owner channel in a real enrollment. */
    fun enroll(pinBytes: ByteArray, expectedFingerprint: ByteArray): Trust {
        require(pinBytes.size == 94 && expectedFingerprint.size == 32) { "Root pin size" }
        require(pinBytes.copyOfRange(0, 5).contentEquals(byteArrayOf(0x5a, 0x54, 0x52, 0x50, 2))) {
            "Root pin magic/profile"
        }
        val account = pinBytes.copyOfRange(5, 21)
        val generation = signedU64(pinBytes, 21)
        val point = pinBytes.copyOfRange(29, 94)
        require(!same(account, zero16) && generation == 1L) { "Root pin identity/generation" }
        DevicePayloadKeyStore.decodePoint(point)
        require(same(sha("ZTSE/root-pin/v2\u0000".toByteArray(Charsets.US_ASCII) + pinBytes),
            expectedFingerprint)) { "Root pin comparison" }
        return Trust(account, generation, point, 0L, zero32.copyOf(), zero32.copyOf())
    }

    fun verify(bytes: ByteArray, pin: Trust, nowMs: Long): Manifest {
        require(bytes.size in 364..9751) { "Manifest size" }
        require(bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(0x5a, 0x54, 0x4d, 0x41, 2))) {
            "Manifest magic/profile"
        }
        val count = bytes[150].toInt() and 0xff
        require(count in 1..64 && bytes.size == 215 + 149 * count) { "Manifest exact size" }
        val account = bytes.copyOfRange(5, 21)
        val generation = signedU64(bytes, 21)
        val version = signedU64(bytes, 29)
        val issued = signedU64(bytes, 37)
        val expires = signedU64(bytes, 45)
        val previous = bytes.copyOfRange(53, 85)
        val root = bytes.copyOfRange(85, 150)
        require(!same(account, zero16) && generation > 0 && version > 0 &&
            same(account, pin.accountId) && generation == pin.generation && same(root, pin.rootPoint)) {
            "Manifest root/account pin"
        }
        currentWindow(issued, expires, nowMs)
        DevicePayloadKeyStore.decodePoint(root)
        val records = ArrayList<Key>(count)
        val points = HashSet<String>()
        var owners = 0
        var archives = 0
        for (i in 0 until count) {
            val at = 151 + i * 149
            val role = bytes[at].toInt() and 0xff
            val id = bytes.copyOfRange(at + 1, at + 33)
            val point = bytes.copyOfRange(at + 33, at + 98)
            val device = bytes.copyOfRange(at + 98, at + 114)
            val line = bytes.copyOfRange(at + 114, at + 130)
            val scope = u16(bytes, at + 130)
            val from = signedU64(bytes, at + 132)
            val until = signedU64(bytes, at + 140)
            val state = bytes[at + 148].toInt() and 0xff
            roleScope(role, scope, device, line)
            require(from <= until && state in 1..2) { "Manifest key validity/state" }
            if (records.isNotEmpty()) {
                val prior = records.last()
                require(role > prior.role || role == prior.role && compareUnsigned(id, prior.id) > 0) {
                    "Manifest record order"
                }
            }
            DevicePayloadKeyStore.decodePoint(point)
            val algorithm = if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)
            require(same(sha(keyLabel + algorithm + point), id)) { "Manifest key ID" }
            require(points.add(point.toHex())) { "Manifest point alias" }
            if (role == 6) {
                owners++
                require(same(point, root) && state == 1 && from <= issued && until >= expires) {
                    "Manifest owner root"
                }
            }
            if (role == 2 && state == 1) archives++
            records.add(Key(role, id, point, device, line, scope, from, until, state))
        }
        require(owners == 1 && archives == 1) { "Manifest owner/archive cardinality" }
        val unsigned = bytes.copyOfRange(0, bytes.size - 64)
        verifySignature(root, bytes.copyOfRange(bytes.size - 64, bytes.size),
            "ZTSE/manifest/v2\u0000", unsigned)
        val semanticDigest = sha(unsigned)
        if (pin.version == 0L) {
            require(version == 1L && same(previous, pin.anchorDigest)) { "Manifest genesis/transition chain" }
        } else {
            require(version == pin.version && same(semanticDigest, pin.digest) ||
                version == pin.version + 1 && same(previous, pin.digest)) { "Manifest rollback/fork/gap" }
        }
        return Manifest(account, generation, version, semanticDigest, issued, expires, records,
            Trust(pin.accountId.copyOf(), pin.generation, pin.rootPoint.copyOf(), version,
                semanticDigest.copyOf(), pin.anchorDigest.copyOf()))
    }

    /** Both roots must sign the same 215-byte transition; no lost-root reset is inferred. */
    fun verifyTransition(bytes: ByteArray, pin: Trust, expectedNewRoot: ByteArray, nowMs: Long): Trust {
        require(bytes.size == 343 && bytes.copyOfRange(0, 5).contentEquals(
            byteArrayOf(0x5a, 0x54, 0x52, 0x54, 2))) { "Transition size/profile" }
        val account = bytes.copyOfRange(5, 21)
        val oldGeneration = signedU64(bytes, 21)
        val newGeneration = signedU64(bytes, 29)
        val oldRoot = bytes.copyOfRange(37, 102)
        val newRoot = bytes.copyOfRange(102, 167)
        val lastDigest = bytes.copyOfRange(167, 199)
        val issued = signedU64(bytes, 199)
        val expires = signedU64(bytes, 207)
        require(pin.version > 0 && oldGeneration < Long.MAX_VALUE &&
            same(account, pin.accountId) && oldGeneration == pin.generation &&
            newGeneration == oldGeneration + 1 && same(oldRoot, pin.rootPoint) &&
            same(newRoot, expectedNewRoot) && !same(newRoot, oldRoot) && same(lastDigest, pin.digest)) {
            "Transition pin/chain"
        }
        currentWindow(issued, expires, nowMs)
        val unsigned = bytes.copyOfRange(0, 215)
        verifySignature(oldRoot, bytes.copyOfRange(215, 279), "ZTSE/root-transition/v2\u0000", unsigned)
        verifySignature(newRoot, bytes.copyOfRange(279, 343), "ZTSE/root-transition/v2\u0000", unsigned)
        return Trust(account, newGeneration, newRoot, 0L, zero32.copyOf(), sha(unsigned))
    }

    /** Returns only the currently authorized outbound signer point. Envelope signature is checked separately. */
    fun authorizeOutbound(manifest: Manifest, parsed: Draft02TinkEnvelopeReceiver.Parsed,
                          expectedDevice: ByteArray, expectedLine: ByteArray, nowMs: Long): ByteArray {
        currentWindow(manifest.issuedMs, manifest.expiresMs, nowMs)
        require(same(parsed.accountId, manifest.accountId) && parsed.keysetVersion == manifest.version &&
            same(parsed.manifestDigest, manifest.digest) &&
            same(parsed.deviceId, expectedDevice) && same(parsed.lineId, expectedLine)) {
            "Manifest envelope binding"
        }
        val signer = manifest.keys.singleOrNull { it.role == 5 && same(it.id, parsed.signerKeyId) }
        require(signer != null && active(signer, nowMs) && signer.scope == 1 &&
            same(signer.lineId, parsed.lineId)) { "Manifest signer authority" }
        var device = 0
        var archive = 0
        var integration = 0
        for (wrap in parsed.wraps) {
            val key = manifest.keys.singleOrNull { it.role == wrap.role && same(it.id, wrap.keyId) }
            require(key != null && active(key, nowMs) && (key.scope and 4) != 0) { "Manifest reader authority" }
            when (wrap.role) {
                1 -> {
                    require(same(key.deviceId, expectedDevice) && same(key.lineId, expectedLine)) {
                        "Manifest selected device/line"
                    }
                    device++
                }
                2 -> archive++
                3 -> integration++
                else -> error("Manifest reader role")
            }
        }
        require(device == 1 && archive == 1 && integration <= 6) { "Manifest reader set" }
        return signer.point.copyOf()
    }

    private fun active(key: Key, now: Long): Boolean =
        key.state == 1 && key.fromMs <= now && now < key.untilMs

    private fun roleScope(role: Int, scope: Int, device: ByteArray, line: ByteArray) {
        require(role in 1..6) { "Manifest role" }
        val exact = intArrayOf(0, 4, 12, 4, 2, 1, 0)[role]
        require(if (role == 3) scope == 4 || scope == 8 || scope == 12 else scope == exact) {
            "Manifest role/scope"
        }
        val deviceBound = role == 1 || role == 4
        val lineBound = deviceBound || role == 5
        require(if (deviceBound) !same(device, zero16) else same(device, zero16)) { "Manifest role/subject" }
        require(if (lineBound) !same(line, zero16) else same(line, zero16)) { "Manifest role/subject" }
    }

    private fun currentWindow(issued: Long, expires: Long, now: Long) {
        require(issued > 0 && expires > issued && expires - issued <= DAY_MS) { "Manifest validity window" }
        require(now >= 0 && issued <= now + SKEW_MS && now < expires) { "Manifest stale/future" }
    }

    private fun verifySignature(point: ByteArray, raw: ByteArray, label: String, unsigned: ByteArray) {
        require(raw.size == 64) { "Manifest signature width" }
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        require(r.signum() > 0 && r < order && s.signum() > 0 && s <= order.shiftRight(1)) {
            "Manifest noncanonical signature"
        }
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(DevicePayloadKeyStore.decodePoint(point))
        verifier.update(label.toByteArray(Charsets.US_ASCII))
        verifier.update(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(unsigned.size).array())
        verifier.update(unsigned)
        require(verifier.verify(rawToDer(raw))) { "Manifest signature verification" }
    }

    private fun rawToDer(raw: ByteArray): ByteArray {
        fun integer(offset: Int): ByteArray {
            var first = offset
            while (first < offset + 31 && raw[first] == 0.toByte()) first++
            val magnitude = raw.copyOfRange(first, offset + 32)
            val positive = if ((magnitude[0].toInt() and 0x80) != 0) byteArrayOf(0) + magnitude else magnitude
            return byteArrayOf(2, positive.size.toByte()) + positive
        }
        val fields = integer(0) + integer(32)
        return byteArrayOf(0x30, fields.size.toByte()) + fields
    }

    private fun sha(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
    private fun signedU64(bytes: ByteArray, at: Int): Long =
        ByteBuffer.wrap(bytes, at, 8).order(ByteOrder.BIG_ENDIAN).long.also { require(it >= 0) }
    private fun u16(bytes: ByteArray, at: Int): Int =
        ByteBuffer.wrap(bytes, at, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xffff
    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return 0
    }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
