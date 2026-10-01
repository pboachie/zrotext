// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature

/**
 * Dormant candidate-02 authority, constructed only after exact-byte verification.
 * Trust and time must come from independently authenticated, durable caller state.
 * This does not enroll or rotate roots, persist a high-water mark, validate a live
 * grant, decrypt content or authorize storage/SMS. No production flow calls it.
 */
internal class Draft02ManifestAuthority private constructor(
    private val account: ByteArray,
    val generation: Long,
    val version: Long,
    private val semanticDigest: ByteArray,
    private val issued: Long,
    private val expires: Long,
    private val records: List<Key>
) {
    val accountId: ByteArray get() = account.copyOf()
    val digest: ByteArray get() = semanticDigest.copyOf()
    override fun toString(): String = "Draft02ManifestAuthority(verified)"

    /** Explicit expected position; later-generation anchors must already be authenticated. */
    class Position private constructor(val kind: Kind, val version: Long, bytes: ByteArray) {
        enum class Kind { GENESIS, AFTER, CURRENT }
        private val value = bytes.copyOf()
        internal fun bytes(): ByteArray = value.copyOf()
        companion object {
            fun genesis(anchor: ByteArray): Position = Position(Kind.GENESIS, 0, anchor).checked()
            fun after(version: Long, digest: ByteArray): Position = Position(Kind.AFTER, version, digest).checked()
            fun current(version: Long, digest: ByteArray): Position = Position(Kind.CURRENT, version, digest).checked()
        }
        private fun checked(): Position = apply {
            require(value.size == 32 && (kind == Kind.GENESIS || version > 0)) { "Chain position" }
        }
    }

    class Trust(accountId: ByteArray, fingerprint: ByteArray, val generation: Long, val position: Position) {
        private val account = accountId.copyOf()
        private val root = fingerprint.copyOf()
        internal fun account(): ByteArray = account.copyOf()
        internal fun fingerprint(): ByteArray = root.copyOf()
        init {
            require(account.size == 16 && !zero(account) && root.size == 32 && generation > 0) { "Trust shape" }
        }
    }

    enum class Direction { OUTBOUND, INBOUND }

    class Reader(val role: Int, keyId: ByteArray) {
        private val id = keyId.copyOf()
        val keyId: ByteArray get() = id.copyOf()
        init { require(id.size == 32) { "Reader ID" } }
    }

    /** Caller-selected routing, never inferred from a relay's manifest directory. */
    class Request(
        val direction: Direction, accountId: ByteArray, messageId: ByteArray,
        deviceId: ByteArray, lineId: ByteArray, peer: ByteArray,
        signerKeyId: ByteArray, readers: List<Reader>
    ) {
        private val account = accountId.copyOf()
        private val message = messageId.copyOf()
        private val device = deviceId.copyOf()
        private val line = lineId.copyOf()
        private val peerValue = peer.copyOf()
        private val signer = signerKeyId.copyOf()
        private val selected = readers.toList()
        internal fun account() = account.copyOf()
        internal fun message() = message.copyOf()
        internal fun device() = device.copyOf()
        internal fun line() = line.copyOf()
        internal fun peer() = peerValue.copyOf()
        internal fun signer() = signer.copyOf()
        internal fun readers() = selected.toList()
        init {
            require(listOf(account, message, device, line).all { it.size == 16 && !zero(it) } &&
                signer.size == 32 && selected.size in 1..8) { "Request shape" }
            require(peerValue.size in 3..16 && peerValue[0] == '+'.code.toByte() &&
                peerValue[1] in '1'.code.toByte()..'9'.code.toByte() &&
                peerValue.drop(2).all { it in '0'.code.toByte()..'9'.code.toByte() }) { "Peer shape" }
        }
    }

    /** Exact values for a subsequent envelope verifier, not a grant or dispatch capability. */
    class Context internal constructor(
        val direction: Direction, account: ByteArray, message: ByteArray, device: ByteArray,
        line: ByteArray, val generation: Long, val version: Long, digest: ByteArray,
        peer: ByteArray, signerId: ByteArray, signer: ByteArray, readers: List<Reader>
    ) {
        private val accountValue = account.copyOf()
        private val messageValue = message.copyOf()
        private val deviceValue = device.copyOf()
        private val lineValue = line.copyOf()
        private val digestValue = digest.copyOf()
        private val signerValue = signer.copyOf()
        private val signerIdValue = signerId.copyOf()
        private val peerValue = peer.copyOf()
        private val readerValues = readers.toList()
        val accountId get() = accountValue.copyOf()
        val messageId get() = messageValue.copyOf()
        val deviceId get() = deviceValue.copyOf()
        val lineId get() = lineValue.copyOf()
        val manifestDigest get() = digestValue.copyOf()
        val signerPoint get() = signerValue.copyOf()
        val signerKeyId get() = signerIdValue.copyOf()
        val peer get() = peerValue.copyOf()
        val readers get() = readerValues.toList()
        override fun toString(): String = "ManifestEnvelopeContext"
    }

    /** Rechecks time at use. Durable chain and live grant checks remain the caller's responsibility. */
    fun context(request: Request, nowMs: Long): Context {
        window(issued, expires, nowMs)
        require(same(request.account(), account)) { "Envelope account" }
        val inbound = request.direction == Direction.INBOUND
        val signer = records.singleOrNull { it.role == (if (inbound) 4 else 5) && same(it.id, request.signer()) }
        require(signer != null && signer.active(nowMs) && signer.scope == (if (inbound) 2 else 1) &&
            same(signer.line, request.line()) && (!inbound || same(signer.device, request.device()))) {
            "Signer authority"
        }
        val readers = request.readers()
        require(readers.size <= if (inbound) 7 else 8) { "Reader count" }
        var prior: Reader? = null
        var devices = 0
        var archives = 0
        var integrations = 0
        for (reader in readers) {
            prior?.let {
                require(reader.role > it.role || reader.role == it.role && compare(reader.keyId, it.keyId) > 0) {
                    "Reader order"
                }
            }
            prior = reader
            val key = records.singleOrNull { it.role == reader.role && same(it.id, reader.keyId) }
            require(key != null && key.active(nowMs) && key.scope and (if (inbound) 8 else 4) != 0) {
                "Reader authority"
            }
            when (reader.role) {
                1 -> {
                    require(!inbound && same(key.device, request.device()) && same(key.line, request.line())) {
                        "Selected device/line"
                    }
                    devices++
                }
                2 -> archives++
                3 -> integrations++
                else -> throw IllegalArgumentException("Reader role")
            }
        }
        require(devices == (if (inbound) 0 else 1) && archives == 1 && integrations <= 6) { "Reader set" }
        return Context(request.direction, account, request.message(), request.device(), request.line(),
            generation, version, semanticDigest, request.peer(), signer.id, signer.point, readers)
    }

    /** Enrollment-only successor: preserve every prior record and add exactly this reply signer. */
    fun requireReplySuccessor(prior: Draft02ManifestAuthority, signerId: ByteArray) {
        require(prior.version < Long.MAX_VALUE && version == prior.version + 1 && generation == prior.generation &&
            same(account, prior.account) && expires == prior.expires && records.size == prior.records.size + 1)
        fun identical(a: Key, b: Key) = a.role == b.role && same(a.id,b.id) && same(a.point,b.point) &&
            same(a.device,b.device) && same(a.line,b.line) && a.scope == b.scope && a.from == b.from &&
            a.until == b.until && a.state == b.state
        require(prior.records.all { old -> records.count { identical(old,it) } == 1 })
        val added = records.filter { next -> prior.records.none { identical(it,next) } }
        require(added.size == 1 && added.single().role == 5 && same(added.single().id,signerId))
    }

    /** Lookup-only device reader check, independent of a reply signer. */
    fun requireDeviceReader(accountId: ByteArray, deviceId: ByteArray, lineId: ByteArray,
                            readerId: ByteArray, nowMs: Long) {
        window(issued, expires, nowMs)
        require(same(accountId, account) && readerId.size == 32)
        val key = records.singleOrNull { it.role == 1 && same(it.id, readerId) }
        require(key != null && key.active(nowMs) && key.scope and 4 != 0 &&
            same(key.device, deviceId) && same(key.line, lineId)) { "Selected device reader" }
    }

    private class Key(val role: Int, val id: ByteArray, val point: ByteArray, val device: ByteArray,
                      val line: ByteArray, val scope: Int, val from: Long, val until: Long, val state: Int) {
        fun active(now: Long) = state == 1 && from <= now && now < until
    }

    companion object {
        private const val DAY = 86_400_000L
        private const val SKEW = 300_000L
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        fun verify(rootPin: ByteArray, manifest: ByteArray, trust: Trust, nowMs: Long): Draft02ManifestAuthority {
            // Bound before allocating copies. All later parsing uses owned snapshots.
            require(rootPin.size == 94 && manifest.size in 364..9751) { "Manifest/pin size" }
            val pin = rootPin.copyOf()
            val bytes = manifest.copyOf()
            require(same(pin.copyOfRange(0, 5), byteArrayOf(0x5a, 0x54, 0x52, 0x50, 2))) { "Pin profile" }
            val account = pin.copyOfRange(5, 21)
            val generation = u64(pin, 21)
            val root = pin.copyOfRange(29, 94)
            require(same(account, trust.account()) && generation == trust.generation &&
                same(sha(ascii("ZTSE/root-pin/v2\u0000") + pin), trust.fingerprint())) { "Root trust" }
            DevicePayloadKeyStore.decodePoint(root)
            require(same(bytes.copyOfRange(0, 5), byteArrayOf(0x5a, 0x54, 0x4d, 0x41, 2))) { "Manifest profile" }
            val count = bytes[150].toInt() and 0xff
            require(count in 1..64 && bytes.size == 215 + 149 * count) { "Manifest exact size" }
            val version = u64(bytes, 29)
            val issued = u64(bytes, 37)
            val expires = u64(bytes, 45)
            require(version > 0 && same(account, bytes.copyOfRange(5, 21)) &&
                generation == u64(bytes, 21) && same(root, bytes.copyOfRange(85, 150))) { "Manifest identity" }
            window(issued, expires, nowMs)
            val keys = ArrayList<Key>(count)
            val points = HashSet<List<Byte>>()
            var owners = 0
            var archives = 0
            repeat(count) { index ->
                val at = 151 + index * 149
                val role = bytes[at].toInt() and 0xff
                val id = bytes.copyOfRange(at + 1, at + 33)
                val point = bytes.copyOfRange(at + 33, at + 98)
                val device = bytes.copyOfRange(at + 98, at + 114)
                val line = bytes.copyOfRange(at + 114, at + 130)
                val scope = ByteBuffer.wrap(bytes, at + 130, 2).short.toInt() and 0xffff
                val from = u64(bytes, at + 132)
                val until = u64(bytes, at + 140)
                val state = bytes[at + 148].toInt() and 0xff
                roleScope(role, scope, device, line)
                require(from <= until && state in 1..2) { "Key validity/state" }
                keys.lastOrNull()?.let { previous ->
                    require(role > previous.role || role == previous.role && compare(id, previous.id) > 0) { "Key order" }
                }
                DevicePayloadKeyStore.decodePoint(point)
                val algorithm = if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)
                require(same(sha(ascii("ZTSE/key/v1\u0000") + algorithm + point), id)) { "Key ID" }
                require(points.add(point.toList())) { "Point alias" }
                if (role == 6) {
                    owners++
                    require(same(point, root) && state == 1 && from <= issued && until >= expires) { "Owner root" }
                }
                if (role == 2 && state == 1) archives++
                keys.add(Key(role, id, point, device, line, scope, from, until, state))
            }
            require(owners == 1 && archives == 1) { "Owner/archive cardinality" }
            val unsigned = bytes.copyOfRange(0, bytes.size - 64)
            signature(root, bytes.copyOfRange(bytes.size - 64, bytes.size), unsigned)
            val digest = sha(unsigned)
            val previous = bytes.copyOfRange(53, 85)
            val position = trust.position
            val expected = position.bytes()
            when (position.kind) {
                Position.Kind.GENESIS -> require(version == 1L && same(previous, expected) &&
                    (if (generation == 1L) zero(expected) else !zero(expected))) { "Genesis anchor" }
                Position.Kind.AFTER -> require(position.version < Long.MAX_VALUE && version == position.version + 1 &&
                    same(previous, expected)) { "Manifest successor" }
                Position.Kind.CURRENT -> require(version == position.version && same(digest, expected)) { "Manifest current" }
            }
            return Draft02ManifestAuthority(account, generation, version, digest, issued, expires, keys)
        }

        private fun window(issued: Long, expires: Long, now: Long) {
            require(now > 0 && issued > 0 && expires > issued && expires - issued <= DAY &&
                (issued <= now || issued - now <= SKEW) && now < expires) { "Manifest freshness" }
        }
        private fun roleScope(role: Int, scope: Int, device: ByteArray, line: ByteArray) {
            require(role in 1..6) { "Key role" }
            val exact = intArrayOf(0, 4, 12, 4, 2, 1, 0)[role]
            require(if (role == 3) scope == 4 || scope == 8 || scope == 12 else scope == exact) { "Key scope" }
            val deviceBound = role == 1 || role == 4
            require(if (deviceBound) !zero(device) else zero(device)) { "Key device" }
            require(if (deviceBound || role == 5) !zero(line) else zero(line)) { "Key line" }
        }
        private fun signature(point: ByteArray, raw: ByteArray, unsigned: ByteArray) {
            val r = BigInteger(1, raw.copyOfRange(0, 32))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            require(r.signum() > 0 && r < ORDER && s.signum() > 0 && s <= ORDER.shiftRight(1)) { "Noncanonical signature" }
            fun integer(value: BigInteger): ByteArray {
                val encoded = value.toByteArray()
                return byteArrayOf(2, encoded.size.toByte()) + encoded
            }
            val fields = integer(r) + integer(s)
            val der = byteArrayOf(0x30, fields.size.toByte()) + fields
            require(Signature.getInstance("SHA256withECDSA").run {
                initVerify(DevicePayloadKeyStore.decodePoint(point))
                update(ascii("ZTSE/manifest/v2\u0000"))
                update(ByteBuffer.allocate(4).putInt(unsigned.size).array())
                update(unsigned)
                verify(der)
            }) { "Owner signature" }
        }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun zero(value: ByteArray) = value.all { it == 0.toByte() }
        private fun u64(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also {
            require(it >= 0) { "Signed storage range" }
        }
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (index in a.indices) {
                val difference = (a[index].toInt() and 0xff) - (b[index].toInt() and 0xff)
                if (difference != 0) return difference
            }
            return 0
        }
    }
}
