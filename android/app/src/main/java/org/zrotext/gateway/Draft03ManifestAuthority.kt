// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature

/** Public cryptographic authority only. No durable selection, session, grant or SMS capability. */
internal class Draft03ManifestAuthority private constructor(
    private val account: ByteArray, val version: Long, private val semanticDigest: ByteArray,
    private val root: ByteArray, private val anchor: ByteArray, val predecessorProfile: Int,
    private val previous: ByteArray, private val issued: Long, private val expires: Long,
    val comparisonMs: Long, private val records: List<Key>, private val signed: ByteArray
) {
    val generation: Long get() = 1
    val accountId get() = account.copyOf()
    val digest get() = semanticDigest.copyOf()
    val rootPoint get() = root.copyOf()
    val signedBytes get() = signed.copyOf()
    override fun toString() = "Draft03ManifestAuthority(verified)"

    /** TRUSTED adapter input, not a locally authenticated token. The real adapter is absent.
     * Original anchor/time/evidence must come from authenticated retained acceptance state. */
    class Accepted02Checkpoint(rootPin: ByteArray, accountId: ByteArray, rootFingerprint: ByteArray,
                               val generation: Long, val version: Long, unsignedDigest: ByteArray,
                               originalAnchorDigest: ByteArray, signedManifestSha256: ByteArray,
                               val verifiedAtMs: Long) {
        private val pin = exactCopy(rootPin, 94)
        private val account = exactCopy(accountId, 16)
        private val fingerprint = exactCopy(rootFingerprint, 32)
        private val digest = exactCopy(unsignedDigest, 32)
        private val anchor = exactCopy(originalAnchorDigest, 32)
        private val evidence = exactCopy(signedManifestSha256, 32)
        internal fun pin() = pin.copyOf()
        internal fun account() = account.copyOf()
        internal fun fingerprint() = fingerprint.copyOf()
        internal fun digest() = digest.copyOf()
        internal fun anchor() = anchor.copyOf()
        internal fun evidence() = evidence.copyOf()
        init {
            require(pin.size == 94 && account.size == 16 && !zero(account) && fingerprint.size == 32 &&
                digest.size == 32 && anchor.size == 32 && zero(anchor) && evidence.size == 32 &&
                generation == 1L && version > 0 && verifiedAtMs > 0) { "Accepted02 checkpoint shape" }
        }
        override fun toString() = "TrustedAccepted02Checkpoint"
    }

    class Reader(val role: Int, keyId: ByteArray) {
        private val id = exactCopy(keyId, 32)
        val keyId get() = id.copyOf()
        init { require(id.size == 32) { "Reader ID" } }
    }

    /** Readiness checks only the payload reader. Independently authenticated E500/device keys
     * do not inherit or require the manifest's distinct role04 inbound-event signing authority. */
    internal fun requireSelectedReader(device: ByteArray, line: ByteArray, readerId: ByteArray,
        readerPoint: ByteArray, nowMs: Long, deadline: Long) {
        require(nowMs >= comparisonMs && deadline > nowMs)
        window(issued, expires, nowMs)
        require(deadline <= expires)
        val key = records.singleOrNull { it.role == 1 && same(it.id, readerId) }
        require(key != null && key.active(nowMs) && deadline <= key.until && key.scope == 4 &&
            same(key.device, device) && same(key.line, line) && same(key.point, readerPoint)) { "Selected device reader" }
    }

    /** Public role/lifetime verification for a distinct03 content ceremony. This cannot grant
     * owner/session/MFA, connector mappings, phone consent, custody or installed permission.
     * Device authentication and original SEALED signing keys never substitute for these roles.
     */
    internal class IntervalKeys(phonePoint: ByteArray, browserPoint: ByteArray, integrationPoints: Map<String, ByteArray>) {
        private val phone = phonePoint.copyOf(); private val browser = browserPoint.copyOf()
        private val integrations = integrationPoints.mapValues { it.value.copyOf() }
        fun phonePoint() = phone.copyOf()
        fun browserPoint() = browser.copyOf()
        fun integrationPoint(keyId: ByteArray) = checkNotNull(integrations[Draft02OutboundPreparation.hex(keyId)]).copyOf()
        override fun toString() = "Draft03ConversationPublicRoles"
    }
    internal fun intervalKeys(statement: ConversationInterval03.Statement, physicalReaderPoint: ByteArray, now: Long): IntervalKeys {
        require(now >= comparisonMs && statement.account.let { same(ReviewedIntent03.uuid(it), account) } &&
            statement.vaultGeneration == generation && statement.manifestVersion == version && same(statement.manifestDigest, semanticDigest))
        statement.requireIntervalCurrent(now)
        window(issued, expires, now)
        require(statement.intervalExpiresMs <= expires)
        fun key(role: Int, id: ByteArray): Key {
            val record = records.singleOrNull { it.role == role && same(it.id, id) }
            require(record != null && record.active(now) && record.active(statement.issuedMs) &&
                statement.intervalExpiresMs <= record.until) { "Conversation selected role/lifetime" }
            return record
        }
        val device = ReviewedIntent03.uuid(statement.device); val line = ReviewedIntent03.uuid(statement.line)
        val reader = key(1, statement.readerKeyId)
        require(reader.scope == 4 && same(reader.device, device) && same(reader.line, line) && same(reader.point, physicalReaderPoint))
        require(key(2, statement.archiveReaderKeyId).scope == 12)
        val phone = key(4, statement.phoneSignerKeyId)
        val browser = key(5, statement.browserSignerKeyId)
        require(phone.scope == 2 && same(phone.device, device) && same(phone.line, line) && browser.scope == 1 && same(browser.line, line))
        val integrations = statement.integrations().associate { mapping ->
            val selected = key(3, mapping.keyId()); require(selected.scope == 12)
            Draft02OutboundPreparation.hex(mapping.keyId()) to selected.point
        }
        return IntervalKeys(phone.point, browser.point, integrations)
    }

    /** Independently selected routing and readers; never inferred as permission from ciphertext. */
    class Request(accountId: ByteArray, messageId: ByteArray, deviceId: ByteArray, lineId: ByteArray,
                  peer: ByteArray, signerKeyId: ByteArray, readers: List<Reader>) {
        private val account = exactCopy(accountId, 16)
        private val message = exactCopy(messageId, 16)
        private val device = exactCopy(deviceId, 16)
        private val line = exactCopy(lineId, 16)
        private val peerValue = peer.also { require(it.size in 3..16) }.copyOf()
        private val signer = exactCopy(signerKeyId, 32)
        private val selected = ArrayList<Reader>().apply {
            val count = readers.size
            require(count in 2..8) { "Reader count" }
            for (index in 0 until count) {
                val reader = readers[index]
                add(Reader(reader.role, reader.keyId))
            }
        }
        internal fun account() = account.copyOf()
        internal fun message() = message.copyOf()
        internal fun device() = device.copyOf()
        internal fun line() = line.copyOf()
        internal fun peer() = peerValue.copyOf()
        internal fun signer() = signer.copyOf()
        internal fun readers() = selected.toList()
        init {
            require(listOf(account, message, device, line).all { it.size == 16 && !zero(it) } && signer.size == 32)
            require(peerValue.size in 3..16 && peerValue[0] == 43.toByte() && peerValue[1] in 49.toByte()..57.toByte() &&
                peerValue.copyOfRange(2, peerValue.size).all { it in 48.toByte()..57.toByte() }) { "Peer shape" }
        }
    }

    class Context internal constructor(val request: Request, val version: Long, digest: ByteArray,
                                       signer: ByteArray, val notAfterMs: Long, val authorityExpiresAtMs: Long) {
        private val identity = digest.copyOf()
        private val signingPoint = signer.copyOf()
        val manifestDigest get() = identity.copyOf()
        val signerPoint get() = signingPoint.copyOf()
        override fun toString() = "Draft03OutboundPublicContext"
    }

    /** Rechecks fresh public roles, including the complete requested message deadline. */
    fun context(request: Request, nowMs: Long, notAfterMs: Long = nowMs): Context {
        require(nowMs >= comparisonMs && notAfterMs >= nowMs) { "Comparison regression/deadline" }
        window(issued, expires, nowMs)
        require(notAfterMs <= expires && same(request.account(), account)) { "Manifest deadline/account" }
        val signer = records.singleOrNull { it.role == 5 && same(it.id, request.signer()) }
        require(signer != null && signer.active(nowMs) && signer.scope == 1 &&
            same(signer.line, request.line()) && notAfterMs <= signer.until) { "Signer authority" }
        var authorityExpiresAtMs = minOf(expires, signer.until)
        var prior: Reader? = null
        var devices = 0
        var archives = 0
        var integrations = 0
        for (reader in request.readers()) {
            prior?.let { require(reader.role > it.role || reader.role == it.role && compare(reader.keyId, it.keyId) > 0) }
            prior = reader
            val key = records.singleOrNull { it.role == reader.role && same(it.id, reader.keyId) }
            require(key != null && key.active(nowMs) && key.scope and 4 != 0 && notAfterMs <= key.until) { "Reader authority" }
            authorityExpiresAtMs = minOf(authorityExpiresAtMs, key.until)
            when (reader.role) {
                1 -> { require(same(key.device, request.device()) && same(key.line, request.line())); devices++ }
                2 -> archives++
                3 -> integrations++
                else -> throw IllegalArgumentException("Reader role")
            }
        }
        require(devices == 1 && archives == 1 && integrations <= 6) { "Reader set" }
        return Context(request, version, semanticDigest, signer.point, notAfterMs, authorityExpiresAtMs)
    }

    fun readerPoint(context: Context, reader: Reader, nowMs: Long): ByteArray {
        require(context.version == version && same(context.manifestDigest, semanticDigest))
        val checked = this.context(context.request, nowMs, context.notAfterMs)
        require(checked.request.readers().any { it.role == reader.role && same(it.keyId, reader.keyId) })
        return records.single { it.role == reader.role && same(it.id, reader.keyId) }.point.copyOf()
    }

    /** A signed review may not predate any selected outbound key, even if all keys are active now.
     * This supplements current authorization without treating the historical observation as now.
     */
    fun reviewedContext(request: Request, observedMs: Long, nowMs: Long, notAfterMs: Long): Context {
        require(observedMs > 0 && observedMs <= nowMs)
        val checked = context(request, nowMs, notAfterMs)
        val selected = request.readers().map { it.role to it.keyId } + (5 to request.signer())
        for ((role, id) in selected) {
            val key = records.single { it.role == role && same(it.id, id) }
            require(observedMs >= key.from && observedMs < key.until) { "Review predates selected key" }
        }
        return checked
    }

    private class Key(val role: Int, val id: ByteArray, val point: ByteArray, val device: ByteArray,
                      val line: ByteArray, val scope: Int, val from: Long, val until: Long, val state: Int) {
        fun active(now: Long) = state == 1 && from <= now && now < until
    }

    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        /** Expired02 can prove HISTORY at its authenticated original time, never present permission.
         * Unlike SDK/Rust fresh02 entry points, this requires an independent original checkpoint. */
        fun verifyFrom02(input: ByteArray, retainedSigned02: ByteArray, checkpoint: Accepted02Checkpoint,
                         comparisonMs: Long): Draft03ManifestAuthority {
            val bytes = capture(input)
            require(retainedSigned02.size in 364..9751)
            val oldBytes = retainedSigned02.copyOf()
            require(comparisonMs >= checkpoint.verifiedAtMs && comparisonMs > 0) { "Comparison regression" }
            require(same(sha(oldBytes), checkpoint.evidence())) { "Original02 signed evidence" }
            val pin = checkpoint.pin()
            val trust = Draft02ManifestAuthority.Trust(checkpoint.account(), checkpoint.fingerprint(), 1,
                Draft02ManifestAuthority.Position.current(checkpoint.version, checkpoint.digest()))
            val old = Draft02ManifestAuthority.verify(pin, oldBytes, trust, checkpoint.verifiedAtMs)
            val value = parse(bytes, old.accountId, pin.copyOfRange(29, 94), checkpoint.anchor(), comparisonMs)
            require(checkpoint.version < Long.MAX_VALUE && value.version == checkpoint.version + 1 &&
                value.predecessorProfile == 2 && same(value.previous, old.digest)) { "Cross-profile successor" }
            return value
        }

        /** An expired prior03 instance is chain history; only the new successor must be fresh. */
        fun verifySuccessor(input: ByteArray, prior: Draft03ManifestAuthority, comparisonMs: Long): Draft03ManifestAuthority {
            val bytes = capture(input)
            require(comparisonMs >= prior.comparisonMs) { "Comparison regression" }
            val value = parse(bytes, prior.account, prior.root, prior.anchor, comparisonMs)
            require(prior.version < Long.MAX_VALUE && value.version == prior.version + 1 &&
                value.predecessorProfile == 3 && same(value.previous, prior.semanticDigest)) { "Manifest successor" }
            return value
        }

        /** Alternate valid signatures prove semantic identity, not exact store replay or replacement. */
        fun verifyCurrent(input: ByteArray, current: Draft03ManifestAuthority, comparisonMs: Long): Draft03ManifestAuthority {
            val bytes = capture(input)
            require(comparisonMs >= current.comparisonMs) { "Comparison regression" }
            val value = parse(bytes, current.account, current.root, current.anchor, comparisonMs)
            require(value.version == current.version && value.predecessorProfile == current.predecessorProfile &&
                same(value.semanticDigest, current.semanticDigest)) { "Current fork/rollback" }
            return value
        }

        private fun capture(input: ByteArray): ByteArray {
            require(input.size in 366..9753) { "Manifest size" }
            return input.copyOf()
        }
        private fun exactCopy(input: ByteArray, size: Int): ByteArray {
            require(input.size == size) { "Byte width" }
            return input.copyOf()
        }
        private fun parse(bytes: ByteArray, account: ByteArray, root: ByteArray, anchor: ByteArray,
                          now: Long): Draft03ManifestAuthority {
            require(same(bytes.copyOfRange(0, 6), byteArrayOf(0x5a, 0x54, 0x4d, 0x41, 3, 3))) { "Manifest profiles" }
            val predecessor = bytes[6].toInt() and 255
            require(predecessor == 2 || predecessor == 3) { "Unsupported predecessor/genesis" }
            val count = bytes[152].toInt() and 255
            require(count in 1..64 && bytes.size == 217 + 149 * count) { "Manifest exact size" }
            val version = u64(bytes, 31)
            val issued = u64(bytes, 39)
            val expires = u64(bytes, 47)
            require(version > 0 && u64(bytes, 23) == 1L && same(account, bytes.copyOfRange(7, 23)) &&
                same(root, bytes.copyOfRange(87, 152)) && zero(anchor)) { "Manifest identity/anchor" }
            window(issued, expires, now)
            DevicePayloadKeyStore.decodePoint(root)
            val records = ArrayList<Key>(count)
            val points = HashSet<List<Byte>>()
            var owners = 0
            var archives = 0
            repeat(count) { index ->
                val at = 153 + 149 * index
                val role = bytes[at].toInt() and 255
                val id = bytes.copyOfRange(at + 1, at + 33)
                val point = bytes.copyOfRange(at + 33, at + 98)
                val device = bytes.copyOfRange(at + 98, at + 114)
                val line = bytes.copyOfRange(at + 114, at + 130)
                val scope = ByteBuffer.wrap(bytes, at + 130, 2).short.toInt() and 65535
                val from = u64(bytes, at + 132)
                val until = u64(bytes, at + 140)
                val state = bytes[at + 148].toInt() and 255
                roleScope(role, scope, device, line)
                require(from <= until && state in 1..2) { "Key interval/state" }
                records.lastOrNull()?.let { require(role > it.role || role == it.role && compare(id, it.id) > 0) }
                DevicePayloadKeyStore.decodePoint(point)
                val algorithm = if (role <= 3) byteArrayOf(0, 0x10) else byteArrayOf(1, 1)
                require(same(sha(ascii("ZTSE/key/v1\u0000") + algorithm + point), id)) { "Key ID" }
                require(points.add(point.toList())) { "Point alias" }
                if (role == 6) {
                    owners++
                    require(same(point, root) && state == 1 && from <= issued && until >= expires) { "Owner root" }
                }
                if (role == 2 && state == 1) archives++
                records.add(Key(role, id, point, device, line, scope, from, until, state))
            }
            require(owners == 1 && archives == 1) { "Owner/archive cardinality" }
            val unsigned = bytes.copyOfRange(0, bytes.size - 64)
            val signature = bytes.copyOfRange(bytes.size - 64, bytes.size)
            require(signatureMatches(root, signature, unsigned)) { "Owner signature" }
            return Draft03ManifestAuthority(account.copyOf(), version, sha(unsigned), root.copyOf(), anchor.copyOf(),
                predecessor, bytes.copyOfRange(55, 87), issued, expires, now, records, bytes.copyOf())
        }

        private fun roleScope(role: Int, scope: Int, device: ByteArray, line: ByteArray) {
            require(role in 1..6) { "Key role" }
            require(if (role == 3) scope == 4 || scope == 8 || scope == 12 else scope == intArrayOf(0, 4, 12, 4, 2, 1, 0)[role])
            val deviceBound = role == 1 || role == 4
            require(if (deviceBound) !zero(device) else zero(device)) { "Key device" }
            require(if (deviceBound || role == 5) !zero(line) else zero(line)) { "Key line" }
        }
        private fun signatureMatches(root: ByteArray, raw: ByteArray, unsigned: ByteArray): Boolean {
            val r = BigInteger(1, raw.copyOfRange(0, 32))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            require(r.signum() > 0 && r < ORDER && s.signum() > 0 && s <= ORDER.shiftRight(1)) { "Noncanonical signature" }
            fun integer(value: BigInteger): ByteArray = value.toByteArray().let { byteArrayOf(2, it.size.toByte()) + it }
            val fields = integer(r) + integer(s)
            return Signature.getInstance("SHA256withECDSA").run {
                initVerify(DevicePayloadKeyStore.decodePoint(root))
                update(ascii("ZTSE/manifest/v3\u0000")); update(ByteBuffer.allocate(4).putInt(unsigned.size).array()); update(unsigned)
                verify(byteArrayOf(0x30, fields.size.toByte()) + fields)
            }
        }
        private fun window(issued: Long, expires: Long, now: Long) {
            require(now > 0 && issued > 0 && expires > issued && expires - issued <= 86_400_000 &&
                (issued <= now || issued - now <= 300_000) && now < expires) { "Manifest freshness" }
        }
        private fun u64(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it >= 0) }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun zero(value: ByteArray) = value.all { it == 0.toByte() }
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (index in a.indices) {
                val difference = (a[index].toInt() and 255) - (b[index].toInt() and 255)
                if (difference != 0) return difference
            }
            return 0
        }
    }
}
