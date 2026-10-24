// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Exact additive ZTCI public commitment. Valid bytes/signatures are NOT an installed interval,
 * a genuine first-receipt ticket, protected sequence/sign reservation or upload permission. */
internal class CaptureIntent03 private constructor(private val wire: ByteArray,
    val identities: Identities, val times: Times, val commitments: Commitments,
    val peer: String, private val selected: List<Draft03ManifestAuthority.Reader>) {
    data class Identities(val account: UUID, val capture: UUID, val request: UUID,
        val interval: UUID, val intervalReceipt: UUID, val device: UUID, val line: UUID,
        val ownerUser: UUID, val ownerSession: UUID, val binding: UUID,
        val electionChallenge: UUID, val originalBinding: UUID, val physicalRefresh: UUID) {
        internal fun values() = listOf(account, capture, request, interval, intervalReceipt, device,
            line, ownerUser, ownerSession, binding, electionChallenge, originalBinding, physicalRefresh)
    }
    data class Times(val bindingGeneration: Long, val vaultGeneration: Long,
        val manifestVersion: Long, val selectionEpoch: Long, val connectionEpoch: Long,
        val deploymentEpoch: Long, val sequence: Long, val observedMs: Long, val observedUpperMs: Long,
        val permissionComparedMs: Long, val permissionExpiresMs: Long, val observedElapsedMs: Long,
        val preparedElapsedMs: Long, val intervalInstalledMs: Long) {
        internal fun values() = listOf(bindingGeneration, vaultGeneration, manifestVersion, selectionEpoch,
            connectionEpoch, deploymentEpoch, sequence, observedMs, observedUpperMs, permissionComparedMs,
            permissionExpiresMs, observedElapsedMs, preparedElapsedMs, intervalInstalledMs)
    }
    class Commitments(reader: ByteArray, archive: ByteArray, phoneSigner: ByteArray, root: ByteArray,
        manifest: ByteArray, ancestry: ByteArray, election: ByteArray, electionBundle: ByteArray,
        origin: ByteArray, ownerSession: ByteArray, deviceSession: ByteArray, physical: ByteArray,
        intervalStatement: ByteArray, ownerSignature: ByteArray, phoneSignature: ByteArray,
        installedSignature: ByteArray, envelope: ByteArray, unsignedEnvelope: ByteArray) {
        private val owned = listOf(reader, archive, phoneSigner, root, manifest, ancestry, election,
            electionBundle, origin, ownerSession, deviceSession, physical, intervalStatement,
            ownerSignature, phoneSignature, installedSignature, envelope, unsignedEnvelope).map {
                require(it.size == 32 && it.any { b -> b != 0.toByte() }); it.copyOf()
            }
        fun reader() = owned[0].copyOf()
        fun archive() = owned[1].copyOf()
        fun phoneSigner() = owned[2].copyOf()
        fun root() = owned[3].copyOf()
        fun manifest() = owned[4].copyOf()
        fun ancestry() = owned[5].copyOf()
        fun election() = owned[6].copyOf()
        fun electionBundle() = owned[7].copyOf()
        fun origin() = owned[8].copyOf()
        fun ownerSession() = owned[9].copyOf()
        fun deviceSession() = owned[10].copyOf()
        fun physical() = owned[11].copyOf()
        fun intervalStatement() = owned[12].copyOf()
        fun ownerSignature() = owned[13].copyOf()
        fun phoneSignature() = owned[14].copyOf()
        fun installedSignature() = owned[15].copyOf()
        fun envelope() = owned[16].copyOf()
        fun unsignedEnvelope() = owned[17].copyOf()
        internal fun values() = owned.map { it.copyOf() }
        override fun toString() = "CaptureIntent03Commitments(public-only)"
    }
    fun bytes() = wire.copyOf()
    fun sha256() = sha(wire)
    fun transcript() = ReviewedIntent03.framed("ZTSE/conversation/capture-intent03/v1", wire)
    fun recipients() = selected.map { Draft03ManifestAuthority.Reader(it.role, it.keyId) }

    fun requireSignature(signature: ByteArray, independentlySelectedRole04Point: ByteArray) {
        require(ConversationContentCrypto.verifyRaw(signature.copyOf(), independentlySelectedRole04Point.copyOf(), transcript()))
    }

    /** The caller's actual-now value is the conservative UPPER clock, never observedMs. */
    fun requireCurrent(upperNowMs: Long, elapsedNowMs: Long) {
        require(upperNowMs >= times.permissionComparedMs && upperNowMs < times.permissionExpiresMs)
        require(upperNowMs >= times.observedMs && upperNowMs - times.observedMs <= MAX_AGE_MS)
        require(elapsedNowMs >= times.preparedElapsedMs && elapsedNowMs - times.observedElapsedMs <= MAX_AGE_MS)
    }

    /** Select routing/current public manifest independently. This checks exact ciphertext
     * linkage only; the caller must separately prove the current installed consent/custody. */
    fun requireEnvelope(envelope: ByteArray, authority: Draft03ManifestAuthority,
        independentlySelectedRequest: Draft03ManifestAuthority.InboundRequest,
        upperNowMs: Long): Draft03InboundEnvelope.Unsigned {
        require(authority.version == times.manifestVersion && same(authority.digest, commitments.manifest()) &&
            same(authority.accountId, ReviewedIntent03.uuid(identities.account)))
        val r = independentlySelectedRequest
        require(same(r.account(), ReviewedIntent03.uuid(identities.account)) &&
            same(r.event(), ReviewedIntent03.uuid(identities.capture)) &&
            same(r.device(), ReviewedIntent03.uuid(identities.device)) &&
            same(r.line(), ReviewedIntent03.uuid(identities.line)) &&
            same(r.signer(), commitments.phoneSigner()) && same(r.peer(), peer.toByteArray(Charsets.US_ASCII)))
        val readers = r.readers()
        require(readers.size == selected.size && readers.zip(selected).all { (a, b) -> a.role == b.role && same(a.keyId, b.keyId) })
        val proof = Draft03InboundEnvelope.verify(envelope, authority, r, times.observedMs,
            times.sequence, upperNowMs, times.permissionExpiresMs)
        require(same(sha(envelope), commitments.envelope()) && same(proof.sha256(), commitments.unsignedEnvelope()))
        return proof
    }
    override fun toString() = "CaptureIntent03(public-proof-only)"

    companion object {
        const val MIN_BYTES = 942
        const val MAX_BYTES = 1153
        const val MAX_AGE_MS = 60_000L
        const val MAX_PERMISSION_MS = 30_000L
        const val MAX_UNCERTAINTY_MS = 2_000L
        private val header = byteArrayOf(90, 84, 67, 73, 1, 3, 3, 2)

        fun encode(identities: Identities, times: Times, commitments: Commitments,
            peer: String, recipients: List<Draft03ManifestAuthority.Reader>): CaptureIntent03 {
            require(peer.length in 3..16 && peer.matches(Regex("\\+[1-9][0-9]{1,14}")) && recipients.size in 1..7)
            val p = peer.toByteArray(Charsets.US_ASCII)
            val readers = recipients.map { Draft03ManifestAuthority.Reader(it.role, it.keyId) }
            val out = ByteBuffer.allocate(904 + 1 + p.size + 1 + readers.size * 33)
            out.put(header)
            identities.values().forEach { out.putLong(it.mostSignificantBits).putLong(it.leastSignificantBits) }
            times.values().forEach { out.putLong(it) }
            commitments.values().forEach { out.put(it) }
            out.put(p.size.toByte()).put(p).put(readers.size.toByte())
            readers.forEach { out.put(it.role.toByte()).put(it.keyId) }
            return decode(out.array())
        }

        fun decode(source: ByteArray): CaptureIntent03 {
            require(source.size in MIN_BYTES..MAX_BYTES)
            val wire = source.copyOf(); val b = ByteBuffer.wrap(wire)
            require(ByteArray(8).also(b::get).contentEquals(header))
            val ids = List(13) { UUID(b.long, b.long) }
            require(ids.take(12).all { it != UUID(0, 0) } && ids[1] != ids[2])
            val n = List(14) { b.long }
            require(n.withIndex().all { (i, value) -> if (i in 11..12) value >= 0 else value > 0 })
            require(n[1] == 1L && n[3] == 1L)
            val t = Times(n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], n[10], n[11], n[12], n[13])
            require(t.observedUpperMs >= t.observedMs && t.observedUpperMs - t.observedMs <= MAX_UNCERTAINTY_MS &&
                t.observedMs >= t.intervalInstalledMs && t.permissionComparedMs >= t.observedMs &&
                (t.observedUpperMs <= t.permissionComparedMs || t.observedUpperMs - t.permissionComparedMs <= MAX_UNCERTAINTY_MS) &&
                t.permissionExpiresMs > t.permissionComparedMs && t.permissionExpiresMs - t.permissionComparedMs <= MAX_PERMISSION_MS &&
                t.permissionExpiresMs - t.observedMs <= MAX_AGE_MS &&
                t.preparedElapsedMs >= t.observedElapsedMs && t.preparedElapsedMs - t.observedElapsedMs <= MAX_AGE_MS)
            val d = List(18) { ByteArray(32).also(b::get) }
            val c = Commitments(d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17])
            val size = b.get().toInt() and 255
            require(size in 3..16 && b.remaining() >= size + 34)
            val rawPeer = ByteArray(size).also(b::get)
            require(rawPeer[0] == 43.toByte() && rawPeer[1] in 49.toByte()..57.toByte() &&
                rawPeer.drop(2).all { it in 48.toByte()..57.toByte() })
            val count = b.get().toInt() and 255
            require(count in 1..7 && b.remaining() == count * 33)
            val readers = List(count) {
                val role = b.get().toInt() and 255
                val key = ByteArray(32).also(b::get)
                require(role in 2..3 && key.any { it != 0.toByte() })
                Draft03ManifestAuthority.Reader(role, key)
            }
            require(readers.count { it.role == 2 } == 1 && same(readers.first { it.role == 2 }.keyId, c.archive()) &&
                readers.zipWithNext().all { (a, next) -> a.role < next.role || a.role == next.role && compare(a.keyId, next.keyId) < 0 })
            val i = Identities(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], ids[8], ids[9], ids[10], ids[11], ids[12])
            return CaptureIntent03(wire, i, t, c, rawPeer.toString(Charsets.US_ASCII), readers)
        }
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (i in a.indices) { val delta = (a[i].toInt() and 255) - (b[i].toInt() and 255); if (delta != 0) return delta }
            return 0
        }
    }
}
