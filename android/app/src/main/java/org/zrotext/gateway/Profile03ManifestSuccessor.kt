// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Public cryptographic history only. A root signature or possession proof cannot establish
 * server acceptance, an authenticated owner/factor, a current physical lease or message consent. */
internal object Profile03ManifestSuccessor {
    class Statement private constructor(private val owned: ByteArray) {
        fun bytes() = owned.copyOf()
        private fun id(at: Int) = uuid(owned.copyOfRange(at, at + 16))
        private fun digest(at: Int) = owned.copyOfRange(at, at + 32)
        private fun number(at: Int) = ByteBuffer.wrap(owned, at, 8).long
        val account get() = id(8)
        val user get() = id(24)
        val ownerSession get() = id(40)
        val device get() = id(56)
        val line get() = id(72)
        val binding get() = id(88)
        val election get() = id(104)
        val opening get() = id(120)
        val bindingGeneration get() = number(136)
        val vaultGeneration get() = number(144)
        val selectionEpoch get() = number(152)
        val predecessorVersion get() = number(160)
        val successorVersion get() = number(168)
        val issuedMs get() = number(176)
        val expiresMs get() = number(184)
        val rootFingerprint get() = digest(192)
        val electionDigest get() = digest(224)
        val bundleDigest get() = digest(256)
        val originDigest get() = digest(288)
        val ownerSessionDigest get() = digest(320)
        val predecessorDigest get() = digest(352)
        val successorSha256 get() = digest(384)
        val browserKeyId get() = digest(416)
        val browserPoint get() = owned.copyOfRange(448, 513)
        fun transcript() = ReviewedIntent03.framed("ZTSE/line/payload-profile/manifest-install03/v1", owned)
        override fun toString() = "Profile03ManifestPossession(public-candidate)"
        companion object {
            fun decode(bytes: ByteArray): Statement {
                require(bytes.size == 513 && bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 77, 83, 1, 3, 3, 0)))
                val s = Statement(bytes.copyOf())
                for (at in 8 until 136 step 16) require(s.id(at) != UUID(0, 0))
                for (at in 136 until 192 step 8) require(s.number(at) > 0)
                for (at in 192 until 448 step 32) require(s.digest(at).any { it != 0.toByte() })
                require(s.vaultGeneration == 1L && s.selectionEpoch == 1L && s.predecessorVersion < Long.MAX_VALUE &&
                    s.successorVersion == s.predecessorVersion + 1 && s.expiresMs > s.issuedMs &&
                    s.expiresMs - s.issuedMs <= 300_000 && s.opening != s.binding && s.opening != s.election)
                DevicePayloadKeyStore.decodePoint(s.browserPoint)
                require(same(s.browserKeyId, Profile03RetainedElection.signingId(s.browserPoint)) &&
                    same(s.ownerSessionDigest, sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
                        ReviewedIntent03.uuid(s.account) + ReviewedIntent03.uuid(s.user) + ReviewedIntent03.uuid(s.ownerSession)))))
                return s
            }
        }
    }

    class Entry(val statement: Statement, signature: ByteArray, successor: ByteArray, val acceptedMs: Long) {
        private val proof = signature.copyOf(); private val manifest = successor.copyOf()
        init { require(acceptedMs > 0 && manifest.size in 366..9753); ConversationInterval03.requireRaw(proof) }
        fun signature() = proof.copyOf()
        fun successor() = manifest.copyOf()
        override fun toString() = "Profile03ManifestEntry(historical-candidate)"
    }

    /** Independently selected immutable original context; not an authenticated transport token. */
    class Scope(val account: UUID, val device: UUID, val line: UUID, val binding: UUID, val election: UUID,
        val bindingGeneration: Long, root: ByteArray, electionDigest: ByteArray, bundleDigest: ByteArray,
        originDigest: ByteArray, forbiddenSigningPoints: List<ByteArray>) {
        private val root = exact(root); private val electionDigest = exact(electionDigest)
        private val bundleDigest = exact(bundleDigest); private val originDigest = exact(originDigest)
        private val forbidden = forbiddenSigningPoints.map { it.copyOf().also { p -> DevicePayloadKeyStore.decodePoint(p) } }
        init { require(listOf(account, device, line, binding, election).all { it != UUID(0, 0) } && bindingGeneration > 0) }
        fun requireStatement(s: Statement) {
            require(s.account == account && s.device == device && s.line == line && s.binding == binding &&
                s.election == election && s.bindingGeneration == bindingGeneration && same(s.rootFingerprint, root) &&
                same(s.electionDigest, electionDigest) && same(s.bundleDigest, bundleDigest) && same(s.originDigest, originDigest) &&
                forbidden.none { same(it, s.browserPoint) })
        }
        fun requireHistory(fields: Map<String, Any>) {
            fun id(name: String) = Profile03ClosedUnaccepted.uuid(Profile03Json.text(fields, name))
            require(id("account_id") == account.toString() && id("device_id") == device.toString() && id("line_id") == line.toString() &&
                id("binding_id") == binding.toString() && Profile03Json.decimal(fields, "binding_generation") == bindingGeneration &&
                Profile03Json.decimal(fields, "selection_epoch") == 1L && same(Profile03Json.binary(fields, "root_fingerprint", 32, 32), root) &&
                same(Profile03Json.binary(fields, "election_digest", 32, 32), electionDigest) &&
                same(Profile03Json.binary(fields, "election_bundle_sha256", 32, 32), bundleDigest))
        }
        fun base(first: Draft03ManifestAuthority, acceptedMs: Long) = sha(ReviewedIntent03.framed(
            "ZTSE/line/payload-profile/manifest-ancestry-base03/v1", ReviewedIntent03.uuid(account) +
                ReviewedIntent03.uuid(election) + ReviewedIntent03.uuid(binding) + sha(first.signedBytes) +
                ByteBuffer.allocate(8).putLong(acceptedMs).array() + bundleDigest))
    }

    fun verify(entry: Entry, prior: Draft03ManifestAuthority, priorAcceptedMs: Long, scope: Scope,
        actualNow: Long): Draft03ManifestAuthority {
        val s = entry.statement; scope.requireStatement(s)
        require(priorAcceptedMs > 0 && entry.acceptedMs in s.issuedMs until s.expiresMs &&
            entry.acceptedMs >= priorAcceptedMs && entry.acceptedMs <= actualNow && s.predecessorVersion == prior.version &&
            same(s.predecessorDigest, prior.digest) && same(s.successorSha256, sha(entry.successor())))
        require(ConversationContentCrypto.verifyRaw(entry.signature(), s.browserPoint, s.transcript()))
        val next = Draft03ManifestAuthority.verifySuccessor(entry.successor(), prior, entry.acceptedMs)
        require(next.version == s.successorVersion && number(next.signedBytes, 39) <= entry.acceptedMs)
        requirePolicy(prior.signedBytes, next.signedBytes, s.line, s.browserPoint, s.browserKeyId, entry.acceptedMs)
        val physical = records(next.signedBytes).filter { it[0].toInt() == 1 &&
            same(it.copyOfRange(98, 114), ReviewedIntent03.uuid(scope.device)) &&
            same(it.copyOfRange(114, 130), ReviewedIntent03.uuid(scope.line)) && it[148].toInt() == 1 }
        require(physical.size == 1 && number(physical.single(), 132) <= entry.acceptedMs && entry.acceptedMs < number(physical.single(), 140))
        return next
    }

    fun step(prior: ByteArray, entry: Entry): ByteArray {
        exact(prior)
        return sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/manifest-ancestry-step03/v1", prior +
            ReviewedIntent03.uuid(entry.statement.opening) + sha(entry.statement.bytes()) + sha(entry.signature()) +
            sha(entry.successor()) + ByteBuffer.allocate(8).putLong(entry.acceptedMs).array()))
    }

    /** Same narrow policy as the public root-custody verifier: only selected role5 enrollment,
     * renewal or explicit replacement; all original unrelated authority is retained byte-exact. */
    private fun requirePolicy(old: ByteArray, next: ByteArray, line: UUID, point: ByteArray, key: ByteArray, at: Long) {
        val prior = records(old); val fresh = records(next); val lineBytes = ReviewedIntent03.uuid(line)
        fun isSelected(r: ByteArray) = r[0].toInt() == 5 && same(r.copyOfRange(114, 130), lineBytes) && r[148].toInt() == 1
        fun identity(r: ByteArray) = r.copyOfRange(0, 33)
        val selected = prior.filter(::isSelected); require(selected.size <= 1)
        val additions = fresh.filter { row -> prior.none { same(identity(it), identity(row)) } }
        val oldSigner = selected.singleOrNull()
        val replace = when {
            oldSigner == null && additions.size == 1 -> false
            oldSigner != null && additions.isEmpty() && same(oldSigner.copyOfRange(1, 33), key) && same(oldSigner.copyOfRange(33, 98), point) -> false
            oldSigner != null && additions.size == 1 && !same(oldSigner.copyOfRange(1, 33), key) && !same(oldSigner.copyOfRange(33, 98), point) -> true
            else -> error("Manifest browser enrollment shape")
        }
        require(fresh.size == prior.size + additions.size)
        val expires = number(next, 47)
        for (original in prior) {
            val row = fresh.single { same(identity(it), identity(original)) }
            when {
                replace && isSelected(original) -> require(same(row.copyOfRange(0, 148), original.copyOfRange(0, 148)) && row[148].toInt() == 2)
                original[148].toInt() != 1 -> require(same(row, original))
                else -> require(same(row.copyOfRange(0, 140), original.copyOfRange(0, 140)) && row[148] == original[148] &&
                    number(row, 140) >= number(original, 140) && number(row, 140) <= expires)
            }
        }
        val signer = fresh.filter(::isSelected).single()
        require(same(signer.copyOfRange(1, 33), key) && same(signer.copyOfRange(33, 98), point) &&
            signer.copyOfRange(98, 114).all { it == 0.toByte() } && signer[130] == 0.toByte() && signer[131] == 1.toByte() &&
            number(signer, 132) <= at && at < number(signer, 140) && number(signer, 140) <= expires)
        additions.singleOrNull()?.let { require(same(it, signer) && number(signer, 132) >= number(next, 39)) }
    }
    private fun records(signed: ByteArray): List<ByteArray> {
        require(signed.size in 366..9753 && signed.size == 217 + 149 * (signed[152].toInt() and 255))
        return (153 until signed.size - 64 step 149).map { signed.copyOfRange(it, it + 149) }
    }
    private fun number(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it >= 0) }
    private fun uuid(bytes: ByteArray) = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }
    private fun exact(bytes: ByteArray) = bytes.copyOf().also { require(it.size == 32 && it.any { b -> b != 0.toByte() }) }
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
