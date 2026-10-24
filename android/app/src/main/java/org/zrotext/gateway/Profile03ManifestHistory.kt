// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest

/** Fixed-tip public history page. All fields are untrusted candidates until original local
 * evidence, every historical signature/policy/checkpoint and the exact prefix are verified. */
internal class Profile03ManifestHistory private constructor(private val fields: Map<String, Any>,
    private val ownedEntries: List<Profile03ManifestSuccessor.Entry>) {
    val afterVersion get() = number("after_version")
    val afterDigest get() = digest("after_digest")
    val afterAncestry get() = digest("after_ancestry_sha256")
    val tipVersion get() = number("tip_version")
    val tipDigest get() = digest("tip_digest")
    val tipAncestry get() = digest("tip_ancestry_sha256")
    val tipAcceptedMs get() = number("tip_accepted_ms")
    val comparedMs get() = number("compared_ms")
    val nextVersion get() = number("next_version")
    val nextDigest get() = digest("next_digest")
    val nextAncestry get() = digest("next_ancestry_sha256")
    val complete get() = fields["complete"] as Boolean
    fun evidence() = Profile03Json.nested(fields, "evidence")
    fun entries() = ownedEntries.toList()
    fun bytes() = Profile03ManifestJson.render(fields)
    fun requireScope(scope: Profile03ManifestSuccessor.Scope) = scope.requireHistory(fields)
    private fun number(name: String) = Profile03Json.decimal(fields, name)
    private fun digest(name: String) = Profile03Json.binary(fields, name, 32, 32)
    class Checkpoint(val authority: Draft03ManifestAuthority, val acceptedMs: Long, ancestry: ByteArray) {
        private val prefix = ancestry.copyOf()
        init { require(acceptedMs > 0 && prefix.size == 32 && prefix.any { it != 0.toByte() }) }
        fun ancestry() = prefix.copyOf()
        override fun toString() = "Manifest03VerifiedHistoricalCheckpoint"
    }
    /** Each page may extend durable HISTORY. Even complete=true produces no current handle. */
    fun verify(after: Checkpoint, scope: Profile03ManifestSuccessor.Scope, actualNow: Long): Checkpoint {
        requireScope(scope)
        require(actualNow >= comparedMs && comparedMs >= tipAcceptedMs && tipAcceptedMs >= after.acceptedMs &&
            afterVersion == after.authority.version && same(afterDigest, after.authority.digest) && same(afterAncestry, after.ancestry()))
        require(tipVersion >= afterVersion && nextVersion in afterVersion..tipVersion)
        var current = after
        for (entry in ownedEntries) {
            val next = Profile03ManifestSuccessor.verify(entry, current.authority, current.acceptedMs, scope, actualNow)
            current = Checkpoint(next, entry.acceptedMs, Profile03ManifestSuccessor.step(current.ancestry(), entry))
        }
        require(current.authority.version == nextVersion && same(current.authority.digest, nextDigest) && same(current.ancestry(), nextAncestry))
        val atTip = nextVersion == tipVersion && same(nextDigest, tipDigest) && same(nextAncestry, tipAncestry)
        require(complete == atTip && (complete || nextVersion > afterVersion))
        if (complete) require(current.acceptedMs == tipAcceptedMs)
        else require(current.acceptedMs <= tipAcceptedMs)
        return current
    }
    override fun toString() = "Manifest03History(unverified-public-page)"
    companion object {
        private val KEYS = setOf("v", "kind", "account_id", "device_id", "line_id", "binding_id", "binding_generation", "selection_epoch",
            "election_digest", "election_bundle_sha256", "root_fingerprint", "after_version", "after_digest", "after_ancestry_sha256",
            "tip_version", "tip_digest", "tip_ancestry_sha256", "tip_accepted_ms", "compared_ms", "entries", "next_version", "next_digest",
            "next_ancestry_sha256", "complete", "evidence")
        fun decode(input: Map<String, Any>): Profile03ManifestHistory {
            val fields = Profile03ManifestJson.objectValue(Profile03ManifestJson.render(input))
            require(fields.keys == KEYS && fields["v"] == Profile03Json.Integer(1) && fields["kind"] == "manifest_ancestry03" && fields["complete"] is Boolean)
            val values = fields["entries"] as? List<*> ?: error("Manifest entries required")
            require(values.size <= 8)
            var total = 0
            val entries = values.map { raw ->
                val entry = (raw as? Map<*, *>)?.entries?.associate { (key, value) -> (key as String) to checkNotNull(value) }
                    ?: error("Manifest entry object required")
                require(entry.keys == setOf("opening_id", "statement", "signature", "successor_manifest03", "accepted_ms"))
                val s = Profile03ManifestSuccessor.Statement.decode(Profile03Json.binary(entry, "statement", 513, 513))
                require(Profile03ClosedUnaccepted.uuid(Profile03Json.text(entry, "opening_id")) == s.opening.toString())
                val signature = Profile03Json.binary(entry, "signature", 64, 64)
                val successor = Profile03Json.binary(entry, "successor_manifest03", 366, 9753)
                total += 513 + 64 + successor.size; require(total <= 65_536)
                Profile03ManifestSuccessor.Entry(s, signature, successor, Profile03Json.decimal(entry, "accepted_ms"))
            }
            require(Profile03Json.nested(fields, "evidence").keys == Profile03RetainedElection.EVIDENCE_KEYS)
            return Profile03ManifestHistory(fields.toMap(), entries).also { page ->
                for (name in listOf("after_version", "tip_version", "tip_accepted_ms", "compared_ms", "next_version")) page.number(name)
                for (name in listOf("after_digest", "after_ancestry_sha256", "tip_digest", "tip_ancestry_sha256", "next_digest", "next_ancestry_sha256"))
                    require(page.digest(name).any { it != 0.toByte() })
            }
        }
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
