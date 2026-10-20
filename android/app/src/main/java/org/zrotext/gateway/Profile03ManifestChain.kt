// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest

/** Streaming historical verification. Each advance touches at most eight retained originals;
 * a long lifetime chain resumes through further chunks, without a fixed lifetime cap. */
internal class Profile03ManifestChain(private val store: Profile03ManifestStore) {
    class Original(val electionId: String, val identity: String, val scope: Profile03ManifestSuccessor.Scope,
        val first: Profile03ManifestHistory.Checkpoint, evidence: Map<String, Any>) {
        private val evidence = canonicalEvidence(evidence)
        fun requireEvidence(candidate: Map<String, Any>) { require(same(evidence, canonicalEvidence(candidate))) }
        init { Profile03ClosedUnaccepted.uuid(electionId); require(identity.matches(Regex("[0-9a-f]{64}"))) }
        override fun toString() = "Manifest03Original(verified-history-only)"
    }
    class Saved internal constructor(val original: Original, val head: Profile03ManifestHead?, val checkpoint: Profile03ManifestHistory.Checkpoint) {
        override fun toString() = "Manifest03SavedHistory(no-live-acknowledgement)"
    }
    class Restoration internal constructor(val original: Original, val head: Profile03ManifestHead?,
        internal val manifest: ByteArray?, internal var cursor: Profile03ManifestHistory.Checkpoint) {
        internal var finished = false
        override fun toString() = "Manifest03Restoration(incomplete-history-only)"
    }
    fun begin(original: Original, now: () -> Long): Restoration {
        require(now() >= original.first.acceptedMs)
        val head = store.dao().head(original.electionId)
        val manifest = head?.let {
            require(it.originalIdentity == original.identity && it.originalVersion == original.first.authority.version && now() >= it.comparedMs)
            store.manifest(it)
        }
        now()
        return Restoration(original, head, manifest, original.first)
    }
    /** Null means verified partial progress only; no stored phase or checkpoint can issue Ready. */
    fun advance(restoration: Restoration, now: () -> Long): Saved? {
        check(!restoration.finished)
        val head = restoration.head
        fun unchanged() {
            now()
            val actual = store.dao().head(restoration.original.electionId)
            now()
            check(if (head == null) actual == null else actual?.same(head) == true)
        }
        unchanged()
        if (head != null && restoration.cursor.authority.version < head.version) {
            val rows = store.dao().entries(head.electionId, restoration.cursor.authority.version)
            require(rows.isNotEmpty() && rows.size <= 8)
            for (row in rows) {
                require(row.version <= head.version && row.electionId == head.electionId && row.priorAncestry == hex(restoration.cursor.ancestry()))
                val entry = store.entry(row)
                val authority = Profile03ManifestSuccessor.verify(entry, restoration.cursor.authority,
                    restoration.cursor.acceptedMs, restoration.original.scope, now())
                val prefix = Profile03ManifestSuccessor.step(restoration.cursor.ancestry(), entry)
                require(row.version == authority.version && row.ancestry == hex(prefix))
                restoration.cursor = Profile03ManifestHistory.Checkpoint(authority, entry.acceptedMs, prefix)
                now()
            }
        }
        unchanged()
        if (head != null && restoration.cursor.authority.version < head.version) return null
        head?.let {
            require(restoration.cursor.authority.version == it.version && hex(restoration.cursor.authority.digest) == it.digest &&
                hex(restoration.cursor.ancestry()) == it.ancestry && restoration.cursor.acceptedMs == it.acceptedMs &&
                same(restoration.cursor.authority.signedBytes, checkNotNull(restoration.manifest)) &&
                store.dao().entries(it.electionId, it.version).isEmpty())
        }
        unchanged(); restoration.finished = true
        return Saved(restoration.original, head, restoration.cursor)
    }
    /** The caller withdraws old effect lifetimes before entering this or waiting on any key. */
    fun append(previous: Saved, page: Profile03ManifestHistory, now: () -> Long, ramCurrent: () -> Unit): Saved {
        previous.original.requireEvidence(page.evidence())
        val checkpoint = page.verify(previous.checkpoint, previous.original.scope, now())
        val rows = ArrayList<Profile03ManifestEntryRecord>()
        var prefix = previous.checkpoint.ancestry()
        for (entry in page.entries()) {
            val next = Profile03ManifestSuccessor.step(prefix, entry)
            rows.add(store.entry(previous.original.electionId, prefix, next, entry)); prefix = next
            now()
        }
        val head = store.head(previous.original.electionId, previous.original.identity, previous.original.first.authority.version,
            checkpoint, page, if (page.complete) "prepared" else "progress")
        now(); ramCurrent()
        store.dao().append(previous.head, head, rows, ramCurrent)
        now()
        return Saved(previous.original, head, checkpoint)
    }
    companion object {
        fun canonicalEvidence(fields: Map<String, Any>): ByteArray {
            require(fields.keys == Profile03RetainedElection.EVIDENCE_KEYS)
            return Profile03Json.render(fields.toSortedMap())
        }
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun hex(b: ByteArray) = Draft02OutboundPreparation.hex(b)
    }
}
