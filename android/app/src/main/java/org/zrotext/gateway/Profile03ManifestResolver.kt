// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest

/** Explicit full-chain consumer. It never adapts a new kind into the first-only selection
 * grammar. The live readback handle is private to the actual current socket, not a Room phase. */
internal class Profile03ManifestResolver(private val runtime: () -> Profile03ManifestRuntime,
    private val store: Profile03ManifestStore, private val time: Profile03SessionTime) {
    class Authority(val authority: Draft03ManifestAuthority, val ramCurrent: () -> Unit,
        private val history: (Long, ByteArray, Long) -> Draft03ManifestAuthority) {
        fun historical(version: Long, digest: ByteArray, at: Long) = history(version, digest.copyOf(), at)
        override fun toString() = "Manifest03ResolvedPublicAuthority"
    }
    fun projection(fields: Map<String, Any>, evidence: Map<String, Any>, installation: Profile03ElectionRecord,
        original: Draft03ManifestAuthority): Authority {
        val resolved = current(evidence, installation, original)
        val h = runtime().currentInstalled().saved.head!!
        require(Profile03Json.decimal(fields, "manifest_version") == h.version &&
            hex(Profile03Json.binary(fields, "manifest_digest", 32, 32)) == h.digest &&
            hex(Profile03Json.binary(fields, "manifest_ancestry_sha256", 32, 32)) == h.ancestry &&
            same(Profile03Json.binary(fields, "current_manifest03", 366, 9753), resolved.authority.signedBytes))
        resolved.ramCurrent()
        return resolved
    }
    fun refresh(evidence: Map<String, Any>, original: Profile03RetainedElection.Verified,
        core: SelectionRefresh03.Core): Authority = current(evidence, original.installation, original.authority).also {
            require(it.authority.version == core.manifestVersion && same(it.authority.digest, core.manifestDigest))
            it.ramCurrent()
        }
    private fun current(evidence: Map<String, Any>, installation: Profile03ElectionRecord,
        original: Draft03ManifestAuthority): Authority {
        val held = runtime().currentInstalled(); held.requireRamCurrent()
        val saved = held.saved; val h = checkNotNull(saved.head)
        require(h.state == "installed" && h.electionId == installation.challengeId &&
            h.originalIdentity == hex(sha(checkNotNull(installation.acceptedEvidenceSha256).toByteArray(Charsets.US_ASCII) +
                Profile03ManifestChain.canonicalEvidence(evidence))) && same(original.signedBytes, saved.original.first.authority.signedBytes))
        fun ram() {
            held.requireRamCurrent()
            check(time.snapshot()?.first?.session === held.session)
            checkNotNull(time.nowMs()).also { check(it >= h.comparedMs) }
            held.requireRamCurrent()
        }
        ram()
        val manifest = store.manifest(h)
        check(store.dao().head(h.electionId)?.same(h) == true)
        ram()
        val authority = Draft03ManifestAuthority.verifyCurrent(manifest, saved.checkpoint.authority, checkNotNull(time.nowMs()))
        ram()
        return Authority(authority, ::ram) { version, digest, at ->
            ram()
            require(version in saved.original.first.authority.version..h.version && at <= checkNotNull(time.nowMs()))
            val originalVersion = version == saved.original.first.authority.version
            val row = if (originalVersion) null else checkNotNull(store.dao().entry(h.electionId, version))
            val signed = if (originalVersion) saved.original.first.authority.signedBytes else store.entry(checkNotNull(row)).successor()
            require(at >= (row?.acceptedMs ?: saved.original.first.acceptedMs))
            ram()
            Draft03ManifestAuthority.verifyHistorical(signed, authority, at).also {
                require(it.version == version && same(it.digest, digest)); ram()
            }
        }
    }
    companion object {
        private fun hex(b: ByteArray) = Draft02OutboundPreparation.hex(b)
        private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
