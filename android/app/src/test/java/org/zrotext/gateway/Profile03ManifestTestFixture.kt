// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Genuine ephemeral P256 root/role5 and full original-proof component fixture. No Android
 * nonexportable custody, authenticated network, physical permission or hosted acceptance claim. */
internal class Profile03ManifestTestFixture : AutoCloseable {
    val original = Profile03RetainedElectionTest.Fixture(distinctEventSigner = true)
    val f = original.f
    val verified = original.verify()
    val scope = Profile03ManifestSuccessor.Scope(f.line.account, f.line.device, f.line.line, f.newBinding, f.challenge, 2,
        f.fingerprint, original.accepted.electionCommitment, original.accepted.electionBundleSha256,
        f.origins.protocolDigest(), listOf(original.devicePoint, original.ownerPoint))
    val base = Profile03ManifestHistory.Checkpoint(verified.authority, original.accepted.acceptedAtMs,
        scope.base(verified.authority, original.accepted.acceptedAtMs))
    val identity = Draft02OutboundPreparation.hex(Profile03ExecutionFixture.sha(checkNotNull(original.installed.acceptedEvidenceSha256).toByteArray(Charsets.US_ASCII) +
        Profile03ManifestChain.canonicalEvidence(original.evidence)))
    val selected = Profile03ManifestChain.Original(f.challenge.toString(), identity, scope, base, original.evidence)
    fun entries(count: Int): List<Profile03ManifestSuccessor.Entry> {
        var prior = base.authority
        return (1..count).map { step ->
            val issued = 100_020L + 5 * step
            val unsigned = prior.signedBytes.copyOf(prior.signedBytes.size - 64).apply {
                this[6] = 3; ByteBuffer.wrap(this).putLong(31, prior.version + 1).putLong(39, issued)
                prior.digest.copyInto(this, 55)
            }
            val manifest = unsigned + Profile03ExecutionFixture.rawSign(f.root, ReviewedIntent03.framed("ZTSE/manifest/v3", unsigned))
            val opening = UUID(0, 1000L + step)
            val bytes = ByteBuffer.allocate(513).put(byteArrayOf(90, 84, 77, 83, 1, 3, 3, 0))
                .put(f.account).put(ReviewedIntent03.uuid(f.ownerUser)).put(ReviewedIntent03.uuid(f.ownerSession)).put(f.device).put(f.lineId)
                .put(ReviewedIntent03.uuid(f.newBinding)).put(ReviewedIntent03.uuid(f.challenge)).put(ReviewedIntent03.uuid(opening))
                .putLong(2).putLong(1).putLong(1).putLong(prior.version).putLong(prior.version + 1).putLong(issued).putLong(issued + 300_000)
                .put(f.fingerprint).put(original.accepted.electionCommitment).put(original.accepted.electionBundleSha256)
                .put(f.origins.protocolDigest())
                .put(Profile03ExecutionFixture.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1", f.account +
                    ReviewedIntent03.uuid(f.ownerUser) + ReviewedIntent03.uuid(f.ownerSession))))
                .put(prior.digest).put(Profile03ExecutionFixture.sha(manifest)).put(Profile03ExecutionFixture.keyId(f.signer, true))
                .put(Profile03ExecutionFixture.point(f.signer)).array()
            val statement = Profile03ManifestSuccessor.Statement.decode(bytes)
            Profile03ManifestSuccessor.Entry(statement, Profile03ExecutionFixture.rawSign(f.signer, statement.transcript()), manifest, issued + 1)
                .also { prior = Profile03ManifestSuccessor.verify(it, prior, if (step == 1) base.acceptedMs else issued - 4, scope, 800_000) }
        }
    }
    fun checkpoint(entries: List<Profile03ManifestSuccessor.Entry>): Profile03ManifestHistory.Checkpoint {
        var value = base
        for (entry in entries) value = Profile03ManifestHistory.Checkpoint(Profile03ManifestSuccessor.verify(entry, value.authority,
            value.acceptedMs, scope, 800_000), entry.acceptedMs, Profile03ManifestSuccessor.step(value.ancestry(), entry))
        return value
    }
    fun page(after: Profile03ManifestHistory.Checkpoint, entries: List<Profile03ManifestSuccessor.Entry>,
        tip: Profile03ManifestHistory.Checkpoint, comparedMs: Long = 800_000): Profile03ManifestHistory {
        var next = after
        for (entry in entries) next = Profile03ManifestHistory.Checkpoint(Profile03ManifestSuccessor.verify(entry, next.authority,
            next.acceptedMs, scope, 800_000), entry.acceptedMs, Profile03ManifestSuccessor.step(next.ancestry(), entry))
        val json = JSONObject().put("v", 1).put("kind", "manifest_ancestry03").put("account_id", f.line.account).put("device_id", f.line.device)
            .put("line_id", f.line.line).put("binding_id", f.newBinding).put("binding_generation", "2").put("selection_epoch", "1")
            .put("election_digest", b64(original.accepted.electionCommitment)).put("election_bundle_sha256", b64(original.accepted.electionBundleSha256))
            .put("root_fingerprint", b64(f.fingerprint)).put("after_version", after.authority.version.toString()).put("after_digest", b64(after.authority.digest))
            .put("after_ancestry_sha256", b64(after.ancestry())).put("tip_version", tip.authority.version.toString()).put("tip_digest", b64(tip.authority.digest))
            .put("tip_ancestry_sha256", b64(tip.ancestry())).put("tip_accepted_ms", tip.acceptedMs.toString()).put("compared_ms", comparedMs.toString())
            .put("entries", JSONArray(entries.map { e -> JSONObject().put("opening_id", e.statement.opening).put("statement", b64(e.statement.bytes()))
                .put("signature", b64(e.signature())).put("successor_manifest03", b64(e.successor())).put("accepted_ms", e.acceptedMs.toString()) }))
            .put("next_version", next.authority.version.toString()).put("next_digest", b64(next.authority.digest)).put("next_ancestry_sha256", b64(next.ancestry()))
            .put("complete", next.authority.version == tip.authority.version).put("evidence", JSONObject(original.evidence))
        return Profile03ManifestHistory.decode(Profile03ManifestJson.objectValue(json.toString().toByteArray()))
    }
    override fun close() = original.close()
    private fun b64(b: ByteArray) = Profile03ElectionEncoding.encode(b)
}
