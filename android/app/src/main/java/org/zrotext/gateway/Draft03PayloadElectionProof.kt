// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature

/** Historical public proof only. No storage, sessions, install, grant or radio permission. */
internal class Draft03PayloadElectionProof private constructor(
    private val accepted: AcceptedRecord03,
    private val root: ByteArray
) {
    override fun toString() = "Draft03PayloadElectionProof(verified)"
    internal fun acceptedRecord() = accepted.ownedCopy()
    internal fun rootPoint() = root.copyOf()

    /** All values must originate in independently authenticated durable acceptance state. */
    class AcceptedRecord03(
        accountId: ByteArray, deviceId: ByteArray, lineId: ByteArray, rootFingerprint: ByteArray,
        val vaultGeneration: Long, oldBindingId: ByteArray, val oldBindingGeneration: Long,
        oldBindingProofDigest: ByteArray, newBindingId: ByteArray, val newBindingGeneration: Long,
        selectedReaderKeyId: ByteArray, val priorManifestVersion: Long, priorManifestDigest: ByteArray,
        priorSignedManifestSha256: ByteArray, val acceptedManifestVersion: Long, acceptedManifestDigest: ByteArray,
        acceptedSignedManifestSha256: ByteArray, electionCoreSha256: ByteArray, electionCommitment: ByteArray,
        electionBundleSha256: ByteArray, val acceptedAtMs: Long
    ) {
        private val fields = arrayOf(
            nonzeroCopy(accountId, 16), nonzeroCopy(deviceId, 16), nonzeroCopy(lineId, 16),
            nonzeroCopy(rootFingerprint, 32), nonzeroCopy(oldBindingId, 16), nonzeroCopy(oldBindingProofDigest, 32),
            nonzeroCopy(newBindingId, 16), nonzeroCopy(selectedReaderKeyId, 32), nonzeroCopy(priorManifestDigest, 32),
            nonzeroCopy(priorSignedManifestSha256, 32), nonzeroCopy(acceptedManifestDigest, 32),
            nonzeroCopy(acceptedSignedManifestSha256, 32), nonzeroCopy(electionCoreSha256, 32),
            nonzeroCopy(electionCommitment, 32), nonzeroCopy(electionBundleSha256, 32)
        )
        val accountId get() = fields[0].copyOf()
        val deviceId get() = fields[1].copyOf()
        val lineId get() = fields[2].copyOf()
        val rootFingerprint get() = fields[3].copyOf()
        val oldBindingId get() = fields[4].copyOf()
        val oldBindingProofDigest get() = fields[5].copyOf()
        val newBindingId get() = fields[6].copyOf()
        val selectedReaderKeyId get() = fields[7].copyOf()
        val priorManifestDigest get() = fields[8].copyOf()
        val priorSignedManifestSha256 get() = fields[9].copyOf()
        val acceptedManifestDigest get() = fields[10].copyOf()
        val acceptedSignedManifestSha256 get() = fields[11].copyOf()
        val electionCoreSha256 get() = fields[12].copyOf()
        val electionCommitment get() = fields[13].copyOf()
        val electionBundleSha256 get() = fields[14].copyOf()
        init { positive(vaultGeneration, oldBindingGeneration, newBindingGeneration,
            priorManifestVersion, acceptedManifestVersion, acceptedAtMs) }
        internal fun ownedCopy() = AcceptedRecord03(accountId, deviceId, lineId, rootFingerprint, vaultGeneration,
            oldBindingId, oldBindingGeneration, oldBindingProofDigest, newBindingId, newBindingGeneration,
            selectedReaderKeyId, priorManifestVersion, priorManifestDigest, priorSignedManifestSha256,
            acceptedManifestVersion, acceptedManifestDigest, acceptedSignedManifestSha256, electionCoreSha256,
            electionCommitment, electionBundleSha256, acceptedAtMs)
        override fun toString() = "TrustedAcceptedElection03"
    }

    /** Structural present input. Receiving matching bytes does not authenticate its origin. */
    class CurrentAuthority03(
        val profile: Int, val manifestProfile: Int, accountId: ByteArray, deviceId: ByteArray,
        lineId: ByteArray, bindingId: ByteArray, val bindingGeneration: Long, selectedReaderKeyId: ByteArray,
        rootFingerprint: ByteArray, val vaultGeneration: Long, val manifestVersion: Long,
        manifestDigest: ByteArray, electionCommitment: ByteArray, electionBundleSha256: ByteArray,
        val comparedAtMs: Long, val permissionExpiresAtMs: Long
    ) {
        private val fields = arrayOf(nonzeroCopy(accountId, 16), nonzeroCopy(deviceId, 16), nonzeroCopy(lineId, 16),
            nonzeroCopy(bindingId, 16), nonzeroCopy(selectedReaderKeyId, 32), nonzeroCopy(rootFingerprint, 32),
            nonzeroCopy(manifestDigest, 32), nonzeroCopy(electionCommitment, 32), nonzeroCopy(electionBundleSha256, 32))
        val accountId get() = fields[0].copyOf()
        val deviceId get() = fields[1].copyOf()
        val lineId get() = fields[2].copyOf()
        val bindingId get() = fields[3].copyOf()
        val selectedReaderKeyId get() = fields[4].copyOf()
        val rootFingerprint get() = fields[5].copyOf()
        val manifestDigest get() = fields[6].copyOf()
        val electionCommitment get() = fields[7].copyOf()
        val electionBundleSha256 get() = fields[8].copyOf()
        init { positive(bindingGeneration, vaultGeneration, manifestVersion, comparedAtMs, permissionExpiresAtMs) }
        internal fun ownedCopy() = CurrentAuthority03(profile, manifestProfile, accountId, deviceId, lineId,
            bindingId, bindingGeneration, selectedReaderKeyId, rootFingerprint, vaultGeneration, manifestVersion,
            manifestDigest, electionCommitment, electionBundleSha256, comparedAtMs, permissionExpiresAtMs)
        override fun toString() = "TrustedCurrentElection03"
    }

    /** Genuine02 cryptographic snapshot; the structural checkpoint is NOT storage attestation. */
    class VerifiedHistorical02 private constructor(
        private val signed: ByteArray,
        private val checkpoint: Draft03ManifestAuthority.Accepted02Checkpoint,
        private val genuine: Draft02ManifestAuthority,
        val lastVerifiedMs: Long,
        val comparisonMs: Long
    ) {
        internal fun signedSha256() = sha(signed)
        internal fun fingerprint() = checkpoint.fingerprint()
        internal fun originalAcceptedAtMs() = checkpoint.verifiedAtMs
        internal fun version() = genuine.version
        internal fun digest() = genuine.digest
        internal fun successor(input: ByteArray, acceptedAtMs: Long): Draft03ManifestAuthority {
            positive(acceptedAtMs)
            require(acceptedAtMs >= comparisonMs) { "Historical comparison regression" }
            // Rust-common subset:02 must also be fresh at election acceptance.
            Draft02ManifestAuthority.verify(checkpoint.pin(), signed, trust(checkpoint), acceptedAtMs)
            return Draft03ManifestAuthority.verifyFrom02(input, signed, checkpoint, acceptedAtMs)
        }
        override fun toString() = "VerifiedHistorical02"
        companion object {
            fun verify(retainedSigned02: ByteArray, checkpoint: Draft03ManifestAuthority.Accepted02Checkpoint,
                       lastVerifiedMs: Long, comparisonMs: Long): VerifiedHistorical02 {
                require(retainedSigned02.size in 364..9751) { "Historical manifest bound" }
                val signed = retainedSigned02.copyOf()
                val captured = Draft03ManifestAuthority.Accepted02Checkpoint(checkpoint.pin(), checkpoint.account(),
                    checkpoint.fingerprint(), checkpoint.generation, checkpoint.version, checkpoint.digest(),
                    checkpoint.anchor(), checkpoint.evidence(), checkpoint.verifiedAtMs)
                positive(lastVerifiedMs, comparisonMs)
                require(captured.verifiedAtMs <= lastVerifiedMs && lastVerifiedMs <= comparisonMs) { "Historical clock order" }
                require(same(sha(signed), captured.evidence())) { "Historical exact evidence" }
                Draft02ManifestAuthority.verify(captured.pin(), signed, trust(captured), captured.verifiedAtMs)
                val genuine = Draft02ManifestAuthority.verify(captured.pin(), signed, trust(captured), comparisonMs)
                return VerifiedHistorical02(signed, captured, genuine, lastVerifiedMs, comparisonMs)
            }
            private fun trust(c: Draft03ManifestAuthority.Accepted02Checkpoint) = Draft02ManifestAuthority.Trust(
                c.account(), c.fingerprint(), 1, Draft02ManifestAuthority.Position.current(c.version, c.digest()))
        }
    }

    /** Checked comparison evidence only; no CAS or independently authenticated current reader. */
    class CurrentComparison03 private constructor(private val value: CurrentAuthority03) {
        val authority get() = value.ownedCopy()
        override fun toString() = "Election03CurrentComparison"
        companion object {
            internal fun compare(proof: Draft03PayloadElectionProof, manifest: Draft03ManifestAuthority,
                                 current: CurrentAuthority03, nowMs: Long): CurrentComparison03 {
                val c = current.ownedCopy()
                val a = proof.acceptedRecord()
                positive(nowMs)
                require(c.profile == 3 && c.manifestProfile == 3 && nowMs >= a.acceptedAtMs &&
                    nowMs >= c.comparedAtMs && nowMs < c.permissionExpiresAtMs) { "Current profile/time" }
                require(same(c.accountId, a.accountId) && same(c.deviceId, a.deviceId) && same(c.lineId, a.lineId) &&
                    same(c.bindingId, a.newBindingId) && c.bindingGeneration == a.newBindingGeneration &&
                    same(c.selectedReaderKeyId, a.selectedReaderKeyId) && same(c.rootFingerprint, a.rootFingerprint) &&
                    c.vaultGeneration == a.vaultGeneration && same(c.electionCommitment, a.electionCommitment) &&
                    same(c.electionBundleSha256, a.electionBundleSha256) && c.manifestVersion >= a.acceptedManifestVersion) {
                    "Current binding/election mismatch"
                }
                val fresh = Draft03ManifestAuthority.verifyCurrent(manifest.signedBytes, manifest, nowMs)
                require(same(fresh.accountId, c.accountId) && same(fresh.rootPoint, proof.rootPoint()) &&
                    fresh.generation == c.vaultGeneration && fresh.version == c.manifestVersion &&
                    same(fresh.digest, c.manifestDigest) &&
                    (c.manifestVersion != a.acceptedManifestVersion || same(c.manifestDigest, a.acceptedManifestDigest))) {
                    "Current manifest mismatch"
                }
                return CurrentComparison03(c)
            }
        }
    }

    fun requireCurrent(manifest: Draft03ManifestAuthority, current: CurrentAuthority03, nowMs: Long) =
        CurrentComparison03.compare(this, manifest, current, nowMs)

    companion object {
        fun verifyHistorical02(retainedSigned02: ByteArray, checkpoint: Draft03ManifestAuthority.Accepted02Checkpoint,
                               lastVerifiedMs: Long, comparisonMs: Long) =
            VerifiedHistorical02.verify(retainedSigned02, checkpoint, lastVerifiedMs, comparisonMs)

        fun verifyAccepted(bundle: ByteArray, expectedCore: ByteArray, accepted: AcceptedRecord03,
                           predecessor: VerifiedHistorical02, acceptedSignedManifest03: ByteArray,
                           deviceSigningPointAtAcceptance: ByteArray,
                           ownerApprovalPointAtAcceptance: ByteArray): Draft03PayloadElectionProof {
            require(bundle.size == 628 && expectedCore.size == 500 && acceptedSignedManifest03.size in 366..9753) {
                "Election/manifest bound"
            }
            val bytes = bundle.copyOf()
            val expected = expectedCore.copyOf()
            val signed03 = acceptedSignedManifest03.copyOf()
            val device = exactCopy(deviceSigningPointAtAcceptance, 65)
            val owner = exactCopy(ownerApprovalPointAtAcceptance, 65)
            val a = accepted.ownedCopy()
            val core = bytes.copyOfRange(0, 500)
            require(same(core, expected) && same(core.copyOfRange(0, 8), byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3)) &&
                zero(core.copyOfRange(496, 500))) { "Election framing/context" }
            for (at in intArrayOf(56, 352, 400, 432, 464)) {
                require(!zero(core.copyOfRange(at, at + if (at == 56) 16 else 32))) { "Zero challenge/session/origin" }
            }
            for ((at, value) in arrayOf(8 to a.accountId, 24 to a.deviceId, 40 to a.lineId, 72 to a.oldBindingId,
                104 to a.oldBindingProofDigest, 136 to a.rootFingerprint, 184 to a.priorManifestDigest,
                224 to a.acceptedManifestDigest, 256 to a.selectedReaderKeyId)) {
                require(same(core.copyOfRange(at, at + value.size), value)) { "Accepted field mismatch" }
            }
            for ((at, n) in arrayOf(88 to a.oldBindingGeneration, 96 to a.newBindingGeneration, 168 to a.vaultGeneration,
                176 to a.priorManifestVersion, 216 to a.acceptedManifestVersion)) {
                require(number(core, at) == n) { "Accepted integer mismatch" }
            }
            val issued = number(core, 384)
            val expires = number(core, 392)
            positive(issued, expires)
            require(expires > issued && expires - issued <= 300_000 && a.acceptedAtMs >= issued &&
                a.acceptedAtMs < expires && a.acceptedAtMs >= predecessor.originalAcceptedAtMs() &&
                a.newBindingGeneration > a.oldBindingGeneration && a.vaultGeneration == 1L &&
                a.priorManifestVersion < Long.MAX_VALUE && a.acceptedManifestVersion == a.priorManifestVersion + 1) {
                "Election time/generation"
            }
            require(same(predecessor.signedSha256(), a.priorSignedManifestSha256) &&
                same(sha(signed03), a.acceptedSignedManifestSha256) && same(sha(core), a.electionCoreSha256) &&
                same(sha(bytes), a.electionBundleSha256) &&
                same(sha(framed("ZTSE/line/payload-profile/commitment/v1", core)), a.electionCommitment)) { "Original evidence digest" }
            val manifest = predecessor.successor(signed03, a.acceptedAtMs)
            require(same(manifest.accountId, a.accountId) && manifest.generation == a.vaultGeneration &&
                manifest.version == a.acceptedManifestVersion && same(manifest.digest, a.acceptedManifestDigest) &&
                predecessor.version() == a.priorManifestVersion && same(predecessor.digest(), a.priorManifestDigest) &&
                same(predecessor.fingerprint(), a.rootFingerprint)) { "Accepted manifest binding" }
            DevicePayloadKeyStore.decodePoint(device)
            DevicePayloadKeyStore.decodePoint(owner)
            require(same(keyId(device), core.copyOfRange(288, 320)) && same(keyId(owner), core.copyOfRange(320, 352))) {
                "Enrollment/approval key ID"
            }
            val deviceProof = bytes.copyOfRange(500, 564)
            verifySignature(device, deviceProof, framed("ZTSE/line/payload-profile/device/v1", core))
            verifySignature(owner, bytes.copyOfRange(564, 628),
                framed("ZTSE/line/payload-profile/owner/v1", core + sha(deviceProof)))
            return Draft03PayloadElectionProof(a, manifest.rootPoint)
        }

        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun verifySignature(point: ByteArray, raw: ByteArray, transcript: ByteArray) {
            require(raw.size == 64) { "Raw signature width" }
            val r = BigInteger(1, raw.copyOfRange(0, 32))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            require(r.signum() > 0 && r < ORDER && s.signum() > 0 && s <= ORDER.shiftRight(1)) { "Raw signature scalar/low-S" }
            fun integer(n: BigInteger) = n.toByteArray().let { byteArrayOf(2, it.size.toByte()) + it }
            val fields = integer(r) + integer(s)
            require(Signature.getInstance("SHA256withECDSA").run {
                initVerify(DevicePayloadKeyStore.decodePoint(point)); update(transcript)
                verify(byteArrayOf(0x30, fields.size.toByte()) + fields)
            }) { "Election signature mismatch" }
        }
        private fun framed(label: String, payload: ByteArray): ByteArray {
            require(label.all { it.code in 1..127 }) { "ASCII label without NUL" }
            return label.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + ByteBuffer.allocate(4).putInt(payload.size).array() + payload
        }
        private fun keyId(point: ByteArray) = sha("ZTSE/key/v1".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 1, 1) + point)
        private fun number(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also {
            require(it >= 0) { "Signed storage range" }
        }
        private fun exactCopy(bytes: ByteArray, width: Int): ByteArray {
            require(bytes.size == width) { "Byte width" }; return bytes.copyOf()
        }
        private fun nonzeroCopy(bytes: ByteArray, width: Int) = exactCopy(bytes, width).also {
            require(!zero(it)) { "Zero identity/digest" }
        }
        private fun positive(vararg values: Long) { require(values.all { it > 0 }) { "Positive signed storage value" } }
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun zero(bytes: ByteArray) = bytes.all { it == 0.toByte() }
    }
}
