// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.zrotext.gateway.Draft03PayloadElectionProof.AcceptedRecord03 as Accepted
import org.zrotext.gateway.Draft03PayloadElectionProof.CurrentAuthority03 as Current

/** Public synthetic proof tests. No custody aliases, installation, network or radio. */
abstract class Draft03PayloadElectionCorpus {
    @Test fun publicVectorBindsHistoricalProofAndFreshLaterAuthority() {
        val v = vector()
        val now = v.getLong("nowMs")
        val pin = hex(v.getString("rootPinHex"))
        val old = hex(v.getJSONObject("manifests").getJSONObject("prior02").getString("signedHex"))
        val next = hex(v.getJSONObject("manifests").getJSONObject("successor03").getString("signedHex"))
        val core = hex(v.getJSONObject("election").getString("coreHex"))
        val bundle = hex(v.getJSONObject("election").getString("bundleHex"))
        val a = record(core, old, next, bundle, now)
        val checkpoint = checkpoint(pin, old, now)
        val historical = Draft03PayloadElectionProof.verifyHistorical02(old, checkpoint, now, now)
        val proof = Draft03PayloadElectionProof.verifyAccepted(bundle, core, a, historical, next,
            hex(v.getJSONObject("publicPointsHex").getString("deviceEnrollment")),
            hex(v.getJSONObject("publicPointsHex").getString("ownerApproval")))
        assertEquals(500, core.size); assertEquals(628, bundle.size)
        assertArrayEquals(hex(v.getJSONObject("election").getString("semanticCommitmentHex")), a.electionCommitment)
        val first = Draft03ManifestAuthority.verifyFrom02(next, old, checkpoint, now)
        val later = now + 60_001
        val c = current(a, first, later, later + 20_000)
        assertArrayEquals(a.newBindingId, proof.requireCurrent(first, c, later).authority.bindingId)
        val afterBytes = hex(v.getJSONObject("manifests").getJSONObject("after03").getString("signedHex"))
        val after = Draft03ManifestAuthority.verifySuccessor(afterBytes, first, later)
        assertEquals(after.version, proof.requireCurrent(after, current(a, after, later, later + 20_000), later).authority.manifestVersion)
        assertTrue(later >= number(core, 392)) // Ceremony expiry is not a current permission window.
    }

    @Test fun everyAcceptedFieldAndIndependentExpectedCoreIsChecked() {
        val f = Sample()
        val a = f.record()
        f.proof(a = a)
        for (field in 0 until 21) {
            denied { f.proof(a = changedAccepted(a, field)) }
        }
        denied { f.proof(expected = f.core.copyOf().apply { this[56] = (this[56].toInt() xor 1).toByte() }) }
        // New UUID is trusted allocation metadata absent from E; a different nonzero
        // mapping can prove the same signatures, but cannot match the original current selection.
        val remapped = cloneAccepted(a) { b, _ -> b[6] = ByteArray(16) { 8 } }
        val proof = f.proof(a = remapped)
        denied { proof.requireCurrent(f.manifest(), current(a, f.manifest(), NOW, NOW + 1000), NOW) }
    }

    @Test fun correctlySignedInvalidCoreSemanticsRefuse() {
        val f = Sample()
        for (edit in listOf<(ByteArray) -> Unit>(
            { it[4] = 2 }, { it[5] = 2 }, { it[6] = 3 }, { it[7] = 2 }, { it[496] = 1 },
            { it.fill(0, 56, 72) }, { it.fill(0, 352, 384) }, { it.fill(0, 400, 432) },
            { it.fill(0, 432, 464) }, { it.fill(0, 464, 496) }
        )) {
            val core = f.core.copyOf().apply(edit)
            val bundle = f.bundle(core)
            val a = f.record(core, bundle)
            denied { f.proof(core, bundle, a) }
        }
        for (width in listOf(0, 499, 501)) denied { f.proof(expected = f.core.copyOf(width)) }
        for (width in listOf(0, 627, 629)) denied { f.proof(bundle = f.bundle().copyOf(width)) }
    }

    @Test fun generationGapsSignedStorageAndAcceptanceTimeBoundsAreExact() {
        val f = Sample()
        val gap = f.core.copyOf().apply { putLong(this, 96, 9_007_199_254_740_993L) }
        val gb = f.bundle(gap)
        assertEquals(9_007_199_254_740_993L, f.proof(gap, gb).acceptedRecord().newBindingGeneration)
        val max = f.core.copyOf().apply { putLong(this, 96, Long.MAX_VALUE) }
        val mb = f.bundle(max)
        assertEquals(Long.MAX_VALUE, f.proof(max, mb).acceptedRecord().newBindingGeneration)
        for (edit in listOf<(ByteArray) -> Unit>(
            { putLong(it, 96, 1) }, { putLong(it, 96, 0) }, { putLong(it, 96, Long.MIN_VALUE) },
            { putLong(it, 168, 2) }, { putLong(it, 176, Long.MAX_VALUE) },
            { putLong(it, 384, 0) }, { putLong(it, 384, NOW + 1) }, { putLong(it, 392, NOW) },
            { putLong(it, 392, number(it, 384) + 300_001) }
        )) {
            val core = f.core.copyOf().apply(edit)
            denied { val bundle = f.bundle(core); f.proof(core, bundle) }
        }
        for (bad in listOf(0L, -1L, Long.MIN_VALUE)) {
            denied { f.history(comparison = bad) }
            denied { f.proof().requireCurrent(f.manifest(), current(f.record(), f.manifest(), NOW, NOW + 1000), bad) }
        }
        denied { f.history(comparison = Long.MAX_VALUE) } // In-range clock, expired bounded manifest.
    }

    @Test fun independentKeysDomainsPointsAndRawScalarShapesAreRequired() {
        val f = Sample()
        val positive = f.proof()
        assertEquals(f.record().acceptedAtMs, positive.acceptedRecord().acceptedAtMs)
        val device = f.deviceProof()
        val wrongDevice = rawSign(f.device, "ZTSE/line/payload-profile/device/v2", f.core)
        val wrongOwner = rawSign(f.owner, "ZTSE/line/payload-profile/owner/v2", f.core + sha(device))
        for (bundle in listOf(f.bundle(deviceProof = wrongDevice), f.bundle(deviceProof = device, ownerProof = wrongOwner),
            f.bundle(deviceProof = rawSign(f.owner, DEVICE, f.core)),
            f.bundle(deviceProof = device, ownerProof = rawSign(f.device, OWNER, f.core + sha(device))))) {
            denied { f.proof(bundle = bundle, a = f.record(bundle = bundle)) }
        }
        for (at in intArrayOf(288, 320)) {
            val core = f.core.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            denied { f.proof(core) }
        }
        for (bad in listOf(ByteArray(65), point(f.device).copyOf(64), point(f.device).apply { this[0] = 2 })) {
            denied { f.proof(devicePoint = bad) }
            denied { f.proof(ownerPoint = bad) }
        }
        for (raw in listOf(ByteArray(64), scalarRaw(BigInteger.ZERO, BigInteger.ONE),
            scalarRaw(ORDER, BigInteger.ONE), scalarRaw(BigInteger.ONE, BigInteger.ZERO), scalarRaw(BigInteger.ONE, ORDER))) {
            for (bundle in listOf(f.bundle(deviceProof = raw), f.bundle(deviceProof = device, ownerProof = raw))) {
                denied { f.proof(bundle = bundle, a = f.record(bundle = bundle)) }
            }
        }
    }

    @Test fun highSTwinsAndOwnersWrongDeviceDigestAreRefusedIndependently() {
        val f = Sample()
        val device = f.deviceProof()
        val owner = f.ownerProof(device)
        val highDevice = high(device)
        val highOwner = high(owner)
        assertTrue(jcaVerify(point(f.device), highDevice, framed(DEVICE, f.core)))
        assertTrue(jcaVerify(point(f.owner), highOwner, framed(OWNER, f.core + sha(device))))
        for (bundle in listOf(f.bundle(deviceProof = highDevice, ownerProof = f.ownerProof(highDevice)),
            f.bundle(deviceProof = device, ownerProof = highOwner))) {
            denied { f.proof(bundle = bundle, a = f.record(bundle = bundle)) }
        }
        // Device guard passes; owner signed a different digest with the correct key/domain.
        val wrong = rawSign(f.owner, OWNER, f.core + sha(highDevice))
        assertTrue(jcaVerify(point(f.owner), wrong, framed(OWNER, f.core + sha(highDevice))))
        val bundle = f.bundle(deviceProof = device, ownerProof = wrong)
        denied { f.proof(bundle = bundle, a = f.record(bundle = bundle)) }
    }

    @Test fun exactAcceptedEvidenceAndSemanticCurrentSignaturesStayDistinct() {
        val f = Sample()
        val original = f.record()
        val altOld = sign(f.root, "ZTSE/manifest/v2", f.old.copyOfRange(0, f.old.size - 64))
        val altNext = sign(f.root, "ZTSE/manifest/v3", f.next.copyOfRange(0, f.next.size - 64))
        assertFalse(f.old.contentEquals(altOld)); assertFalse(f.next.contentEquals(altNext))
        val oldEvidence = altOld
        denied { f.proof(a = original, historical = f.history(old = oldEvidence)) }
        denied { f.proof(a = original, next = altNext) }
        val first = f.manifest()
        val alternate = Draft03ManifestAuthority.verifyCurrent(altNext, first, NOW)
        val proof = f.proof(a = original)
        proof.requireCurrent(alternate, current(original, alternate, NOW, NOW + 1000), NOW)
        assertArrayEquals(f.next, first.signedBytes)
        assertArrayEquals(original.acceptedSignedManifestSha256, proof.acceptedRecord().acceptedSignedManifestSha256)
    }

    @Test fun genuineHistoricalCheckpointHasIndependentClockAndFreshAcceptanceSubset() {
        val f = Sample()
        for (edit in listOf<(ByteArray, ByteArray) -> Draft03ManifestAuthority.Accepted02Checkpoint>(
            { pin, old -> checkpoint(pin, old, NOW, fingerprint = ByteArray(32) { 9 }) },
            { pin, old -> checkpoint(pin, old, NOW, account = ByteArray(16) { 9 }) },
            { pin, old -> checkpoint(pin, old, NOW, evidence = ByteArray(32) { 9 }) }
        )) denied { Draft03PayloadElectionProof.verifyHistorical02(f.old, edit(f.pin, f.old), NOW, NOW) }
        denied { Draft03PayloadElectionProof.verifyHistorical02(f.old, f.checkpoint(), NOW - 1, NOW) }
        denied { Draft03PayloadElectionProof.verifyHistorical02(f.old, f.checkpoint(), NOW + 1, NOW) }
        denied { f.history(old = f.old + byteArrayOf(0)) }
        denied { checkpoint(f.pin, f.old, NOW, anchor = ByteArray(32) { 1 }) }
        val expired02 = f.manifestBytes(2, 1, 0, ByteArray(32), expires = NOW)
        val next = f.manifestBytes(3, 2, 2, unsignedSha(expired02))
        val core = f.core.copyOf().apply {
            unsignedSha(expired02).copyInto(this, 184); unsignedSha(next).copyInto(this, 224)
        }
        val cp = checkpoint(f.pin, expired02, NOW - 500)
        val historical = Draft03PayloadElectionProof.verifyHistorical02(expired02, cp, NOW - 500, NOW - 500)
        // Parent has broader expired02-history support; the election component deliberately refuses.
        Draft03ManifestAuthority.verifyFrom02(next, expired02, cp, NOW)
        val bundle = f.bundle(core)
        denied { f.proof(core, bundle, record(core, expired02, next, bundle, NOW), historical, next) }
        // Recovery after expiry is pure: validation is at original recorded acceptance time.
        val proof = f.proof()
        val later = NOW + 100_000
        val currentManifest = f.manifest(later)
        proof.requireCurrent(currentManifest, current(f.record(), currentManifest, later, later + 1000), later)
        assertTrue(later > number(f.core, 392))
    }

    @Test fun rootSignedSuccessorMustMatchAcceptedChainAndExactEvidence() {
        val f = Sample()
        for (edit in listOf<(ByteArray) -> Unit>(
            { it[6] = 3 }, { putLong(it, 23, 2) }, { putLong(it, 31, 3) },
            { it[7] = (it[7].toInt() xor 1).toByte() }, { it.fill(0, 55, 87) },
            { it[87 + 1] = (it[87 + 1].toInt() xor 1).toByte() }
        )) {
            val unsigned = f.next.copyOfRange(0, f.next.size - 64).apply(edit)
            val next = sign(f.root, "ZTSE/manifest/v3", unsigned)
            val core = f.core.copyOf().apply { unsignedSha(next).copyInto(this, 224) }
            val bundle = f.bundle(core)
            denied { f.proof(core, bundle, record(core, f.old, next, bundle, NOW), next = next) }
        }
        val corrupted = f.next.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        val bundle = f.bundle()
        denied { f.proof(bundle = bundle, a = record(f.core, f.old, corrupted, bundle, NOW), next = corrupted) }
    }

    @Test fun allPresentTupleFieldsAndFreshPermissionAreCompared() {
        val f = Sample()
        val a = f.record(); val proof = f.proof(); val manifest = f.manifest()
        val current = current(a, manifest, NOW, NOW + 1000)
        proof.requireCurrent(manifest, current, NOW)
        for (field in 0 until 16) denied { proof.requireCurrent(manifest, changedCurrent(current, field), NOW) }
        denied { proof.requireCurrent(manifest, current, NOW + 1000) }
        denied { proof.requireCurrent(manifest, current, NOW - 1) }
        val laterVerified = f.manifest(NOW + 1)
        denied { proof.requireCurrent(laterVerified, current, NOW) }
        val expired = NOW + 800_000
        denied { proof.requireCurrent(manifest, current(a, manifest, expired, expired + 1000), expired) }
    }

    @Test fun capturedInputsAndCopyOutEvidenceCannotBeMutated() {
        val f = Sample()
        val core = f.core.copyOf(); val bundle = f.bundle(core); val next = f.next.copyOf()
        val device = point(f.device); val owner = point(f.owner); val a = f.record(core, bundle)
        val pristine = f.record(core, bundle)
        val proof = f.proof(core, bundle, a, next = next, devicePoint = device, ownerPoint = owner)
        core.fill(0); bundle.fill(0); next.fill(0); device.fill(0); owner.fill(0)
        a.accountId.fill(0); a.electionCommitment.fill(0); proof.acceptedRecord().newBindingId.fill(0)
        val manifest = f.manifest(); val c = current(pristine, manifest, NOW, NOW + 1000)
        val comparison = proof.requireCurrent(manifest, c, NOW)
        c.bindingId.fill(0); c.manifestDigest.fill(0); comparison.authority.electionBundleSha256.fill(0)
        assertArrayEquals(pristine.newBindingId, comparison.authority.bindingId)
        assertArrayEquals(pristine.electionCommitment, proof.acceptedRecord().electionCommitment)
        val cp = f.checkpoint(); val old = f.old.copyOf(); val history = f.history(old = old, cp = cp)
        old.fill(0); cp.pin().fill(0); cp.evidence().fill(0)
        f.proof(historical = history)
    }

    @Test fun pureReverificationDoesNotManufactureReplayCasOrAdvanceOtherClock() {
        val f = Sample()
        val first = f.proof(); val again = f.proof()
        assertArrayEquals(first.acceptedRecord().electionBundleSha256, again.acceptedRecord().electionBundleSha256)
        val alternate = f.bundle() // Randomized valid signatures, identical E.
        assertFalse(alternate.contentEquals(f.originalBundle))
        denied { f.proof(bundle = alternate, a = f.record(bundle = f.originalBundle)) }
        val manifest = f.manifest()
        val original = current(f.record(), manifest, NOW, NOW + 1000)
        first.requireCurrent(manifest, current(f.record(), manifest, NOW + 10, NOW + 1000), NOW + 10)
        // No global clock mutation: caller must obtain durable fresh state independently.
        again.requireCurrent(manifest, original, NOW)
        val fork = cloneAccepted(f.record()) { b, _ -> b[6] = ByteArray(16) { 7 } }
        val forkProof = f.proof(a = fork)
        forkProof.requireCurrent(manifest, current(fork, manifest, NOW, NOW + 1000), NOW)
        first.requireCurrent(manifest, original, NOW) // No cross-call allocation CAS is supplied.
    }

    private class Sample {
        val root = key(); val reader = key(); val archive = key(); val device = key(); val owner = key()
        val account = ByteArray(16) { 1 }; val deviceId = ByteArray(16) { 2 }; val line = ByteArray(16) { 3 }
        val pin = byteArrayOf(90, 84, 82, 80, 2) + account + long(1) + point(root)
        val old = manifestBytes(2, 1, 0, ByteArray(32))
        val next = manifestBytes(3, 2, 2, unsignedSha(old))
        val core = hex(vector().getJSONObject("election").getString("coreHex")).apply {
            account.copyInto(this, 8); deviceId.copyInto(this, 24); line.copyInto(this, 40)
            putLong(this, 88, 1); putLong(this, 96, 2); fingerprint(pin).copyInto(this, 136)
            putLong(this, 168, 1); putLong(this, 176, 1); unsignedSha(old).copyInto(this, 184)
            putLong(this, 216, 2); unsignedSha(next).copyInto(this, 224); id(point(reader), false).copyInto(this, 256)
            id(point(device), true).copyInto(this, 288); id(point(owner), true).copyInto(this, 320)
            putLong(this, 384, NOW - 100); putLong(this, 392, NOW + 1000)
        }
        val originalBundle = bundle()
        fun deviceProof(core: ByteArray = this.core) = rawSign(device, DEVICE, core)
        fun ownerProof(deviceProof: ByteArray, core: ByteArray = this.core) = rawSign(owner, OWNER, core + sha(deviceProof))
        fun bundle(core: ByteArray = this.core, deviceProof: ByteArray = deviceProof(core),
                   ownerProof: ByteArray = ownerProof(deviceProof, core)) = core + deviceProof + ownerProof
        fun record(core: ByteArray = this.core, bundle: ByteArray = originalBundle) =
            Draft03PayloadElectionCorpus.record(core, old, next, bundle, NOW)
        fun checkpoint() = Draft03PayloadElectionCorpus.checkpoint(pin, old, NOW)
        fun history(old: ByteArray = this.old, comparison: Long = NOW,
                    cp: Draft03ManifestAuthority.Accepted02Checkpoint = Draft03PayloadElectionCorpus.checkpoint(pin, old, NOW)) =
            Draft03PayloadElectionProof.verifyHistorical02(old, cp, NOW, comparison)
        fun manifest(now: Long = NOW) = Draft03ManifestAuthority.verifyFrom02(next, old, checkpoint(), now)
        fun proof(core: ByteArray = this.core,
                  bundle: ByteArray = if (core.contentEquals(this.core)) originalBundle else bundle(core),
                  a: Accepted = record(core, bundle), historical: Draft03PayloadElectionProof.VerifiedHistorical02 = history(),
                  next: ByteArray = this.next, expected: ByteArray = core,
                  devicePoint: ByteArray = point(device), ownerPoint: ByteArray = point(owner)) =
            Draft03PayloadElectionProof.verifyAccepted(bundle, expected, a, historical, next, devicePoint, ownerPoint)
        fun manifestBytes(profile: Int, version: Long, predecessor: Int, previous: ByteArray,
                          expires: Long = NOW + 800_000): ByteArray {
            fun row(role: Int, pair: KeyPair, scope: Int, bound: Boolean) = byteArrayOf(role.toByte()) +
                id(point(pair), role > 3) + point(pair) + (if (bound) deviceId else ByteArray(16)) +
                (if (bound) line else ByteArray(16)) + byteArrayOf(0, scope.toByte()) + long(1) + long(expires) + byteArrayOf(1)
            val records = row(1, reader, 4, true) + row(2, archive, 12, false) + row(4, device, 2, true) + row(6, root, 0, false)
            val header = if (profile == 2) byteArrayOf(90, 84, 77, 65, 2) else byteArrayOf(90, 84, 77, 65, 3, 3, predecessor.toByte())
            val unsigned = header + account + long(1) + long(version) + long(NOW - 1000) + long(expires) + previous + point(root) + byteArrayOf(4) + records
            return sign(root, "ZTSE/manifest/v$profile", unsigned)
        }
    }

    companion object {
        private const val NOW = 10_000L
        private const val DEVICE = "ZTSE/line/payload-profile/device/v1"
        private const val OWNER = "ZTSE/line/payload-profile/owner/v1"
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private fun vector() = Draft03PayloadElectionCorpus::class.java.classLoader!!
            .getResourceAsStream("sealed-profile03-contract-01.json")!!.use { JSONObject(it.bufferedReader(Charsets.UTF_8).readText()) }
        private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        private fun unsignedSha(b: ByteArray) = sha(b.copyOfRange(0, b.size - 64))
        private fun fingerprint(pin: ByteArray) = sha("ZTSE/root-pin/v2".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + pin)
        private fun long(n: Long) = ByteBuffer.allocate(8).putLong(n).array()
        private fun putLong(b: ByteArray, at: Int, n: Long) { ByteBuffer.wrap(b, at, 8).putLong(n) }
        private fun number(b: ByteArray, at: Int) = ByteBuffer.wrap(b, at, 8).long
        private fun framed(label: String, b: ByteArray) = label.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + ByteBuffer.allocate(4).putInt(b.size).array() + b
        private fun key() = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        private fun point(key: KeyPair) = DevicePayloadKeyStore.encodePoint(key.public as ECPublicKey)
        private fun id(p: ByteArray, signing: Boolean) = sha("ZTSE/key/v1".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            (if (signing) byteArrayOf(1, 1) else byteArrayOf(0, 16)) + p)
        private fun scalarRaw(r: BigInteger, s: BigInteger): ByteArray {
            fun padded(n: BigInteger) = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            return padded(r) + padded(s)
        }
        private fun der(raw: ByteArray): ByteArray {
            fun integer(at: Int) = BigInteger(1, raw.copyOfRange(at, at + 32)).toByteArray().let { byteArrayOf(2, it.size.toByte()) + it }
            val f = integer(0) + integer(32); return byteArrayOf(0x30, f.size.toByte()) + f
        }
        private fun sign(key: KeyPair, label: String, body: ByteArray): ByteArray {
            val encoded = Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(framed(label, body)); sign() }
            val rSize = encoded[3].toInt() and 255; val sAt = 4 + rSize; val sSize = encoded[sAt + 1].toInt() and 255
            val r = BigInteger(1, encoded.copyOfRange(4, sAt)); val s = BigInteger(1, encoded.copyOfRange(sAt + 2, sAt + 2 + sSize))
            return body + scalarRaw(r, if (s > ORDER.shiftRight(1)) ORDER - s else s)
        }
        private fun rawSign(key: KeyPair, label: String, body: ByteArray) = sign(key, label, body).takeLast(64).toByteArray()
        private fun high(raw: ByteArray) = scalarRaw(BigInteger(1, raw.copyOfRange(0, 32)), ORDER - BigInteger(1, raw.copyOfRange(32, 64)))
        private fun jcaVerify(point: ByteArray, raw: ByteArray, bytes: ByteArray) = Signature.getInstance("SHA256withECDSA").run {
            initVerify(DevicePayloadKeyStore.decodePoint(point)); update(bytes); verify(der(raw))
        }
        private fun checkpoint(pin: ByteArray, old: ByteArray, at: Long, fingerprint: ByteArray = fingerprint(pin),
                               account: ByteArray = pin.copyOfRange(5, 21), evidence: ByteArray = sha(old),
                               anchor: ByteArray = ByteArray(32)) = Draft03ManifestAuthority.Accepted02Checkpoint(pin,
            account, fingerprint, 1, number(old, 29), unsignedSha(old), anchor, evidence, at)
        private fun record(core: ByteArray, old: ByteArray, next: ByteArray, bundle: ByteArray, at: Long) = Accepted(
            core.copyOfRange(8, 24), core.copyOfRange(24, 40), core.copyOfRange(40, 56), core.copyOfRange(136, 168), number(core, 168),
            core.copyOfRange(72, 88), number(core, 88), core.copyOfRange(104, 136), ByteArray(16) { 9 }, number(core, 96),
            core.copyOfRange(256, 288), number(core, 176), core.copyOfRange(184, 216), sha(old), number(core, 216),
            core.copyOfRange(224, 256), sha(next), sha(core), sha(framed("ZTSE/line/payload-profile/commitment/v1", core)), sha(bundle), at)
        private fun cloneAccepted(a: Accepted, edit: (Array<ByteArray>, LongArray) -> Unit): Accepted {
            val b = arrayOf(a.accountId, a.deviceId, a.lineId, a.rootFingerprint, a.oldBindingId, a.oldBindingProofDigest,
                a.newBindingId, a.selectedReaderKeyId, a.priorManifestDigest, a.priorSignedManifestSha256,
                a.acceptedManifestDigest, a.acceptedSignedManifestSha256, a.electionCoreSha256, a.electionCommitment, a.electionBundleSha256)
            val n = longArrayOf(a.vaultGeneration, a.oldBindingGeneration, a.newBindingGeneration, a.priorManifestVersion, a.acceptedManifestVersion, a.acceptedAtMs)
            edit(b, n)
            return Accepted(b[0], b[1], b[2], b[3], n[0], b[4], n[1], b[5], b[6], n[2], b[7], n[3], b[8], b[9], n[4], b[10], b[11], b[12], b[13], b[14], n[5])
        }
        private fun changedAccepted(a: Accepted, field: Int) = cloneAccepted(a) { b, n ->
            if (field < 15) { if (field == 6) b[field].fill(0) else b[field][0] = (b[field][0].toInt() xor 1).toByte() }
            else if (field == 20) n[5] += 1000 else n[field - 15]++
        }
        private fun current(a: Accepted, manifest: Draft03ManifestAuthority, compared: Long, expires: Long) = Current(3, 3,
            a.accountId, a.deviceId, a.lineId, a.newBindingId, a.newBindingGeneration, a.selectedReaderKeyId,
            a.rootFingerprint, a.vaultGeneration, manifest.version, manifest.digest, a.electionCommitment, a.electionBundleSha256, compared, expires)
        private fun changedCurrent(c: Current, field: Int): Current {
            val b = arrayOf(c.accountId, c.deviceId, c.lineId, c.bindingId, c.selectedReaderKeyId, c.rootFingerprint,
                c.manifestDigest, c.electionCommitment, c.electionBundleSha256)
            val n = longArrayOf(c.bindingGeneration, c.vaultGeneration, c.manifestVersion, c.comparedAtMs, c.permissionExpiresAtMs)
            var profile = c.profile; var manifestProfile = c.manifestProfile
            when { field == 0 -> profile = 2; field == 1 -> manifestProfile = 2
                field < 11 -> { val at = field - 2; b[at][0] = (b[at][0].toInt() xor 1).toByte() }
                field == 15 -> n[4] = NOW
                else -> n[field - 11]++ }
            return Current(profile, manifestProfile, b[0], b[1], b[2], b[3], n[0], b[4], b[5], n[1], n[2], b[6], b[7], b[8], n[3], n[4])
        }
        private fun denied(block: () -> Any?) {
            try { block() } catch (_: IllegalArgumentException) { return }
            fail("Expected election proof refusal")
        }
    }
}
