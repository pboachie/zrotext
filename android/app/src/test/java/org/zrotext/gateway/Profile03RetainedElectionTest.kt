// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.Signature
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Complete genuinely signed synthetic registration/v2/02/03/election composition and actual
 * Room history. Public descriptors are not hardware custody or a hosted acceptance assertion.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03RetainedElectionTest {
    private class Memory : Draft02TrustStore.Storage, Draft02TrustStore.Session {
        private var key = Draft02TrustStore.KeyState.ABSENT
        private var value: ByteArray? = null
        @Synchronized override fun <T> locked(action: Draft02TrustStore.Session.() -> T) = action(this)
        override fun keyState() = key
        override fun read() = value?.copyOf()
        override fun createKey() { check(key == Draft02TrustStore.KeyState.ABSENT); key = Draft02TrustStore.KeyState.READY }
        override fun seal(plaintext: ByteArray) = plaintext.copyOf()
        override fun open(ciphertext: ByteArray) = ciphertext.copyOf()
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) { preCommit(); value = ciphertext.copyOf() }
    }
    private class Fixture(distinctEventSigner: Boolean = false, includeEventSigner: Boolean = true) : AutoCloseable {
        val origin = "https://gateway.example.test"
        val f = Profile03ExecutionFixture(canonicalOrigin = origin, distinctEventSigner = distinctEventSigner, includeEventSigner = includeEventSigner)
        val activation = checkNotNull(f.line.db.lineActivationsV2().find("sealed", f.line.challengeId.toString()))
        val registrationId = UUID(0, 91)
        val ownerPoint = Profile03ExecutionFixture.point(f.approval)
        val devicePoint = Profile03ExecutionFixture.point(f.enrollment)
        private fun text(value: String) = value.toByteArray(Charsets.US_ASCII).let {
            ByteBuffer.allocate(2).putShort(it.size.toShort()).array() + it
        }
        val registrationTranscript = "ZTSE/line/owner-key/register/v1\u0000".toByteArray(Charsets.US_ASCII) +
            f.account + ReviewedIntent03.uuid(f.ownerUser) + ReviewedIntent03.uuid(f.ownerSession) + f.device + f.lineId +
            Profile03ExecutionFixture.long(1) + ReviewedIntent03.uuid(registrationId) + ByteArray(32) { 19 } +
            Profile03ExecutionFixture.long(99_900) + Profile03ExecutionFixture.long(200_000) + f.pin + f.fingerprint +
            ownerPoint + Profile03ExecutionFixture.sha(ownerPoint) + Profile03ExecutionFixture.sha(devicePoint) +
            Profile03ExecutionFixture.long(f.line.epoch) + Profile03ExecutionFixture.long(1) +
            text("synthetic-site") + text("synthetic-instance") + text(origin)
        val registration = ReviewedIntent03.framed("ZTSE/line/payload-profile/registration-evidence/v1",
            ByteBuffer.allocate(4).putInt(registrationTranscript.size).array() + registrationTranscript +
                Profile03ExecutionFixture.rawSign(f.root, registrationTranscript) + Profile03ExecutionFixture.rawSign(f.approval, registrationTranscript) +
                ownerPoint + Profile03ExecutionFixture.sha(ownerPoint) + Profile03ExecutionFixture.sha(devicePoint) +
                Profile03ExecutionFixture.long(99_900) + Profile03ExecutionFixture.long(200_000) + Profile03ExecutionFixture.long(99_999))
        val observation = LineActivationV2Observation.decode(Profile03ElectionEncoding.decode(activation.observationB64url, 121))
        val deviceStatement = LineActivationV2Statements.device(LineActivationV2Purpose.SEALED,
            LineActivationV2StatementFields(f.line.account, f.line.line, f.line.device, 1, f.line.challengeId, ByteArray(32) { 9 }), observation)
        val deviceDer = java.util.Base64.getUrlDecoder().decode(checkNotNull(activation.signatureDerB64url))
        val ownerStatement = LineActivationV2Statements.owner(LineActivationV2Purpose.SEALED, deviceStatement, deviceDer)
        val ownerDer = Signature.getInstance("SHA256withECDSA").run { initSign(f.approval.private); update(ownerStatement); sign() }
        val activationEvidence = ReviewedIntent03.framed("ZTSE/line/payload-profile/activation-evidence/v1",
            ReviewedIntent03.uuid(registrationId) + ReviewedIntent03.uuid(f.oldBinding) + devicePoint + ownerPoint +
                deviceStatement + ByteBuffer.allocate(2).putShort(deviceDer.size.toShort()).array() + deviceDer + ownerStatement +
                ByteBuffer.allocate(2).putShort(ownerDer.size.toShort()).array() + ownerDer + Profile03ExecutionFixture.long(100_000))
        val bindingDigest = Profile03ExecutionFixture.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/old-binding/v1",
            byteArrayOf(2, 2) + ReviewedIntent03.uuid(f.oldBinding) + f.account + f.device + f.lineId + Profile03ExecutionFixture.long(1) +
                ReviewedIntent03.uuid(f.line.challengeId) + ReviewedIntent03.uuid(registrationId) + Profile03ExecutionFixture.sha(registration) +
                Profile03ExecutionFixture.sha(ownerStatement + ownerDer) + Profile03ExecutionFixture.sha(deviceStatement + deviceDer) +
                Profile03ExecutionFixture.keyId(f.reader, false)))
        val core = f.core.copyOf().apply { bindingDigest.copyInto(this, 104); ByteBuffer.wrap(this).putLong(384, 100_001) }
        val deviceProof = Profile03ExecutionFixture.rawSign(f.enrollment, ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", core))
        val bundle = core + deviceProof + Profile03ExecutionFixture.rawSign(f.approval,
            ReviewedIntent03.framed("ZTSE/line/payload-profile/owner/v1", core + Profile03ExecutionFixture.sha(deviceProof)))
        val accepted = Draft03PayloadElectionProof.AcceptedRecord03(f.account, f.device, f.lineId, f.fingerprint, 1,
            ReviewedIntent03.uuid(f.oldBinding), 1, bindingDigest, ReviewedIntent03.uuid(f.newBinding), 2,
            Profile03ExecutionFixture.keyId(f.reader, false), 1, Profile03ExecutionFixture.unsigned(f.old), Profile03ExecutionFixture.sha(f.old),
            2, Profile03ExecutionFixture.unsigned(f.next), Profile03ExecutionFixture.sha(f.next), Profile03ExecutionFixture.sha(core),
            Profile03ExecutionFixture.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/commitment/v1", core)),
            Profile03ExecutionFixture.sha(bundle), f.acceptedAt)
        val installed = f.installed.copy(coreB64url = Profile03ElectionEncoding.encode(core),
            deviceSignatureB64url = Profile03ElectionEncoding.encode(deviceProof), acceptedEvidenceSha256 = Draft03OutboundPreparation.acceptedIdentity(accepted))
        val reader = DevicePayloadPublic(Profile03ExecutionFixture.point(f.reader), Profile03ExecutionFixture.keyId(f.reader, false), PayloadKeySecurity.TRUSTED_ENVIRONMENT)
        val store = compared()
        private fun compared(): Draft02TrustStore {
            val storage = Draft02TrustStore(Memory())
            val comparison = Draft02RootComparison()
            val display = comparison.begin(f.pin, f.account)
            check(storage.enroll(comparison.confirm(display.fingerprintHex, true)).status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
            check(Profile03ManifestBootstrap.install(storage, listOf(f.old), f.binding, reader, { 100_000 }, {}) == 1L)
            return storage
        }
        val evidence = mapOf<String, Any>("root_pin" to b64(f.pin), "prior_manifest02" to b64(f.old), "prior_accepted_ms" to "100000",
            "accepted_manifest03" to b64(f.next), "accepted_ms" to f.acceptedAt.toString(), "bundle" to b64(bundle),
            "device_signing_point" to b64(devicePoint), "owner_approval_point" to b64(ownerPoint),
            "registration_evidence" to b64(registration), "activation_evidence" to b64(activationEvidence))
        init {
            val dao = f.line.db.profile03Elections()
            check(dao.reserve(installed.copy(state = "reserved", deviceSignatureB64url = null, acceptedEvidenceSha256 = null)) {})
            check(dao.recordSigned(installed.copy(state = "signed", acceptedEvidenceSha256 = null)) {})
            check(dao.install(installed) {})
        }
        fun verify(input: Map<String, Any> = evidence, selected: Profile03ElectionRecord = installed,
            current: Draft02TrustStore = store, hardware: DevicePayloadPublic = reader) =
            Profile03RetainedElection.verify(input, selected, activation, current, hardware, devicePoint, origin) { f.now }
        private fun b64(value: ByteArray) = Profile03ElectionEncoding.encode(value)
        override fun close() = f.close()
    }
    @Test fun fullOriginalProofsVerifyBeforeFreshPhysicalAvailabilityWithoutPublishingPermission() = Fixture().use { v ->
        v.f.line.callback()
        assertNull(v.f.binding.installedSelectionV2())
        val verified = v.verify()
        assertTrue(verified.original.matchesLocal(v.activation))
        assertArrayEquals(v.accepted.electionCommitment, verified.election.acceptedRecord().electionCommitment)
        assertEquals(v.installed, v.f.line.db.profile03Elections().find(v.installed.challengeId))
        assertNull(v.f.binding.installedSelectionV2())
    }
    @Test fun downloadedCheckpointCannotRepairMissingComparedLocalRootAndHistory() = Fixture().use { v ->
        assertTrue(runCatching { v.verify(current = Draft02TrustStore(Memory())) }.isFailure)
        assertTrue(runCatching { v.verify(v.evidence + ("accepted_ms" to (v.f.acceptedAt + 1).toString())) }.isFailure)
        assertTrue(runCatching { v.verify(selected = v.installed.copy(acceptedEvidenceSha256 = "a".repeat(64))) }.isFailure)
        assertTrue(runCatching { v.verify(selected = v.installed.copy(state = "signed", acceptedEvidenceSha256 = null)) }.isFailure)
    }
    @Test fun originalProofAndHardwareSubstitutionRefusesEvenWithMatchingServerDigestFields() = Fixture().use { v ->
        for (name in listOf("registration_evidence", "activation_evidence", "bundle", "owner_approval_point", "root_pin", "prior_manifest02", "accepted_manifest03")) {
            val bytes = java.util.Base64.getUrlDecoder().decode(v.evidence[name] as String).apply { val index = if (name == "activation_evidence")
                "ZTSE/line/payload-profile/activation-evidence/v1".length + 5 + 162 + 100 else lastIndex
                // The final activation timestamp is durable metadata, not a signed byte. Mutate
                // the original signed device statement for the original-proof negative control.
                this[index] = (this[index].toInt() xor 1).toByte() }
            assertTrue(name, runCatching { v.verify(v.evidence + (name to Profile03ElectionEncoding.encode(bytes))) }.isFailure)
        }
        val wrong = DevicePayloadPublic(Profile03ExecutionFixture.point(v.f.archive), Profile03ExecutionFixture.keyId(v.f.archive, false), PayloadKeySecurity.TRUSTED_ENVIRONMENT)
        assertTrue(runCatching { v.verify(hardware = wrong) }.isFailure)
        assertTrue(runCatching { v.verify(v.evidence + ("extra" to "unsupported")) }.isFailure)
    }
    @Test fun originalEnrollmentProofCompositionDoesNotRequireItToBeTheManifestInboundEventSigner() {
        for (eventPresent in listOf(true, false)) Fixture(distinctEventSigner = true, includeEventSigner = eventPresent).use { v ->
            v.f.line.callback()
            val verified = v.verify()
            assertArrayEquals(v.devicePoint, verified.original.devicePoint())
            assertArrayEquals(v.accepted.electionCommitment, verified.election.acceptedRecord().electionCommitment)
            assertNull(v.f.binding.installedSelectionV2())
        }
    }
}
