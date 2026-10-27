// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual current reader, nonce clock, Room originals and genuine signatures up to the
 * existing-only custody boundary. Missing JVM custody must refuse; no SIM/radio success. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03CurrentOriginsTest {
    private class Harness(val original: Profile03RetainedElectionTest.Fixture,
        routing: String = original.f.origins.routingHash) {
        val f = original.f
        private val app = RuntimeEnvironment.getApplication()
        private val sent = mutableListOf<JSONObject>()
        private var elapsed = 100L
        val clock = Profile03SessionTime(f.line.account, f.line.device, f.line.epoch, routing,
            { elapsed }, { true }, { 2 }, { sent.add(JSONObject(it)); true })
        init {
            check(clock.request())
            clock.accept(JSONObject().put("v", 1).put("type", "payload_profile_session03")
                .put("challenge", sent.single().getString("challenge")).put("account_id", f.line.account)
                .put("device_id", f.line.device).put("connection_epoch", f.line.epoch).put("deployment_epoch", 1)
                .put("session_id", UUID(0, 600)).put("server_time_ms", f.now)
                .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
                .put("line_activation_version", 2).toString().toByteArray())
            elapsed++
        }
        val reader = Profile03CurrentReader(app, f.origins, f.line.db, original.store,
            DevicePayloadKeyStore(app, "zrotext.synthetic.missing.reader.${UUID.randomUUID()}"),
            DeviceSigningKeyStore(app, "zrotext.synthetic.missing.signer.${UUID.randomUUID()}"), clock, { true },
            { _, _, _ -> { error("No interval permission should be requested") } })
        fun projection(): JSONObject = JSONObject().put("v", 1).put("envelope_profile", 3).put("manifest_profile", 3)
            .put("kind", "device_selection03").put("account_id", f.line.account).put("device_id", f.line.device)
            .put("line_id", f.line.line).put("selection_epoch", "1").put("origin_digest", b64(f.origins.protocolDigest()))
            .put("device_session_digest", b64(clock.snapshot()!!.first.deviceSessionDigest(original.devicePoint)))
            .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
            .put("connection_epoch", f.line.epoch.toString()).put("deployment_epoch", "1")
            .put("old_binding_id", f.oldBinding).put("old_binding_generation", "1")
            .put("old_binding_proof_digest", b64(original.bindingDigest)).put("binding_id", f.newBinding)
            .put("binding_generation", "2").put("reader_key_id", b64(original.reader.keyId))
            .put("device_signing_key_id", b64(Profile03RetainedElection.signingId(original.devicePoint)))
            .put("approval_key_id", b64(Profile03RetainedElection.signingId(original.ownerPoint)))
            .put("root_fingerprint", b64(f.fingerprint)).put("trust_generation", "1").put("manifest_version", "2")
            .put("manifest_digest", b64(f.authority.digest)).put("election_digest", b64(original.accepted.electionCommitment))
            .put("election_bundle_sha256", b64(original.accepted.electionBundleSha256)).put("compared_ms", f.now.toString())
            .put("selection_expires_ms", "101000").put("evidence", JSONObject(original.evidence))
            .put("physical_selection", JSONObject().put("kind", "original_v2"))
        fun select(projection: JSONObject = projection()) = reader.deviceSelection(projection.toString().toByteArray(), f.line.line)
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
    }

    @Test fun genuineCurrentAndStoredHttpsElectionReachExistingOnlyCustodyWithTheActualWssSession() {
        Profile03RetainedElectionTest.Fixture().use { v ->
            val h = Harness(v)
            val original = v.f.line.db.profile03Elections().find(v.installed.challengeId)
            assertEquals(v.f.origins.protocolHash, original!!.originHash)
            assertEquals(v.f.origins.routingHash, h.clock.snapshot()!!.first.session.originHash)
            assertNotEquals(original.originHash, h.clock.snapshot()!!.first.session.originHash)
            val failure = assertThrows(Exception::class.java) { h.select() }
            assertTrue(failure.stackTrace.any { it.className == DevicePayloadKeyStore::class.java.name && it.methodName == "existingPublic" })
            assertEquals(original, v.f.line.db.profile03Elections().find(v.installed.challengeId))
            assertNull(v.f.line.db.attempts().getAttempt(v.f.attempt.toString()))
        }
    }

    @Test fun wrongProtocolOrActualSocketHostOrPortRefusesBeforeCustodyWithoutRewritingHistory() {
        Profile03RetainedElectionTest.Fixture().use { v ->
            val correct = Harness(v)
            val wrongProtocol = Profile03Origins.fromProtocol(v.f.line.account, v.f.line.device, "https://other.example.test")
            val failure = assertThrows(IllegalArgumentException::class.java) {
                correct.select(correct.projection().put("origin_digest", Profile03ElectionEncoding.encode(wrongProtocol.protocolDigest()))) }
            assertFalse(failure.stackTrace.any { it.className == DevicePayloadKeyStore::class.java.name })
            for (stream in listOf("wss://other.example.test/device", "wss://gateway.example.test:9443/device")) {
                val wrong = EvidenceIdentity.fromStream(v.f.line.account, v.f.line.device, stream)
                val rejected = assertThrows(IllegalArgumentException::class.java) { Harness(v, wrong.originHash).select() }
                assertFalse(rejected.stackTrace.any { it.className == DevicePayloadKeyStore::class.java.name })
            }
            assertEquals(v.installed, v.f.line.db.profile03Elections().find(v.installed.challengeId))
            assertTrue(v.f.line.db.sealedPreparations().count() == 0)
        }
    }

    @Test fun actualStoredActivationAndSignedElectionKeepTheirOriginalDifferentDomains() {
        Profile03RetainedElectionTest.Fixture().use { v ->
            val proof = v.verify()
            val activation = v.f.line.db.lineActivationsV2().find("sealed", v.activation.challengeId)!!
            assertEquals(v.f.origins.routingHash, activation.originHash)
            assertEquals(v.f.origins.protocolHash, v.installed.originHash)
            assertTrue(proof.original.matchesLocal(activation))
            assertFalse(proof.original.matchesLocal(activation.copy(originHash = v.f.origins.protocolHash)))
            assertThrows(IllegalArgumentException::class.java) {
                v.installed.copy(originHash = v.f.origins.routingHash).requireShape() }
            assertEquals(activation, v.f.line.db.lineActivationsV2().find("sealed", activation.challengeId))
        }
    }
}
