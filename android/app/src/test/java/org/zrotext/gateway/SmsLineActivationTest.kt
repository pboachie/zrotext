// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30])
class SmsLineActivationTest {
    private val account = UUID.fromString("00000000-0000-4000-8000-000000000001")
    private val line = UUID.fromString("00000000-0000-4000-8000-000000000002")
    private val device = UUID.fromString("00000000-0000-4000-8000-000000000003")
    private val challengeId = UUID.fromString("00000000-0000-4000-8000-000000000004")
    private val challenge = SmsLineChallenge(challengeId, account, line, device, 1,
        ByteArray(32) { it.toByte() }, 300_000)

    private val signingKey = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun signer(challenge: SmsLineChallenge, api: Int, selected: Int): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey.private)
            update(SmsLineActivationTranscript.deviceStatement(challenge, api, selected))
            sign()
        }

    /** Reflection also builds the rejected (accepted = false) case, which no frame produces. */
    private fun ack(proof: PreparedSmsLineActivation, accepted: Boolean = true,
                    challenge: UUID = challengeId, signatureDigest: ByteArray =
                        sha256(proof.deviceSignatureDer())): AuthenticatedSmsLineActivationAck {
        val constructor = AuthenticatedSmsLineActivationAck::class.java.declaredConstructors
            .single { it.parameterCount == 8 }.apply { isAccessible = true }
        return constructor.newInstance(accepted, challenge, account, line, device, 1L,
            sha256(proof.deviceStatement()), signatureDigest) as AuthenticatedSmsLineActivationAck
    }

    @Test fun exactSmsStatementMatchesTheServerVectorAndOwnerDigest() {
        val bytes = SmsLineActivationTranscript.deviceStatement(challenge, 28, 7)
        assertEquals(
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f763100" +
                "0000000000004000800000000000000100000000000040008000000000000002" +
                "0000000000004000800000000000000300000000000000010000000000004000" +
                "8000000000000004000102030405060708090a0b0c0d0e0f101112131415" +
                "161718191a1b1c1d1e1f001c0100000007",
            hex(bytes))
        assertFalse(bytes.contentEquals(SmsLineActivationTranscript.deviceStatement(
            challenge.copy(generation = 2), 28, 7)))
        assertFalse(bytes.contentEquals(SmsLineActivationTranscript.deviceStatement(
            challenge.copy(nonce = ByteArray(32) { 9 }), 28, 7)))
        val der = signer(challenge, 28, 7)
        val owner = SmsLineActivationTranscript.ownerStatement(bytes, der)
        assertTrue(owner.toString(Charsets.ISO_8859_1).startsWith(
            "ZTSMS/line/owner-approve/v1\u0000"))
        assertArrayEquals(sha256(der), owner.takeLast(32).toByteArray())
        assertFalse(owner.contentEquals(SmsLineActivationTranscript.ownerStatement(bytes,
            der.copyOf().apply { this[lastIndex] = (last().toInt() xor 1).toByte() })))
    }

    @Test fun proofUsesFreshPhysicalSimAndTheEnrolledDeviceSignatureShape() {
        var now = 1_000L
        var selected = 7
        var active: List<ActiveSimCard>? = listOf(ActiveSimCard(7, 42))
        val producer = SmsLineActivationDevice({ 30 }, { selected }, { active },
            ::signer, { now })
        val proof = producer.prepare(challenge, account, device)!!
        assertEquals(7, proof.selectedSubscriptionId)
        assertEquals(42, proof.sim.cardId)
        assertEquals(proof.sim, proof.simAfterSigning)
        assertArrayEquals(SmsLineActivationTranscript.ownerStatement(proof.deviceStatement(),
            proof.deviceSignatureDer()), proof.ownerStatement())
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(signingKey.public)
            update(proof.deviceStatement())
            assertTrue(verify(proof.deviceSignatureDer()))
        }
        assertNull(producer.prepare(challenge, UUID.randomUUID(), device))
        assertNull(producer.prepare(challenge, account, UUID.randomUUID()))
        selected = 8
        assertNull(producer.prepare(challenge, account, device))
        selected = 7
        active = listOf(ActiveSimCard(7, 42, isEmbedded = true))
        assertNull(producer.prepare(challenge, account, device))
        active = listOf(ActiveSimCard(7, -2))
        assertNull(producer.prepare(challenge, account, device))
        active = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 42))
        assertNull(producer.prepare(challenge, account, device))
        active = null
        assertNull(producer.prepare(challenge, account, device))
        active = listOf(ActiveSimCard(7, 42))
        now = 300_000L
        assertNull(producer.prepare(challenge, account, device))
    }

    @Test fun simChangeDuringSigningStopsProofBeforeOwnerApproval() {
        var active = listOf(ActiveSimCard(7, 42))
        val producer = SmsLineActivationDevice({ 30 }, { 7 }, { active },
            { challenge, api, selected ->
                val der = signer(challenge, api, selected)
                active = listOf(ActiveSimCard(7, 43))
                der
            }, { 1_000 })
        assertNull(producer.prepare(challenge, account, device))
    }

    @Test fun invalidChallengeAndMutableNonceCannotChangePreparedProof() {
        val producer = SmsLineActivationDevice({ 30 }, { 7 },
            { listOf(ActiveSimCard(7, 42)) }, ::signer, { 1_000 })
        assertNull(producer.prepare(challenge.copy(generation = 0), account, device))
        assertNull(producer.prepare(challenge.copy(nonce = ByteArray(31)), account, device))
        assertNull(producer.prepare(challenge.copy(expiresAtMs = 302_000), account, device))
        assertNull(producer.prepare(challenge.copy(lineId = UUID(0, 0)), account, device))
        val mutable = challenge.copy(nonce = challenge.nonce.copyOf())
        val proof = producer.prepare(mutable, account, device)!!
        val statement = proof.deviceStatement()
        mutable.nonce[0] = 99
        proof.challenge.nonce[1] = 99
        assertArrayEquals(statement, proof.deviceStatement())
        assertArrayEquals(statement, SmsLineActivationTranscript.deviceStatement(
            proof.challenge, proof.apiLevel, proof.selectedSubscriptionId))
    }

    @Test fun confirmationMustMatchSignedProofAndFreshSimBeforeLocalInstallation() {
        var now = 1_000L
        var selected = 7
        var active: List<ActiveSimCard>? = listOf(ActiveSimCard(7, 42))
        val producer = SmsLineActivationDevice({ 30 }, { selected }, { active },
            ::signer, { now })
        val proof = producer.prepare(challenge, account, device)!!
        val confirmation = ack(proof)
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            assertTrue(dao.recordLocalWithdrawal("a".repeat(64), "b".repeat(64),
                InboundClassification.OPT_OUT, 7, active, now))
            assertNull(dao.localWithdrawal("a".repeat(64))?.lineId)
            assertTrue(dao.isRecipientSuppressed("b".repeat(64)))
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof,
                ack(proof, accepted = false), account, device))
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof,
                ack(proof, challenge = UUID.randomUUID()), account, device))
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof,
                ack(proof, signatureDigest = ByteArray(32)), account, device))
            active = listOf(ActiveSimCard(7, 43))
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
            active = listOf(ActiveSimCard(7, 42, isEmbedded = true))
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
            active = listOf(ActiveSimCard(7, 42))
            selected = 8
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
            selected = 7
            assertNull(dao.currentLineBinding())
            now = 2_000L
            assertTrue(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
            assertEquals(42, dao.currentLineBinding()?.cardId)
            assertEquals(1L, dao.currentLineBinding()?.generation)
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
            assertNull(dao.localWithdrawal("a".repeat(64))?.lineId)
            now = 300_000L
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, confirmation,
                account, device))
        } finally { db.close() }
    }

    @Test fun api28CannotPrepareDespiteServerWireFloorAndSyntheticSim() {
        val producer = SmsLineActivationDevice({ 28 }, { 7 },
            { listOf(ActiveSimCard(7, 42)) }, ::signer, { 1_000 })
        assertNull(producer.prepare(challenge, account, device))
    }

    @Test fun exactSelectedPhysicalSimPreparesAndInstallsWithUnrelatedSecondSim() {
        val active = listOf(ActiveSimCard(8, 43, true), ActiveSimCard(7, 42))
        val producer = SmsLineActivationDevice({ 30 }, { 7 }, { active }, ::signer, { 1_000 })
        val proof = checkNotNull(producer.prepare(challenge, account, device))
        assertEquals(ActivatedSimCard(7, 42), proof.sim)
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            assertTrue(producer.installAfterAuthenticatedAck(db.attempts(), proof, ack(proof), account, device))
            assertEquals(7, db.attempts().currentLineBinding()?.subscriptionId)
            assertEquals(42, db.attempts().currentLineBinding()?.cardId)
        } finally { db.close() }
    }

    @Test fun unrelatedPeerChangeDuringSigningDoesNotChangeChosenStatement() {
        var active = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
        val producer = SmsLineActivationDevice({ 30 }, { 7 }, { active }, { c, api, selected ->
            signer(c, api, selected).also { active = listOf(ActiveSimCard(9, null, true), ActiveSimCard(7, 42)) }
        }, { 1_000 })
        val proof = checkNotNull(producer.prepare(challenge, account, device))
        assertEquals(ActivatedSimCard(7, 42), proof.simAfterSigning)
        assertArrayEquals(SmsLineActivationTranscript.deviceStatement(challenge, 30, 7), proof.deviceStatement())
    }

    @Test fun dualSimSelectionLossOrSelectedCollisionDuringSigningRefusesPublication() {
        for (mutation in 0..2) {
            var selected = 7
            var active = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
            val producer = SmsLineActivationDevice({ 30 }, { selected }, { active }, { c, api, sub ->
                signer(c, api, sub).also {
                    when (mutation) {
                        0 -> selected = 8
                        1 -> active = listOf(ActiveSimCard(8, 43))
                        else -> active = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 42))
                    }
                }
            }, { 1_000 })
            assertNull(producer.prepare(challenge, account, device))
        }
    }

    @Test fun selectedMutationOrExpiryAfterActualDaoWriteCannotClaimLiveInstallation() {
        for (mutation in 0..2) {
            val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
                SmsJournalDatabase::class.java).allowMainThreadQueries().build()
            try {
                val dao = db.attempts()
                var selected = 7
                var active = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
                var now = 1_000L
                val producer = SmsLineActivationDevice({ 30 }, { selected }, {
                    // Observe a real committed binding before injecting the post-storage loss.
                    if (dao.currentLineBinding() != null) when (mutation) {
                        0 -> selected = 8
                        1 -> active = listOf(ActiveSimCard(7, 44), ActiveSimCard(8, 43))
                        else -> now = challenge.expiresAtMs + SmsLineActivationDevice.ACK_GRACE_MS
                    }
                    active
                }, ::signer, { now })
                val proof = checkNotNull(producer.prepare(challenge, account, device))
                assertFalse(producer.installAfterAuthenticatedAck(dao, proof, ack(proof), account, device))
                // The durable record is still the exact proof; it is never replaced with the peer.
                assertEquals(7, dao.currentLineBinding()?.subscriptionId)
                assertEquals(42, dao.currentLineBinding()?.cardId)
            } finally { db.close() }
        }
    }

    @Test fun selectionChangeInsideInitialObservationNeverSignsStaleChosenSubscription() {
        var selected = 7
        var signatures = 0
        val producer = SmsLineActivationDevice({ 30 }, { selected }, {
            selected = 8
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
        }, { c, api, subscription -> signatures++; signer(c, api, subscription) }, { 1_000 })
        assertNull(producer.prepare(challenge, account, device))
        assertEquals(0, signatures)
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
    @Test @Config(sdk = [34]) fun selectedEsimNeedsDurableProofAndExactAckThenRetiresOnAnyCallback() {
        EsimProfileFixture().use { f ->
            val producer = SmsLineActivationDevice({ 34 }, { 7 }, f::cards, ::signer, { 1000 })
            val proof = checkNotNull(producer.prepare(challenge, account, device))
            assertEquals(f.candidate, proof.sim.profile)
            val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
                .allowMainThreadQueries().build()
            try {
                assertFalse(producer.installAfterAuthenticatedAck(db.attempts(), proof, ack(proof, false), account, device))
                assertNull(db.attempts().currentLineBinding())
                assertTrue(producer.installAfterAuthenticatedAck(db.attempts(), proof, ack(proof), account, device))
                val binding = checkNotNull(db.attempts().currentLineBinding())
                assertEquals("esim", binding.continuityKind)
                assertTrue(binding.liveContinuity())
                f.tracker.onSubscriptionsChanged()
                assertFalse(binding.liveContinuity())
                assertNull(producer.prepare(challenge, account, device))
            } finally { db.close() }
        }
    }
    @Test @Config(sdk = [34]) fun expiryDuringReservationRefusesBeforeSignatureAndCrashCannotRenewChallenge() {
        EsimProfileFixture().use { f ->
            var now = 1000L; var signatures = 0
            f.afterWrite = { now = challenge.expiresAtMs }
            val producer = SmsLineActivationDevice({ 34 }, { 7 }, f::cards,
                { c, api, sub -> signatures++; signer(c, api, sub) }, { now })
            assertNull(producer.prepare(challenge, account, device))
            assertEquals(0, signatures)
            // Same disk denial, different facade: no live association can be reconstructed.
            val store = object : ProfileChallengePersistence {
                override fun read() = f.ledger
                override fun write(value: ProfileChallengeLedger): Boolean { f.ledger = value; return true }
            }
            val key = ProfileChallengeKey(ProfileLineAuthority(account.toString(), device.toString(), line.toString(), 1),
                challengeId.toString())
            assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key, f.candidate))
        }
    }
    @Test @Config(sdk = [34]) fun throwingPostpublicationObservationRevokesTheExactInstalledCapability() {
        EsimProfileFixture().use { f ->
            val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
                .allowMainThreadQueries().build()
            try {
                val producer = SmsLineActivationDevice({ 34 }, { 7 }, {
                    if (db.attempts().currentLineBinding()?.installedProfile() != null) error("Synthetic final read failure")
                    f.cards()
                }, ::signer, { 1000 })
                val proof = checkNotNull(producer.prepare(challenge, account, device))
                assertFalse(producer.installAfterAuthenticatedAck(db.attempts(), proof, ack(proof), account, device))
                assertEquals("esim", db.attempts().currentLineBinding()?.continuityKind)
                assertNull(db.attempts().currentLineBinding()?.installedProfile())
            } finally { db.close() }
        }
    }

}
