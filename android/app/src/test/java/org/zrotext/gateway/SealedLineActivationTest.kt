// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class SealedLineActivationTest {
    @Test fun transcriptMatchesIndependentRustFieldOrderAndNeverSmsDomain() {
        val f = SealedLineActivationFixture()
        val expected = "5a5453452f6c696e652f6465766963652d636f6e6669726d2f763100" +
            "00000000000000000000000000000001" + "00000000000000000000000000000002" +
            "00000000000000000000000000000003" + "0000000000000007" +
            "00000000000000000000000000000004" + "05".repeat(32) + "001f0100000007"
        val statement = SealedLineActivationTranscript.deviceStatement(f.challenge, 31, 7)
        assertEquals(expected, statement.joinToString("") { "%02x".format(it.toInt() and 255) })
        val sms = SmsLineActivationTranscript.deviceStatement(SmsLineChallenge(f.challenge.challengeId,
            f.challenge.accountId, f.challenge.lineId, f.challenge.deviceId, f.challenge.generation,
            f.challenge.nonce, f.challenge.expiresAtMs), 31, 7)
        assertFalse(statement.contentEquals(sms))
        val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        assertFalse(SealedLineActivationTranscript.verify(f.point, sms, proof.signature()))
    }
    @Test fun api30AmbiguousSelectedEmbeddedMissingOrDifferentSimNeverSigns() {
        val f = SealedLineActivationFixture()
        f.api = 30; assertNull(f.device.prepare(f.challenge, f.selection))
        f.api = 31
        for (cards in listOf(null, emptyList(), listOf(ActiveSimCard(7, null)),
            listOf(ActiveSimCard(7, 42, true)), listOf(ActiveSimCard(8, 42)),
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 42)))) {
            f.cards = cards; assertNull(f.device.prepare(f.challenge, f.selection))
        }
        assertEquals(0, f.signatures)
    }
    @Test fun wrongIndependentSelectionSignerFutureOrExpiredChallengeNeverSigns() {
        val f = SealedLineActivationFixture()
        for (c in listOf(f.challenge.copy(accountId = UUID(0, 8)), f.challenge.copy(deviceId = UUID(0, 8)),
            f.challenge.copy(lineId = UUID(0, 8)), f.challenge.copy(generation = 8),
            f.challenge.copy(expiresAtMs = f.now), f.challenge.copy(expiresAtMs = f.now + 300_001))) {
            assertNull(f.device.prepare(c, f.selection))
        }
        f.point[4] = (f.point[4].toInt() xor 1).toByte()
        assertNull(f.device.prepare(f.challenge, f.selection)); assertEquals(0, f.signatures)
    }
    @Test fun expirySelectionOrCardChangeDuringSigningDeclines() {
        for (mutation in 0..2) {
            val f = SealedLineActivationFixture()
            f.afterSign = { when (mutation) {
                0 -> f.now = f.challenge.expiresAtMs
                1 -> f.selected = 8
                else -> f.cards = listOf(ActiveSimCard(7, 43))
            } }
            assertNull(f.device.prepare(f.challenge, f.selection))
        }
    }
    @Test fun preparedNonceSignatureAndReceiptDigestsAreDefensiveCopies() {
        val f = SealedLineActivationFixture()
        val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        val bytes = proof.statement(); val signature = proof.signature()
        f.challenge.nonce[0] = 99; proof.challenge.nonce[1] = 99
        proof.statement()[0] = 99; proof.signature()[0] = 99; proof.fingerprint()[0] = 99
        assertArrayEquals(bytes, proof.statement()); assertArrayEquals(signature, proof.signature())
        assertEquals(5.toByte(), proof.challenge.nonce[0])
    }
    @Test fun exactProofAckRequiredAndWrongEpochCannotInstall() {
        val f = SealedLineActivationFixture(); val p = f.provider()
        val frame = checkNotNull(p.accept(SealedLineActivationFrames.Incoming.Challenge(f.challenge)))
        val signature = SealedLineActivationFrames.variableBytes(org.json.JSONObject(frame), "signature_der", 8, 72)
        val ack = f.receipt(signature)
        assertNull(p.accept(f.activated(ack)))
        p.accept(SealedLineActivationFrames.Incoming.ProofAck(SealedLineActivationFrames.Ack(43, ack.challengeId, true)))
        assertNull(p.accept(f.activated(ack)))
        p.accept(SealedLineActivationFrames.Incoming.ProofAck(SealedLineActivationFrames.Ack(42, ack.challengeId, true)))
        assertNull(p.accept(f.activated(f.reepoch(ack, 43))))
        assertTrue(f.events.isEmpty())
    }
    @Test fun installBeforeCommitAndExactServerAckConfirmsOnlyReceipt() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        assertNotNull(p.accept(f.activated(ack)))
        assertEquals(listOf("install", "commit"), f.events)
        assertFalse(p.installationReceiptConfirmed())
        p.accept(SealedLineActivationFrames.Incoming.InstallAck(SealedLineActivationFrames.Ack(43, ack.challengeId, true)))
        assertFalse(p.installationReceiptConfirmed())
        p.accept(SealedLineActivationFrames.Incoming.InstallAck(SealedLineActivationFrames.Ack(42, ack.challengeId, true)))
        assertTrue(p.installationReceiptConfirmed())
        f.cards = listOf(ActiveSimCard(7, 43)); assertFalse(p.installationReceiptConfirmed())
    }
    @Test fun failedInstallOrCommitNeverSendsOrClaimsReadyAndCommitRetryIsExact() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        f.installOk = false; assertNull(p.accept(f.activated(ack)))
        assertEquals(listOf("install"), f.events); assertNull(f.stored)
        f.installOk = true; f.commitOk = false
        assertNull(p.accept(f.activated(ack))); assertNull(f.stored); assertFalse(p.installationReceiptConfirmed())
        f.commitOk = true; assertNotNull(p.accept(f.activated(ack)))
        assertTrue(checkNotNull(f.stored).receipt.matches(checkNotNull(f.installedProof)))
    }
    @Test fun lifecycleLossAfterDaoInstallDoesNotCommitOrSendReceipt() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        f.afterInstall = { f.current = false }
        assertNull(p.accept(f.activated(ack))); assertEquals(listOf("install"), f.events)
        assertNull(f.stored); assertFalse(p.installationReceiptConfirmed())
    }
    @Test fun coldStartWithoutExactDurableProofNeverTrustsLineGenerationAlone() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        f.commitOk = false; assertNull(p.accept(f.activated(ack)))
        assertNotNull(f.installedProof); p.close()
        val next = f.provider(43)
        assertNull(next.accept(f.activated(f.reepoch(ack, 43))))
        assertNull(f.stored)
    }
    @Test fun durableExactProofRecoveryRequiresFreshEpochAndPreservesOriginalDigests() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        assertNotNull(p.accept(f.activated(ack))); p.close()
        val next = f.provider(43)
        assertNull(next.accept(f.activated(ack)))
        val encoded = checkNotNull(next.accept(f.activated(f.reepoch(ack, 43))))
        val frame = org.json.JSONObject(encoded)
        assertEquals(43L, frame.getLong("connection_epoch"))
        assertEquals("sealed_line_installed", frame.getString("type"))
        assertArrayEquals(ack.signatureDigest(), SealedLineActivationFrames.bytes(frame, "device_signature_sha256", 32))
        assertEquals(42L, checkNotNull(f.stored).proof.challenge.connectionEpoch)
        assertEquals(43L, checkNotNull(f.stored).receipt.connectionEpoch)
    }
    @Test fun recoveryRejectsSignatureDigestSimSignerSelectionExpiryAndClosedSessionChanges() {
        for (mutation in 0..5) {
            val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
            assertNotNull(p.accept(f.activated(ack))); p.close()
            val next = f.provider(43)
            var candidate = f.reepoch(ack, 43)
            when (mutation) {
                0 -> candidate = SealedLineActivationReceipt(43, ack.challengeId, ack.accountId, ack.lineId,
                    ack.deviceId, ack.generation, ack.statementDigest(), ByteArray(32))
                1 -> f.cards = listOf(ActiveSimCard(7, 43))
                2 -> f.point[4] = (f.point[4].toInt() xor 1).toByte()
                3 -> f.selected = 8
                4 -> f.now = f.challenge.expiresAtMs + SealedLineActivationTranscript.ACK_GRACE_MS
                else -> next.close()
            }
            assertNull(next.accept(f.activated(candidate)))
        }
    }
    @Test fun heldFinalSignerReadCrossingExpiryNeverPublishesPreparedProof() {
        val f = SealedLineActivationFixture()
        // Read three is the additional hardware identity comparison after validate completed.
        f.duringPointRead = { if (f.pointReads == 3) f.now = f.challenge.expiresAtMs }
        assertNull(f.device.prepare(f.challenge, f.selection))
        assertEquals(1, f.signatures)
    }
    @Test fun heldSignerProviderCrossingAckGracePreventsDaoInstallAndReceiptCommit() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        f.duringPointRead = { f.now = f.challenge.expiresAtMs + SealedLineActivationTranscript.ACK_GRACE_MS }
        assertNull(p.accept(f.activated(ack)))
        assertTrue(f.events.isEmpty()); assertNull(f.installedProof); assertNull(f.stored)
    }
    @Test fun backwardsClockDuringProviderWorkRefusesValidation() {
        val f = SealedLineActivationFixture(); val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        f.duringPointRead = { f.now -= 1 }
        assertFalse(f.device.validate(proof, f.selection, true))
    }

    @Test fun exactSelectedPhysicalSimWithEmbeddedPeerCompletesDurableAckPath() {
        val f = SealedLineActivationFixture()
        f.cards = listOf(ActiveSimCard(8, 43, true), ActiveSimCard(7, 42))
        val provider = f.provider()
        val (_, ack) = f.start(provider)
        assertNotNull(provider.accept(f.activated(ack)))
        assertEquals(ActivatedSimCard(7, 42), f.installedProof?.sim)
        assertEquals(listOf("install", "commit"), f.events)
        assertFalse(provider.installationReceiptConfirmed())
        provider.accept(SealedLineActivationFrames.Incoming.InstallAck(
            SealedLineActivationFrames.Ack(42, ack.challengeId, true)))
        assertTrue(provider.installationReceiptConfirmed())
        f.cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(9, null, true))
        assertTrue(provider.installationReceiptConfirmed())
    }

    @Test fun unrelatedPeerChangeDuringSigningPreservesSelectedPhysicalProof() {
        val f = SealedLineActivationFixture()
        f.cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
        f.afterSign = { f.cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(9, -1)) }
        val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        assertEquals(ActivatedSimCard(7, 42), proof.sim)
        assertEquals(1, f.signatures)
    }

    @Test fun selectedLossDuringStorageCannotCommitReceiptOrClaimReadyWithPeerPresent() {
        for (mutation in 0..2) {
            val f = SealedLineActivationFixture()
            f.cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
            val provider = f.provider(); val (_, ack) = f.start(provider)
            f.afterInstall = { when (mutation) {
                0 -> f.selected = 8
                1 -> f.cards = listOf(ActiveSimCard(8, 43))
                else -> f.cards = listOf(ActiveSimCard(7, 44), ActiveSimCard(8, 43))
            } }
            assertNull(provider.accept(f.activated(ack)))
            assertEquals(listOf("install"), f.events)
            assertNull(f.stored)
            assertFalse(provider.installationReceiptConfirmed())
        }
    }

    @Test fun selectedChangeInsideFinalObservationRefusesValidatedProof() {
        val f = SealedLineActivationFixture()
        val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        var observations = 0
        val device = SealedLineActivationDevice({ 31 }, { f.selected }, {
            observations++
            if (observations == 2) f.selected = 8
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
        }, { f.point }, { _, _, _, _ -> error("Validation must not sign") }, { f.now })
        assertFalse(device.validate(proof, f.selection, true))
        assertEquals(2, observations)
    }
}
