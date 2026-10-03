// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class SealedLineActivationFramesTest {
    private fun reject(action: () -> Unit) { assertTrue(runCatching(action).isFailure) }
    @Test fun challengeRequiresExactFieldsCanonicalUuidAndIntegerVersionEpochGenerationAndExpiry() {
        val f = SealedLineActivationFixture()
        val frame = SealedLineActivationFrames.challengeFrame(f.challenge)
        assertEquals(42L, SealedLineActivationFrames.challenge(frame).connectionEpoch)
        for (key in listOf("v", "connection_epoch", "generation", "expires_at_ms")) {
            for (value in listOf(1.0, "1", true, JSONObject.NULL, -1)) {
                val changed = JSONObject(frame.toString()).put(key, value)
                reject { SealedLineActivationFrames.challenge(changed) }
            }
        }
        for (key in listOf("challenge_id", "account_id", "line_id", "device_id")) {
            reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).put(key, "00000000-0000-0000-0000-000000000000")) }
            reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).put(key, 1)) }
        }
        reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).put("type", "sms_line_challenge")) }
        reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).put("unexpected", 1)) }
        reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).also { it.remove("connection_epoch") }) }
    }
    @Test fun canonicalUnpaddedNonceAndExactP256DerAreRequired() {
        val f = SealedLineActivationFixture()
        val frame = SealedLineActivationFrames.challengeFrame(f.challenge)
        val nonce = frame.getString("nonce")
        for (value in listOf("", nonce + "=", nonce.dropLast(1), "A".repeat(5000),
            SealedLineActivationFrames.encode(ByteArray(32)))) {
            reject { SealedLineActivationFrames.challenge(JSONObject(frame.toString()).put("nonce", value)) }
        }
        reject { SealedLineActivationTranscript.requireCanonicalDer(byteArrayOf(0x30, 6, 2, 1, 0, 2, 1, 1)) }
        reject { SealedLineActivationTranscript.requireCanonicalDer(byteArrayOf(0x30, 7, 2, 2, 0, 1, 2, 1, 1)) }
        val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        reject { SealedLineActivationTranscript.requireCanonicalDer(proof.signature() + 0) }
        val emitted = JSONObject(SealedLineActivationFrames.proof(proof))
        assertEquals("sealed_line_proof", emitted.getString("type"))
        assertEquals(31, emitted.getInt("android_api_level")); assertEquals(1, emitted.getInt("active_subscription_count"))
        assertArrayEquals(proof.signature(), SealedLineActivationFrames.variableBytes(emitted, "signature_der", 8, 72))
    }
    @Test fun proofAndInstallAcksAreStrictAndNotInterchangeable() {
        val f = SealedLineActivationFixture()
        val ack = JSONObject().put("v", 1).put("type", "sealed_line_proof_ack").put("connection_epoch", 42L)
            .put("challenge_id", f.challenge.challengeId.toString()).put("accepted", true)
        assertTrue(SealedLineActivationFrames.proofAck(ack).accepted)
        reject { SealedLineActivationFrames.installAck(ack) }
        for (value in listOf("true", 1, JSONObject.NULL)) {
            reject { SealedLineActivationFrames.proofAck(JSONObject(ack.toString()).put("accepted", value)) }
        }
        reject { SealedLineActivationFrames.proofAck(JSONObject(ack.toString()).put("v", 1.0)) }
        reject { SealedLineActivationFrames.proofAck(JSONObject(ack.toString()).put("connection_epoch", 42.0)) }
        assertTrue(SealedLineActivationFrames.installAck(JSONObject(ack.toString()).put("type", "sealed_line_install_ack")).accepted)
    }
    @Test fun activatedAndInstalledHaveExactOriginalDigestsAndFreshEpoch() {
        val f = SealedLineActivationFixture(); val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        val ack = f.receipt(proof.signature())
        val frame = SealedLineActivationFrames.receiptFrame(ack)
        assertTrue(SealedLineActivationFrames.activated(frame).matches(proof))
        for (key in listOf("device_statement_sha256", "device_signature_sha256")) {
            reject { SealedLineActivationFrames.activated(JSONObject(frame.toString()).put(key, "AA")) }
        }
        reject { SealedLineActivationFrames.activated(JSONObject(frame.toString()).put("generation", 7.0)) }
        reject { SealedLineActivationFrames.activated(JSONObject(frame.toString()).put("extra", true)) }
        reject { SealedLineActivationFrames.installed(ack, 43) }
        val installed = JSONObject(SealedLineActivationFrames.installed(ack, 42))
        assertEquals("sealed_line_installed", installed.getString("type"))
        assertEquals(frame.keys().asSequence().toSet(), installed.keys().asSequence().toSet())
        assertEquals(frame.getString("device_signature_sha256"), installed.getString("device_signature_sha256"))
    }
}
