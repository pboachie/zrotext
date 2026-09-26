// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.util.Log
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

/**
 * No-radio physical-SIM activation and continuity on real hardware. It uses a throwaway
 * software key and an in-memory journal, so it never touches the app's device key or data,
 * and it never sends an SMS. Only the line count and embedded flags are logged.
 *
 * Pass `-e expected_sub N -e expected_card M` (from an earlier run's local logcat) to check
 * continuity after a reboot or SIM swap; without them that check is skipped.
 */
@RunWith(AndroidJUnit4::class)
class SmsLineActivationPhysicalSimDeviceTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val args = InstrumentationRegistry.getArguments()
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val account = UUID.fromString("00000000-0000-4000-8000-00000000000a")
    private val line = UUID.fromString("00000000-0000-4000-8000-00000000000b")
    private val deviceId = UUID.fromString("00000000-0000-4000-8000-00000000000d")
    private val challengeId = UUID.fromString("00000000-0000-4000-8000-00000000000e")

    private fun observeSinglePhysical(): ActivatedSimCard {
        val observed = SimCardContinuity.observe(context)
        Log.i("ZTSimCheck", "observed=${observed?.size} embedded=${observed?.map { it.isEmbedded }}")
        assumeTrue("needs readable telephony with exactly one active physical SIM",
            observed != null && observed.size == 1 && !observed.single().isEmbedded)
        val candidate = SimCardContinuity.activationCandidate(observed)
        assertNotNull("a single physical SIM with a readable card ID must be eligible", candidate)
        // Local-only continuity reference for the reboot/swap run; never recorded elsewhere.
        Log.i("ZTSimCheck", "reference expected_sub=${candidate!!.subscriptionId} expected_card=${candidate.cardId}")
        return candidate
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    @Test fun physicalSimActivatesInstallsAndStaysContinuousWithoutRadio() {
        val candidate = observeSinglePhysical()
        val softwareKey = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        var signed = 0
        val device = SmsLineActivationDevice(
            apiLevel = { android.os.Build.VERSION.SDK_INT },
            selectedSubscriptionId = { candidate.subscriptionId },
            observe = { SimCardContinuity.observe(context) },
            sign = { challenge, api, selected ->
                signed += 1
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(softwareKey.private)
                    update(SmsLineActivationTranscript.deviceStatement(challenge, api, selected))
                    sign()
                }
            },
            nowMs = System::currentTimeMillis
        )
        val challenge = SmsLineActivationFrames.challenge(JSONObject().put("v", 1)
            .put("type", "sms_line_challenge").put("challenge_id", challengeId.toString())
            .put("account_id", account.toString()).put("line_id", line.toString())
            .put("device_id", deviceId.toString()).put("generation", 1)
            .put("nonce", b64.encodeToString(ByteArray(32) { 7 }))
            .put("expires_at_ms", System.currentTimeMillis() + 240_000))
        val proof = device.prepare(challenge, account, deviceId)
        assertNotNull("the physical SIM must produce a signed declaration", proof)
        assertEquals(1, signed)
        assertEquals(candidate, proof!!.sim)
        assertEquals(proof.sim, proof.simAfterSigning)
        assertEquals(candidate.subscriptionId, proof.selectedSubscriptionId)

        val ack = SmsLineActivationFrames.activated(JSONObject().put("v", 1)
            .put("type", "sms_line_activated").put("challenge_id", challengeId.toString())
            .put("account_id", account.toString()).put("line_id", line.toString())
            .put("device_id", deviceId.toString()).put("generation", 1)
            .put("device_statement_sha256", b64.encodeToString(sha256(proof.deviceStatement())))
            .put("device_signature_sha256", b64.encodeToString(sha256(proof.deviceSignatureDer()))))
        assertTrue(ack.matches(proof))

        val db = Room.inMemoryDatabaseBuilder(context, SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            assertTrue("a matching ack must install the binding",
                device.installAfterAuthenticatedAck(dao, proof, ack, account, deviceId))
            val binding = dao.currentLineBinding()
            assertNotNull(binding)
            assertEquals(candidate.cardId, binding!!.cardId)
            assertEquals(candidate.subscriptionId, binding.subscriptionId)
            assertTrue(ack.isInstalledAs(binding))
            // A fresh telephony read still matches the installed card.
            assertTrue(SimCardContinuity.matches(candidate, SimCardContinuity.observe(context)))
            // A replayed ack cannot install twice.
            assertFalse(device.installAfterAuthenticatedAck(dao, proof, ack, account, deviceId))
        } finally { db.close() }
    }

    @Test fun activatedCardStillMatchesAfterRebootOrSwap() {
        val sub = args.getString("expected_sub")?.toIntOrNull()
        val card = args.getString("expected_card")?.toIntOrNull()
        assumeTrue("pass expected_sub and expected_card from an earlier run", sub != null && card != null)
        val observed = SimCardContinuity.observe(context)
        Log.i("ZTSimCheck", "continuity observed=${observed?.size} embedded=${observed?.map { it.isEmbedded }}")
        val same = SimCardContinuity.matches(ActivatedSimCard(sub!!, card!!), observed)
        Log.i("ZTSimCheck", "continuity matches=$same")
        val expectMatch = args.getString("expect_match")?.toBooleanStrictOrNull() ?: true
        assertEquals("continuity after reboot (true) or a different SIM (false)", expectMatch, same)
    }
}
