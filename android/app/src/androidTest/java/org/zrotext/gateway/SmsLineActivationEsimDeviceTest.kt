// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/** Real public subscription reads only; throwaway software signer and RAM ledger, never radio. */
@RunWith(AndroidJUnit4::class)
class SmsLineActivationEsimDeviceTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    @Test fun explicitlySelectedCurrentEsimUsesProfileLeaseWithoutDefaultOrPeerFallback() {
        assumeTrue("requires API33+ public port mapping", android.os.Build.VERSION.SDK_INT >= 33)
        InstrumentationRegistry.getInstrumentation().runOnMainSync { SimProfileContinuity.initialize(context) }
        val until = android.os.SystemClock.elapsedRealtime() + 3000
        var cards = SimCardContinuity.observe(context)
        while (android.os.SystemClock.elapsedRealtime() < until &&
            cards?.none { it.isEmbedded && it.profileCandidate?.isCurrent() == true } != false) {
            Thread.sleep(50); cards = SimCardContinuity.observe(context)
        }
        val observed = cards
        val selected = observed?.firstOrNull { it.isEmbedded && it.profileCandidate?.isCurrent() == true }
        assumeTrue("requires readable, coherently observed active eSIM profile", selected != null)
        val chosen = checkNotNull(selected)
        val candidate = checkNotNull(SimCardContinuity.activationCandidate(observed, chosen.subscriptionId))
        assertNotNull(candidate.profile)
        assertNull(SimCardContinuity.activationCandidate(observed, Int.MAX_VALUE))
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        var ledger = ProfileChallengeLedger()
        val fence = ProfileChallengeFence(object : ProfileChallengePersistence {
            override fun read() = ledger
            override fun write(value: ProfileChallengeLedger): Boolean { ledger = value; return true }
        })
        var signatures = 0
        val device = SmsLineActivationDevice({ android.os.Build.VERSION.SDK_INT }, { chosen.subscriptionId },
            { SimCardContinuity.observe(context) }, { c, api, subscription ->
                signatures++
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(keys.private); update(SmsLineActivationTranscript.deviceStatement(c, api, subscription)); sign()
                }
            }, System::currentTimeMillis, { fence })
        val account = UUID(0, 10); val deviceId = UUID(0, 13)
        val challenge = SmsLineChallenge(UUID.randomUUID(), account, UUID(0, 11), deviceId, 1,
            ByteArray(32) { 7 }, System.currentTimeMillis() + 240000)
        val proof = checkNotNull(device.prepare(challenge, account, deviceId))
        assertEquals(chosen.subscriptionId, proof.selectedSubscriptionId)
        assertEquals(1, signatures)
        assertTrue(checkNotNull(proof.sim.profile).isCurrent())
        // No installation/ACK, no app signing alias, no durable app ledger, no SMS operation.
    }
}
