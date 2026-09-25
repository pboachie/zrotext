// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Opt-in owner-pairing probe against a private loopback HTTPS writer. */
@RunWith(AndroidJUnit4::class)
class LocalPairingDeviceTest {
    @Test fun claimAndProveWithOnDeviceKeystore() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires a private local pairing fixture", args.getString("m1LocalPairing") == "true")
        val pairingId = args.getString("m1PairingId")
        val token = args.getString("m1PairingToken")
        assumeTrue("requires a pairing ID and one-use token", !pairingId.isNullOrBlank() && !token.isNullOrBlank())
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val proof = PairingClient(DeviceSigningKeyStore(app)).claimAndProve(
            "https://localhost:8443", pairingId!!, token!!
        )
        assertTrue(proof.comparisonCode.matches(Regex("[0-9]{8}")))
        assertTrue(proof.fingerprintHex.matches(Regex("[A-F0-9]{64}")))
        File(app.filesDir, "m1-local-pairing-proof.json").writeText(
            JSONObject().put("comparison_code", proof.comparisonCode)
                .put("key_fingerprint", proof.fingerprintHex)
                .put("key_security", proof.keySecurity.name).toString()
        )
    }
}
