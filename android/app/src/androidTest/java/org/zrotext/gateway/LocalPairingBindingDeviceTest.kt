// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/** Opt-in real-client handoff probe. Requires a disposable owner and localhost HTTPS writer. */
@RunWith(AndroidJUnit4::class)
class LocalPairingBindingDeviceTest {
    private val app: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val keys get() = DeviceSigningKeyStore(app)

    @Before fun requirePrivateFixtureAndNoRadioPermission() {
        assumeTrue("requires a private setup handoff fixture",
            InstrumentationRegistry.getArguments().getString("setupHandoff") == "true")
        check(BuildConfig.DEBUG) { "Debug fixture only" }
        assertNoStartOrRadioPermission()
        for (name in listOf(RECEIPT, "$RECEIPT.tmp")) {
            val old = File(app.filesDir, name)
            check(!old.exists() || old.delete()) { "Could not retire previous private fixture receipt" }
        }
    }

    @Test fun claimBrowserQrAndReadPending() {
        // The one-use input is the exact browser QR payload, never a separately
        // supplied device ID, trust endpoint, approval or signing credential.
        assertNull("Resolve the saved attempt before claiming another", PairingLocatorStore.read(app))
        val input = File(app.filesDir, QR_INPUT)
        check(input.isFile && input.length() in 1..AndroidPairingQrPayload.MAX_UTF8_BYTES.toLong())
        val raw = input.readBytes()
        check(input.delete()) { "Could not retire one-use fixture input" }
        val payload = try { AndroidPairingQrPayload.parse(raw) } finally { raw.fill(0) }
        val proof = try {
            check(payload.origin == ORIGIN) { "QR cannot choose trusted service" }
            val claim = payload.takeClaimInputs { true }
            try {
                claim.use { origin, pairing, token ->
                    PairingClient(keys) { selected, id, fingerprint ->
                        check(selected == ORIGIN)
                        check(PairingLocatorStore.save(app, PairingLocator(selected, id, fingerprint)))
                    }.claimAndProve(origin, pairing, token)
                }
            } finally { claim.close() }
        } finally { payload.close() }
        val locator = savedLocator()
        assertEquals(proof.fingerprintHex, locator.fingerprint)
        val binding = PairingBindingClient(keys).read(locator)
        assertEquals(PairingBindingStatus.PENDING, binding.status)
        assertEquals(proof.comparisonCode, binding.comparisonCode)
        assertNull(binding.deviceId)
        receipt("claim_pending", locator, "pending", binding)
    }

    @Test fun readSavedPairingPending() = readExpected("read_pending", PairingBindingStatus.PENDING)

    @Test fun readSavedPairingApproved() = readExpected("read_approved", PairingBindingStatus.APPROVED)

    @Test fun readSavedPairingCancelled() = readExpected("read_cancelled", PairingBindingStatus.CANCELLED)

    @Test fun readSavedPairingExpired() = readExpected("read_expired", PairingBindingStatus.EXPIRED)

    @Test fun readSavedPairingUnknown() {
        val locator = savedLocator()
        assertOriginalIdentity(locator)
        val observation = observePairingRecovery(locator, keys::observeExistingIdentity) {
            PairingBindingClient(keys).read(locator)
        }
        assertEquals(GatewaySetupRecovery.UNAVAILABLE, observation.recovery)
        assertNull(observation.binding)
        assertOriginalIdentity(locator)
        receipt("read_unknown", locator, "unavailable", null)
    }

    /** Destructive only to this explicitly selected disposable fixture's existing signer. Run last. */
    @Test fun confirmedKeyLossBlocksBeforeNetwork() {
        check(Build.HARDWARE in setOf("ranchu", "goldfish")) { "Disposable emulator only" }
        check(InstrumentationRegistry.getArguments().getString("setupHandoffDeleteTestKey") == "true") {
            "Deleting the disposable fixture key needs the additional explicit opt-in"
        }
        val locator = savedLocator()
        assertOriginalIdentity(locator)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.deleteEntry(DeviceSigningKeyStore.DEFAULT_ALIAS)
        assertEquals(ExistingSigningIdentity.Missing, keys.observeExistingIdentity())
        var networkReads = 0
        val observation = observePairingRecovery(locator, keys::observeExistingIdentity) {
            networkReads++
            PairingBindingClient(keys).read(locator)
        }
        assertEquals(GatewaySetupRecovery.KEYS_LOST, observation.recovery)
        assertNull(observation.binding)
        assertEquals(0, networkReads)
        assertEquals(ExistingSigningIdentity.Missing, keys.observeExistingIdentity())
        assertFalse(store.containsAlias(DeviceSigningKeyStore.DEFAULT_ALIAS))
        receipt("keys_lost", locator, "keys_lost", null)
    }

    private fun readExpected(operation: String, status: PairingBindingStatus) {
        val locator = savedLocator()
        assertOriginalIdentity(locator)
        val binding = PairingBindingClient(keys).read(locator)
        assertEquals(status, binding.status)
        if (status == PairingBindingStatus.APPROVED) assertNotNull(binding.deviceId)
        else assertNull(binding.deviceId)
        assertOriginalIdentity(locator)
        receipt(operation, locator, status.name.lowercase(java.util.Locale.ROOT), binding)
    }

    private fun savedLocator(): PairingLocator = checkNotNull(PairingLocatorStore.read(app)).also {
        check(it.origin == ORIGIN) { "Private fixture must use the independently selected localhost service" }
        assertEquals("wss://localhost:8443/v1/device-stream", it.streamEndpoint)
    }

    private fun assertOriginalIdentity(locator: PairingLocator) {
        assertEquals(ExistingSigningIdentity.Present(locator.fingerprint), keys.observeExistingIdentity())
        assertEquals(locator.fingerprint, keys.existing().fingerprintHex)
    }

    private fun assertNoStartOrRadioPermission() {
        assertFalse(GatewayService.processActive)
        assertFalse(AuthenticatedGatewayService.processActive)
        assertEquals(0, AuthenticatedGatewayStatus.authenticatedSessions)
        assertEquals(0, AuthenticatedGatewayStatus.heartbeats)
        for (permission in listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS)) {
            assertEquals("The handoff fixture must never grant radio access", PackageManager.PERMISSION_DENIED,
                app.checkSelfPermission(permission))
        }
    }

    private fun receipt(operation: String, locator: PairingLocator, status: String, binding: PairingBinding?) {
        assertEquals(locator, PairingLocatorStore.read(app))
        val publicProgress = app.getSharedPreferences("pairing-locator", Context.MODE_PRIVATE).all
        assertEquals(setOf("origin", "pairing_id", "fingerprint"), publicProgress.keys)
        assertNoStartOrRadioPermission()
        val value = JSONObject().put("schema_version", 1).put("operation", operation)
            .put("process_id", Process.myPid()).put("origin", locator.origin)
            .put("pairing_id", locator.pairingId.toString()).put("key_fingerprint", locator.fingerprint)
            .put("status", status).put("device_id", binding?.deviceId?.toString() ?: JSONObject.NULL)
            .put("comparison_code", binding?.comparisonCode ?: JSONObject.NULL)
            .put("stream_endpoint", locator.streamEndpoint).put("services_running", false)
            .put("locator_unchanged", true)
        val pending = File(app.filesDir, "$RECEIPT.tmp")
        pending.writeText(value.toString(), Charsets.UTF_8)
        check(pending.renameTo(File(app.filesDir, RECEIPT))) { "Could not publish private fixture receipt" }
        assertTrue(File(app.filesDir, RECEIPT).isFile)
    }

    companion object {
        private const val ORIGIN = "https://localhost:8443"
        private const val QR_INPUT = "setup-handoff-qr.json"
        private const val RECEIPT = "setup-handoff-receipt.json"
    }
}
