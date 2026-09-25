// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.app.Activity
import android.os.Build
import android.telephony.SubscriptionManager
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Run only with an isolated emulator and one injected synthetic SMS. Never invokes SmsManager. */
@RunWith(AndroidJUnit4::class)
class M1VirtualInboundSmsDeviceTest {
    @Test fun emulatorSmsBroadcastCreatesOneEncryptedUpload() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("m1VirtualInbound") == "true")
        assumeTrue(Build.FINGERPRINT.contains("sdk_gphone", ignoreCase = true))
        val runId = checkNotNull(args.getString("m1VirtualRunId"))
        assertTrue(runId.matches(Regex("[0-9a-f]{32}")))
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(android.content.pm.PackageManager.PERMISSION_GRANTED,
            ContextCompat.checkSelfPermission(app, Manifest.permission.RECEIVE_SMS))
        assertEquals(android.content.pm.PackageManager.PERMISSION_GRANTED,
            ContextCompat.checkSelfPermission(app, Manifest.permission.READ_PHONE_STATE))
        assertEquals(android.content.pm.PackageManager.PERMISSION_DENIED,
            ContextCompat.checkSelfPermission(app, Manifest.permission.SEND_SMS))
        val subscriptions = app.getSystemService(SubscriptionManager::class.java)
            .activeSubscriptionInfoList.orEmpty()
        assertEquals("one synthetic emulator SIM", 1, subscriptions.size)
        val subId = subscriptions.single().subscriptionId
        assertTrue(subId >= 0)

        val senderToken = InboundVault.token("sender-v1", "+12025550199".toByteArray(Charsets.US_ASCII))
        // Application startup reconciliation must finish before this test-only fixture is seeded.
        JournalRuntime.io.submit { }.get(10, TimeUnit.SECONDS)
        val dao = SmsJournalDatabase.get(app).attempts()
        val attempt = UUID.randomUUID().toString()
        val message = UUID.randomUUID().toString()
        val intent = UUID.randomUUID().toString()
        val identity = EvidenceIdentity.fromStream(
            UUID.randomUUID(), UUID.randomUUID(), "wss://m1-virtual.invalid")
        val now = System.currentTimeMillis()
        dao.reserveAlpha(attempt, message, subId, 1, intent, now, senderToken, identity)
        assertTrue(dao.acknowledgeAlphaIntent(intent, true, now + 1))
        assertEquals(1, dao.consumeRadioStart(attempt, message, subId, 1, now + 2))
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, now + 3)
        assertTrue(dao.activeInboundWindows(senderToken, System.currentTimeMillis()).isNotEmpty())
        Log.i("M1VirtualInbound", "READY $runId")

        val deadline = System.currentTimeMillis() + 90_000L
        var captured: InboundEvent? = null
        while (System.currentTimeMillis() < deadline) {
            val rows = dao.inboundForAttempt(attempt)
            if (rows.isNotEmpty()) {
                assertEquals(1, rows.size)
                captured = rows.single()
                break
            }
            Thread.sleep(250)
        }
        val event = checkNotNull(captured) { "emulator SMS broadcast did not reach receiver" }
        assertEquals(InboundClassification.CAPTURED_LOCAL, event.classification)
        assertEquals(subId, event.observedSubscriptionId)
        assertEquals("ZT VIRTUAL INBOUND 1", InboundVault.open(
            InboundVault.Sealed(checkNotNull(event.encryptedBody), checkNotNull(event.nonce)),
            event.dedupeToken))
        val upload = checkNotNull(dao.nextInboundUpload(0, identity.accountId,
            identity.deviceId, identity.originHash)) { "captured event has no upload row" }
        assertEquals(event.eventId, upload.eventId)
        assertEquals(1L, upload.sequence)
        assertNull(upload.signatureDer)
        Log.i("M1VirtualInbound", "PASS $runId")
    }
}
