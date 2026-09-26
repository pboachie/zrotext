// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Opt-in physical reply probe. Starts metadata upload; never arms an outbound SMS. */
@RunWith(AndroidJUnit4::class)
class M1LocalInboundReplyTest {
    @Test fun oneConsentedReplyReachesTheWriter() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires an explicitly coordinated physical reply", args.getString("m1InboundReply") == "true")
        val deviceId = args.getString("m1DeviceId")
        val messageId = args.getString("m1MessageId")
        assumeTrue("requires the existing disposable device and sent message",
            !deviceId.isNullOrBlank() && !messageId.isNullOrBlank())
        UUID.fromString(deviceId)
        UUID.fromString(messageId)

        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val db = SmsJournalDatabase.get(app).openHelper.readableDatabase
        fun counts(): Pair<Int, Int> {
            db.query(SimpleSQLiteQuery(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN u.acknowledgedAtMs IS NOT NULL THEN 1 ELSE 0 END), 0) " +
                    "FROM inbound_events e JOIN inbound_uploads u ON u.eventId=e.eventId WHERE e.messageId=?",
                arrayOf(messageId)
            )).use { cursor ->
                check(cursor.moveToFirst())
                return cursor.getInt(0) to cursor.getInt(1)
            }
        }
        assertEquals("reply already recorded for this disposable message", 0, counts().first)
        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
            .putExtra(AuthenticatedGatewayService.EXTRA_INBOUND_UPLOAD, true)
        try {
            ContextCompat.startForegroundService(app, start)
            val deadline = System.currentTimeMillis() + 360_000L
            var result = counts()
            while (System.currentTimeMillis() < deadline && result.second == 0) {
                Thread.sleep(500)
                result = counts()
            }
            assertEquals("expected exactly one locally captured reply", 1, result.first)
            assertTrue("reply metadata was not acknowledged by the writer; ${AuthenticatedGatewayStatus.value}",
                result.second == 1)
        } finally {
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }
}
