// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class JournalDeviceUpgradeTest {
    @Test fun installedJournalOpensAtVersionSixWithIdentityBoundOutbox() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val db = SmsJournalDatabase.get(context)
        assertEquals(6, db.openHelper.readableDatabase.version)
        db.attempts().nextAlphaEvent("11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", "a".repeat(64))
        db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM inbound_windows").close()
        db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM inbound_events").close()
        db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM inbound_uploads").close()
        db.openHelper.readableDatabase.query("PRAGMA table_info(sms_attempts)").use { cursor ->
            val name = cursor.getColumnIndexOrThrow("name")
            var found = false
            while (cursor.moveToNext()) if (cursor.getString(name) == "messageId") found = true
            assertTrue(found)
        }
    }
}
