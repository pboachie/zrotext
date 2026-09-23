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
    @Test fun installedJournalOpensAtVersionThreeWithEventOutbox() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val db = SmsJournalDatabase.get(context)
        assertEquals(3, db.openHelper.readableDatabase.version)
        db.attempts().nextAlphaEvent()
        db.openHelper.readableDatabase.query("PRAGMA table_info(sms_attempts)").use { cursor ->
            val name = cursor.getColumnIndexOrThrow("name")
            var found = false
            while (cursor.moveToNext()) if (cursor.getString(name) == "messageId") found = true
            assertTrue(found)
        }
    }
}
