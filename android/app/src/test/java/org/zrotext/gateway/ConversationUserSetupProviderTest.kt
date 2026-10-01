// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.ContextWrapper
import androidx.room.Room
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationUserSetupProviderTest {
    @Test fun disabledResolutionDoesNotReadContextLineHardwareOrPublicCandidate() {
        val context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = error("Disabled context access")
        }
        val database = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        val lines = database.attempts()
        database.close() // Any accidental query must fail rather than opening setup storage.
        val provider = ConversationUserSetupProvider(context, lines)
        // API 28, malformed public bytes and throwing providers must remain untouched.
        assertNull(provider.resolve(ByteArray(0)))
        assertNull(provider.resolve(byteArrayOf(1), enabled = false))
    }
}
