// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.provider.Telephony
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * No-radio RCS risk observation on real telephony. Reads only the platform's
 * default-SMS-app answer; never sends anything, changes no setting, and logs
 * the classification only, never the package name or any telephony detail.
 */
@RunWith(AndroidJUnit4::class)
class DefaultSmsAppRcsRiskDeviceTest {
    @Test fun defaultSmsAppRiskIsObservableAndMatchesThePlatformAnswer() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val observed = DefaultSmsAppRcsRisk.observe(context)
        assertNotNull(observed)
        // The reported risk must be derivable from exactly what the platform
        // answered, so the UI's warning can never disagree with the platform.
        val packageAnswer = runCatching { Telephony.Sms.getDefaultSmsPackage(context) }.getOrNull()
        assertEquals(DefaultSmsAppRcsRisk.classify(packageAnswer), observed)
        // Only the coarse classification is recorded; the package name and any
        // telephony detail stay off the logs.
        Log.i("ZTRcsCheck", "class=$observed")
    }
}
