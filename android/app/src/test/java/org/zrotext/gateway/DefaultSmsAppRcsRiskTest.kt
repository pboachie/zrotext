// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test

class DefaultSmsAppRcsRiskTest {
    @Test fun knownRcsCapableDefaultAppsAreFlagged() {
        for (pkg in listOf("com.google.android.apps.messaging", "com.samsung.android.messaging")) {
            assertEquals(DefaultSmsAppRcsRisk.Risk.RCS_CAPABLE_APP, DefaultSmsAppRcsRisk.classify(pkg))
        }
    }

    @Test fun unrecognizedOrNullDefaultsNeverClaimRcsIsOff() {
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP,
            DefaultSmsAppRcsRisk.classify("com.example.messaging"))
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP, DefaultSmsAppRcsRisk.classify(""))
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNAVAILABLE, DefaultSmsAppRcsRisk.classify(null))
    }

    @Test fun packageMatchingIsExactSoNearMissNamesStayUnknown() {
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP,
            DefaultSmsAppRcsRisk.classify("Com.Google.Android.Apps.Messaging"))
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP,
            DefaultSmsAppRcsRisk.classify("com.google.android.apps.messaging.fake"))
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP,
            DefaultSmsAppRcsRisk.classify(" com.google.android.apps.messaging"))
    }
}
