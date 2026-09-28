// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DefaultSmsAppRcsRiskObservationTest {
    @Test fun aPlatformWithoutADefaultSmsPackageNeverClaimsRcsIsOff() {
        // Robolectric exposes no default SMS package, so this also covers a real
        // platform answer of null or a lookup failure: the observation stays
        // unavailable instead of becoming a positive safety claim.
        val app = RuntimeEnvironment.getApplication()
        assertEquals(DefaultSmsAppRcsRisk.Risk.UNAVAILABLE, DefaultSmsAppRcsRisk.observe(app))
    }
}
