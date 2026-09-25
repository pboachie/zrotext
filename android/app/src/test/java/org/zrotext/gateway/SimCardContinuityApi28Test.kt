// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class SimCardContinuityApi28Test {
    @Test fun api28ProvidesNoPublicCardIdentityObservation() {
        assertNull(SimCardContinuity.observe(RuntimeEnvironment.getApplication()))
    }
}
