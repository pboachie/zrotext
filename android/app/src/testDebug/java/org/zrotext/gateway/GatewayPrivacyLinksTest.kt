// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewayPrivacyLinksTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun access() {
        compose.onNodeWithText("Setup").performClick()
        compose.onNodeWithText("1. Review access").performScrollTo().performClick()
    }

    private fun assertBrowserOnly(url: String) = compose.runOnIdle {
        val activity = shadowOf(compose.activity)
        val intent = requireNotNull(activity.nextStartedActivity)
        assertEquals(Intent.ACTION_VIEW, intent.action)
        assertEquals(url, intent.dataString)
        assertNull(activity.lastRequestedPermission)
        assertTrue(activity.allStartedServices.isEmpty())
    }

    @Test fun policyLinkIsVisibleBeforeAccessRequestsAndOpensPublicPolicy() {
        access()
        compose.onNodeWithText("Privacy policy").performScrollTo().performClick()
        assertBrowserOnly("https://zrotext.com/privacy")
    }

    @Test fun deletionLinkOpensInstructionsAnchorWithoutSendingRequest() {
        access()
        compose.onNodeWithText("Account and data deletion requests").performScrollTo().performClick()
        assertBrowserOnly("https://zrotext.com/privacy#deletion")
    }
}
