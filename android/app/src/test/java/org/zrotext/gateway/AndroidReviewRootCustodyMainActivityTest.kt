// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.view.WindowManager
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Real ordinary app entry; no cookie, server, native fake or SMS grant. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[34],qualifiers="w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class AndroidReviewRootCustodyMainActivityTest {
    @get:Rule val compose=createEmptyComposeRule()
    @Test fun setupOpensDistinctSecureReviewEntryAndRejectsNonOriginBeforeBrowser() {
        val app=RuntimeEnvironment.getApplication()
        val host=Robolectric.buildActivity(MainActivity::class.java,
            Intent(app,MainActivity::class.java).putExtra("gateway_screen","SETUP")).setup().visible()
        try {
            compose.onNodeWithText("Open isolated review workspace custody").performScrollTo().performClick()
            compose.onNodeWithText("Review workspace custody").assertIsDisplayed()
            assertTrue(host.get().window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE!=0)
            compose.onNodeWithText("Review service HTTPS origin").performTextInput("https://review.example.test/path")
            compose.onNodeWithText("Open review sign-in").performClick()
            compose.onNodeWithText("Enter the exact HTTPS origin without a path.").assertIsDisplayed()
            compose.onNodeWithText("Close").performClick()
            compose.onNodeWithText("Set up or recover owner custody on Android").performScrollTo().assertIsDisplayed()
        } finally {host.pause().stop().destroy()}
    }
}
