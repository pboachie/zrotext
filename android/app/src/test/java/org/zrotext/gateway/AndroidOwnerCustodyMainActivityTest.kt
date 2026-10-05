// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.content.Context
import android.view.WindowManager
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.semantics.SemanticsProperties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.concurrent.atomic.AtomicBoolean

/** Ordinary app entry, with no probe Activity, device bearer, SMS grant or native fake. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class AndroidOwnerCustodyMainActivityTest {
    @get:Rule val compose = createEmptyComposeRule()
    @Test fun clearingIdlePairingErasesAlreadyEnteredManualCredentials() {
        val app = RuntimeEnvironment.getApplication()
        val outcome = app.getSharedPreferences("pairing-outcome", Context.MODE_PRIVATE)
        assertTrue(outcome.edit().clear().commit())
        val host = Robolectric.buildActivity(MainActivity::class.java,
            Intent(app, MainActivity::class.java).putExtra("gateway_screen", "SETUP")).setup().visible()
        try {
            compose.onNodeWithText("3. Pair this phone").performScrollTo().performClick()
            compose.onNodeWithText("HTTPS server origin").performScrollTo().performTextInput("https://owner.invalid")
            compose.onNodeWithText("Use existing manual pairing").performScrollTo().performClick()
            compose.onNodeWithText("Pairing ID").performScrollTo()
                .performTextInput("11111111-1111-4111-8111-111111111111")
            compose.onNodeWithText("One-use pairing token").performScrollTo()
                .performTextInput("ztp_" + "A".repeat(43))
            fun fieldText(label: String) = compose.onNodeWithText(label).fetchSemanticsNode()
                .config[SemanticsProperties.EditableText].text
            assertTrue("Synthetic ID must be entered before cancellation", fieldText("Pairing ID").isNotEmpty())
            assertTrue("Synthetic token must be entered before cancellation", fieldText("One-use pairing token").isNotEmpty())
            compose.onNodeWithText("Clear scanned pairing").performScrollTo().performClick()
            assertEquals("", fieldText("Pairing ID"))
            assertEquals("", fieldText("One-use pairing token"))
            compose.onNodeWithText("Scan pairing QR").performScrollTo().assertIsDisplayed()
        } finally {
            host.pause().stop().destroy()
            assertTrue(outcome.edit().clear().commit())
        }
    }

    @Test fun uncertainStorageBlocksFreshActivityEvenWhenCachedOutcomeLooksResolved() {
        val app = RuntimeEnvironment.getApplication()
        val outcome = app.getSharedPreferences("pairing-outcome", Context.MODE_PRIVATE)
        val uncertain = MainActivity::class.java.getDeclaredField("pairingStorageUncertain")
            .apply { isAccessible = true }.get(null) as AtomicBoolean
        val previous = uncertain.getAndSet(true)
        try {
            assertTrue(outcome.edit().putBoolean("unresolved", false).commit())
            val host = Robolectric.buildActivity(MainActivity::class.java,
                Intent(app, MainActivity::class.java).putExtra("gateway_screen", "SETUP")).setup().visible()
            try {
                compose.onNodeWithText("3. Pair this phone").performScrollTo().performClick()
                compose.onNodeWithText("I reconciled the original ticket; use a fresh ticket")
                    .performScrollTo().assertIsDisplayed()
                compose.onNodeWithText("Scan pairing QR").assertDoesNotExist()
                compose.onNodeWithText("Use existing manual pairing").assertDoesNotExist()
                compose.onNodeWithText("Claim pairing and prove key").assertDoesNotExist()
                compose.onNodeWithText("One-use pairing token").assertDoesNotExist()
                assertTrue(uncertain.get())
            } finally { host.pause().stop().destroy() }
        } finally {
            uncertain.set(previous)
            assertTrue(outcome.edit().clear().commit())
        }
    }

    @Test fun unresolvedPairingRestoresAcrossFreshActivitiesWithoutOfferingAnotherClaim() {
        val app = RuntimeEnvironment.getApplication()
        val outcome = app.getSharedPreferences("pairing-outcome", Context.MODE_PRIVATE)
        assertTrue(outcome.edit().putBoolean("unresolved", true).commit())
        try {
            repeat(2) {
                val host = Robolectric.buildActivity(MainActivity::class.java,
                    Intent(app, MainActivity::class.java).putExtra("gateway_screen", "SETUP")).setup().visible()
                try {
                    compose.onNodeWithText("3. Pair this phone").performScrollTo().performClick()
                    compose.onNodeWithText("I reconciled the original ticket; use a fresh ticket")
                        .performScrollTo().assertIsDisplayed()
                    compose.onNodeWithText("Scan pairing QR").assertDoesNotExist()
                    compose.onNodeWithText("Use existing manual pairing").assertDoesNotExist()
                    compose.onNodeWithText("Claim pairing and prove key").assertDoesNotExist()
                    compose.onNodeWithText("One-use pairing token").assertDoesNotExist()
                    assertTrue(outcome.getBoolean("unresolved", false))
                } finally { host.pause().stop().destroy() }
            }
        } finally { assertTrue(outcome.edit().clear().commit()) }
    }

    @Test fun ordinarySetupOpensSecureOwnerPaneAndClosesBackToSetup() {
        val app = RuntimeEnvironment.getApplication()
        val host = Robolectric.buildActivity(MainActivity::class.java,
            Intent(app, MainActivity::class.java).putExtra("gateway_screen", "SETUP")).setup().visible()
        try {
            compose.onNodeWithText("Set up or recover owner custody on Android").performScrollTo().performClick()
            compose.onNodeWithText("Android owner setup").assertIsDisplayed()
            assertTrue(host.get().window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            compose.onNodeWithText("Close owner ceremony").performScrollTo().performClick()
            compose.onNodeWithText("Set up or recover owner custody on Android").performScrollTo().assertIsDisplayed()
        } finally { host.pause().stop().destroy() }
    }
}
