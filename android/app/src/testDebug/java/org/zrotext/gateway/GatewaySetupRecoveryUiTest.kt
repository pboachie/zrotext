// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
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
import java.util.UUID

/** UX-NAV-02, SETUP-RESUME-01, SETUP-CONNECT-01, SETUP-UNKNOWN-01, REC-KEYS. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewaySetupRecoveryUiTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test fun primaryNavigationStaysVisibleAcrossOrdinaryAndAdvancedScreens() {
        listOf("Setup", "Activity", "Connection", "Tools", "Home").forEach { page ->
            compose.openGatewayPage(page)
            listOf("Home", "Activity", "Setup").forEach { label ->
                val node = compose.onNodeWithTag("gateway-nav-$label").assertIsDisplayed().fetchSemanticsNode()
                assertEquals(label == page, node.config[SemanticsProperties.Selected])
            }
        }
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun approvedObservationMovesToProtectionBeforeSimWithoutGrantingAccessOrStartingConnection() {
        val recovery = mutableStateOf(GatewaySetupRecovery.COMPARE)
        var checks = 0
        compose.runOnIdle { compose.activity.setContent { GatewayTheme {
            GatewayCompanion(initialPage = GatewayPage.SETUP) { _, _ ->
                GatewaySetupGuide("Not selected", "Pending", {}, recovery = recovery.value, onCheck = { checks++ },
                    accessContent = {}, simContent = {}, pairingContent = {}, comparisonContent = {
                        androidx.compose.material3.Text("Comparison code: 12345678")
                        androidx.compose.material3.Text("Key fingerprint: " + "AB".repeat(32))
                    })
            }
        } } }
        compose.onNodeWithText("Compare phone details").assertExists()
        compose.onNodeWithText("Comparison code: 12345678").assertExists()
        compose.onNodeWithText("Check saved pairing").assertDoesNotExist()
        assertEquals(0, checks)
        compose.runOnIdle { recovery.value = GatewaySetupRecovery.APPROVED }
        compose.onNodeWithText("Protect this phone").assertExists()
        compose.onNodeWithText("Step 3 of 4").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun unknownOutcomeOffersStatusCheckWithoutNewClaim() {
        var checks = 0
        compose.runOnIdle { compose.activity.setContent { GatewayTheme {
            GatewayCompanion(initialPage = GatewayPage.SETUP) { _, _ ->
                GatewaySetupGuide("Not selected", "Unconfirmed", {}, initialStep = GatewaySetupStep.COMPARE,
                    recovery = GatewaySetupRecovery.UNAVAILABLE, onCheck = { checks++ },
                    accessContent = {}, simContent = {}, pairingContent = {})
            }
        } } }
        compose.onNodeWithText(GatewaySetupRecovery.UNAVAILABLE.title).assertExists()
        compose.onNodeWithText("Check saved pairing").performScrollTo().performClick()
        assertEquals(1, checks)
        compose.onNodeWithText("Scan pairing QR").assertDoesNotExist()
        compose.onNodeWithText("Use replacement pairing").assertDoesNotExist()
    }

    @Test fun lostSimAndUnavailableBindingReturnToOnlyTheAffectedTask() {
        val recovery = mutableStateOf(GatewaySetupRecovery.APPROVED)
        val sim = mutableStateOf("SIM 1: Synthetic")
        compose.runOnIdle { compose.activity.setContent { GatewayTheme {
            GatewayCompanion(initialPage = GatewayPage.SETUP) { _, _ ->
                GatewaySetupGuide(sim.value, "Approved", {}, recovery = recovery.value,
                    accessContent = {}, simContent = {}, pairingContent = {})
            }
        } } }
        compose.onNodeWithText("Protect this phone").assertExists()
        compose.onNodeWithText("Review SIM and Android access").performScrollTo().performClick()
        compose.onNodeWithText("Choose a SIM").assertExists()
        compose.runOnIdle { sim.value = "Not selected" }
        compose.onNodeWithText("Choose a SIM").assertExists()
        compose.runOnIdle { recovery.value = GatewaySetupRecovery.UNAVAILABLE }
        compose.onNodeWithText("Pairing recovery").assertExists()
        compose.onNodeWithText(GatewaySetupRecovery.UNAVAILABLE.title).assertExists()
        compose.onNodeWithText("Check saved pairing").assertExists()
        compose.onNodeWithText("Get setup help").assertExists()
        compose.runOnIdle { assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty()) }
    }

    @Test fun savedPublicLocatorAndUnavailableProviderKeepRetryWithoutReplacingIdentity() {
        val locator = PairingLocator("https://gateway.example.test",
            UUID.fromString("11111111-1111-4111-8111-111111111111"), "AB".repeat(32))
        compose.runOnIdle {
            assertTrue(PairingLocatorStore.save(compose.activity, locator))
            val values = compose.activity.getSharedPreferences("pairing-locator", Context.MODE_PRIVATE).all
            assertEquals(setOf("origin", "pairing_id", "fingerprint"), values.keys)
        }
        compose.activityRule.scenario.recreate()
        compose.openGatewayPage("Setup")
        compose.waitUntil(5000) {
            compose.onAllNodesWithText(GatewaySetupRecovery.UNAVAILABLE.title).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText(GatewaySetupRecovery.UNAVAILABLE.detail).assertExists()
        compose.onNodeWithText("Check saved pairing").assertExists()
        compose.onNodeWithText("Get setup help").assertExists()
        compose.onNodeWithText("Use replacement pairing").assertDoesNotExist()
        compose.onNodeWithText("Start connection").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(locator, PairingLocatorStore.read(compose.activity))
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
            assertTrue(PairingLocatorStore.clear(compose.activity))
        }
    }

    @Test fun transientKeyReadCanRecoverOnExplicitCheckWithoutClaimOrStart() {
        val locator = PairingLocator("https://gateway.example.test",
            UUID.fromString("11111111-1111-4111-8111-111111111111"), "AB".repeat(32))
        var available = false
        var bindingReads = 0
        val identity = { ExistingSigningIdentity.observe({ true }) {
            if (!available) throw java.security.ProviderException("Temporarily unavailable")
            locator.fingerprint
        } }
        val check = { observePairingRecovery(locator, identity) {
            bindingReads++; PairingBinding(PairingBindingStatus.PENDING, null, "12345678")
        } }
        val recovery = mutableStateOf(check().recovery)
        compose.runOnIdle {
            assertTrue(PairingLocatorStore.save(compose.activity, locator))
            compose.activity.setContent { GatewayTheme {
                GatewayCompanion(initialPage = GatewayPage.SETUP) { _, _ ->
                    GatewaySetupGuide("Not selected", "Unconfirmed", {}, recovery = recovery.value,
                        onCheck = { available = true; recovery.value = check().recovery },
                        accessContent = {}, simContent = {}, pairingContent = {})
                }
            } }
        }
        assertEquals(0, bindingReads)
        compose.onNodeWithText("Use replacement pairing").assertDoesNotExist()
        compose.onNodeWithText("Check saved pairing").performScrollTo().performClick()
        compose.onNodeWithText("Compare phone details").assertExists()
        assertEquals(1, bindingReads)
        compose.onNodeWithText("Scan pairing QR").assertDoesNotExist()
        compose.onNodeWithText("Start connection").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(locator, PairingLocatorStore.read(compose.activity))
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(PairingLocatorStore.clear(compose.activity))
        }
    }

    @Test fun connectionConsentIsUncheckedAfterLeavingAndReturning() {
        compose.openGatewayPage("Setup")
        compose.onNodeWithText("Review Android access").performScrollTo().performClick()
        compose.onNodeWithText("Back to SIM selection").performScrollTo().performClick()
        compose.onNodeWithText("Next: connection").performScrollTo().performClick()
        compose.onNodeWithText("Resume this connection after reboot").performScrollTo().assertIsOff().performClick().assertIsOn()
        compose.openGatewayPage("Home")
        compose.openGatewayPage("Setup")
        compose.onNodeWithText("Resume this connection after reboot").performScrollTo().assertIsOff()
            .performClick().assertIsOn()
        compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
        compose.onNodeWithText("Resume this connection after reboot").performScrollTo().assertIsOff()
        compose.onNodeWithText("Start connection").performScrollTo().performClick()
        compose.runOnIdle { assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty()) }
    }
}
