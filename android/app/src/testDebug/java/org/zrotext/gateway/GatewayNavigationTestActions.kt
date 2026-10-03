// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.ComposeContentTestRule

/** Follow the visible screen menu; navigation must not be bypassed by test intents. */
internal fun ComposeContentTestRule.openGatewayPage(label: String) {
    onNode(hasContentDescription("Controls") and hasClickAction()).performScrollTo().performClick()
    onNode(hasText(label) and hasClickAction()).assertIsDisplayed().performClick()
}

/** Follow the gear popover to the preserved secondary actions. */
internal fun ComposeContentTestRule.openGatewayQuickControls() {
    onNode(hasContentDescription("Controls") and hasClickAction()).performScrollTo().performClick()
    onNode(hasText("Quick controls") and hasClickAction()).assertIsDisplayed().performClick()
}

internal fun ComposeContentTestRule.openGatewayMessages() {
    // Ordinary Home puts this entry in the initial viewport, including a
    // standalone synthetic Home fixture without an outer scroll container.
    onNodeWithTag("home-metric-Messages").assertIsDisplayed().performClick()
}
