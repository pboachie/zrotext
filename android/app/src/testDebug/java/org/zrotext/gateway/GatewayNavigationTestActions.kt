// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.ComposeContentTestRule

/** Follow the visible screen menu; navigation must not be bypassed by test intents. */
internal fun ComposeContentTestRule.openGatewayPage(label: String) {
    onNode(hasText("Controls") and hasClickAction()).performScrollTo().performClick()
    onNode(hasText(label) and hasClickAction()).assertIsDisplayed().performClick()
}
