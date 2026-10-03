// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w320dp-h480dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class SealedLineReviewPaneTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    @Test fun mountingAndCancelNeverApproveLine() {
        var approvals = 0; var cancelled = 0
        compose.runOnIdle { compose.activity.setContent {
            GatewayTheme { SealedLineReviewPane("", "", {}, {}, null, "", {},
                { approvals++ }, { cancelled++ }) }
        } }
        compose.onNodeWithText("Approve this exact line on this phone").assertDoesNotExist()
        compose.onNodeWithText("Close review and withdraw line approval").performScrollTo().performClick()
        assertEquals(0, approvals); assertEquals(1, cancelled)
    }
    @Test fun largeTextReviewConfirmsOnlyDisplayedTupleOnce() {
        val identity = EvidenceIdentity(UUID(0, 1).toString(), UUID(0, 2).toString(), "a".repeat(64))
        val scope = ConversationSocketComposition.AuthenticatedIdentitySnapshot(identity) {}
        val exact = SealedLineReviewController.Review(UUID(0, 1), UUID(0, 2), UUID(0, 3), 4, 7, ByteArray(32), scope)
        val displayed = mutableStateOf<SealedLineReviewController.Review?>(exact)
        val approvals = mutableListOf<SealedLineReviewController.Review>()
        compose.runOnIdle { compose.activity.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) {
                GatewayTheme { SealedLineReviewPane(exact.line.toString(), "4", {}, {}, displayed.value,
                    "Server installation is still required.", {}, { approvals += it; displayed.value = null }, {}) }
            }
        } }
        compose.onNodeWithText("Approve this exact line on this phone").performScrollTo().performClick()
        compose.onNodeWithText("Approve this exact line on this phone").assertDoesNotExist()
        assertEquals(1, approvals.size); assertSame(exact, approvals.single())
        compose.onNodeWithText("Server installation is still required.").assertExists()
    }
}
