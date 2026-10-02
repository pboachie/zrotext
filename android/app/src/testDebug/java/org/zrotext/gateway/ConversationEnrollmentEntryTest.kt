// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExternalResource
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Real entry actions; no authenticated host, hardware creation, service or radio is substituted. */
@RunWith(RobolectricTestRunner::class) @Config(sdk = [34], qualifiers = "w320dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationEnrollmentEntryTest {
    private val compose = createAndroidComposeRule<MainActivity>()
    @get:Rule val rules: RuleChain = RuleChain.outerRule(object : ExternalResource() {
        override fun before() {
            val app = org.robolectric.RuntimeEnvironment.getApplication()
            org.robolectric.Shadows.shadowOf(app).grantPermissions("${app.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
        }
    }).around(compose)
    private fun click(text: String) {
        val node = compose.onNodeWithText(text)
        if (!node.isDisplayed()) node.performScrollTo()
        node.performClick()
    }
    private fun open() {
        compose.onNode(hasText("Connection") and hasClickAction()).performClick()
        click("Open conversation review")
    }
    private fun replies(): Boolean = compose.activity.conversationRepliesEnabled
    @Test fun reviewOptInDoesNotEnableRepliesAndCandidateReplacementWithdrawsBothChoices() {
        open()
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        compose.runOnIdle { assertTrue(compose.activity.conversationSetupEnabled); assertFalse(replies()) }
        click("Allow approved replies for this session")
        compose.runOnIdle { assertTrue(replies()); compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        compose.runOnIdle { assertFalse(replies()); assertFalse(compose.activity.conversationSetupEnabled) }
    }
    @Test fun pauseWithdrawsReplyPermissionEvenWhileActivityRemainsVisible() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session"); click("Allow approved replies for this session")
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        assertFalse(replies()); assertFalse(compose.activity.conversationSetupEnabled)
    }
    @Test fun closingEnrollmentCreatesNoKeysOrConversationJournalAndKeepsReviewOff() {
        open(); click("Enroll conversation keys and compared root")
        click("Close enrollment and return to review")
        compose.runOnIdle {
            assertFalse(compose.activity.conversationSetupEnabled); assertFalse(replies())
            assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        }
    }
    @Test fun deliberateEnrollmentWithoutCurrentAuthenticatedHostIsRefusedBeforeProtectionOrReaderCreation() {
        open(); click("Enroll conversation keys and compared root")
        click("Enroll hardware reader and journal protection")
        compose.waitUntil(10000) {
            compose.onAllNodesWithText("Enrollment refused.", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        compose.runOnIdle {
            assertFalse(compose.activity.conversationSetupEnabled); assertFalse(replies())
            assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        }
    }
}
