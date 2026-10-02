// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.input.key.Key
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
        compose.openGatewayPage("Connection")
        click("Open conversation review")
    }
    private fun replies(): Boolean = compose.activity.conversationRepliesEnabled
    private fun invokeRetainedChoice(action: () -> Boolean) {
        try { action() } catch (failure: IllegalStateException) {
            assertEquals("Cannot read CompositionLocal because the Modifier node is not currently attached.", failure.message)
        }
        assertFalse(replies())
    }
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
    @Test fun rootComparisonControlHasAnExplicitNameAndDoesNotEnrollOnToggle() {
        open(); click("Enroll conversation keys and compared root")
        val comparison = compose.onNodeWithContentDescription("Independent account and root fingerprint comparison")
        if (!comparison.isDisplayed()) comparison.performScrollTo()
        comparison.assertIsOff().performClick().assertIsOn()
        compose.onNodeWithText("Enroll independently compared root").assertIsNotEnabled()
        compose.runOnIdle {
            assertFalse(compose.activity.conversationSetupEnabled); assertFalse(replies())
            assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        }
    }
    @Test fun delayedReplyChoiceFromBeforePauseCannotRestoreConsentAfterFreshReviewOptIn() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        val delayed = compose.onNodeWithText("Allow approved replies for this session")
            .fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        click("Open conversation review"); click("Enable review for this session")
        compose.runOnIdle { invokeRetainedChoice(delayed) }
    }
    @Test fun delayedReplyChoiceCannotApplyToAReselectedCandidateEvenWithTheSameUri() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        val delayed = compose.onNodeWithText("Allow approved replies for this session")
            .fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        compose.runOnIdle { invokeRetainedChoice(delayed) }
        click("Allow approved replies for this session")
        compose.runOnIdle { assertTrue(replies()) }
    }
    @Test fun withdrawnReplyChoiceCannotBeReenabledByAnEarlierControlAction() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        val delayed = compose.onNodeWithText("Allow approved replies for this session")
            .fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        click("Allow approved replies for this session"); click("Turn replies off")
        compose.runOnIdle { invokeRetainedChoice(delayed) }
        click("Allow approved replies for this session")
        compose.runOnIdle { assertTrue(replies()) }
    }
    @Test fun keyboardFocusStaysOnTheReplyControlWhenTheChoiceChanges() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        val choice = compose.onNodeWithText("Allow approved replies for this session")
        if (!choice.isDisplayed()) choice.performScrollTo()
        // Robolectric dialogs begin in touch mode; focus the real dialog host in keyboard mode.
        compose.runOnIdle {
            val global = Class.forName("android.view.WindowManagerGlobal")
            val instance = global.getMethod("getInstance").invoke(null)
            val windows = global.getMethod("getWindowViews").invoke(instance) as List<*>
            fun composeView(view: android.view.View): android.view.View? {
                if (view.javaClass.simpleName == "AndroidComposeView") return view
                if (view is android.view.ViewGroup) for (i in 0 until view.childCount) {
                    composeView(view.getChildAt(i))?.let { return it }
                }
                return null
            }
            val view = requireNotNull(composeView(windows.last() as android.view.View))
            val manager = view.javaClass.getMethod("getInputModeManager").invoke(view)
            val request = manager.javaClass.methods.single { it.name.startsWith("requestInputMode") }
            assertEquals(true, request.invoke(manager, 2))
            view.requestFocus()
        }
        choice.performSemanticsAction(SemanticsActions.RequestFocus) { it() }
        choice.assertIsFocused().performKeyInput { pressKey(Key.Enter) }
        compose.onNodeWithText("Turn replies off").assertIsFocused().performKeyInput { pressKey(Key.Enter) }
        compose.onNodeWithText("Allow approved replies for this session").assertIsFocused()
        compose.runOnIdle { assertFalse(replies()) }
    }
}
