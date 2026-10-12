// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import androidx.compose.runtime.MutableState
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowSubscriptionManager.SubscriptionInfoBuilder
import java.util.concurrent.Executor

/** Synthetic app selection/preparation only; no device, radio, service or Keystore operation. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], shadows = [MainActivityCompleteSelectionPreparationTest.CompleteListShadow::class])
class MainActivityCompleteSelectionPreparationTest {
    @Implements(SubscriptionManager::class)
    class CompleteListShadow {
        @Implementation fun getActiveSubscriptionInfoList(): List<SubscriptionInfo> = visible
        @Implementation fun getCompleteActiveSubscriptionInfoList(): List<SubscriptionInfo> {
            if (failCompleteRead) throw SecurityException("Synthetic platform refusal")
            completeReads++
            return complete
        }
        companion object {
            var visible = emptyList<SubscriptionInfo>()
            var complete = emptyList<SubscriptionInfo>()
            var failCompleteRead = false
            var completeReads = 0
        }
    }

    private fun info(id: Int) = SubscriptionInfoBuilder.newBuilder().setId(id)
        .setSimSlotIndex(if (id == 7) 0 else 1).setDisplayName("Synthetic choice")
        .buildSubscriptionInfo()

    private class Observations {
        var rows = listOf(ProfileSubscriptionObservation(7, 40, false, 0, 0),
            ProfileSubscriptionObservation(8, 50, true, 1, 1))
        val callbacks = ArrayList<() -> Unit>()
        var closes = 0
        val reads = Executor { it.run() }
        val coordinator = CompleteSelectionPreparationCoordinator({ notify ->
            val source = object : ProfileObservationSource {
                override fun permissionGranted() = true
                override fun register(changed: () -> Unit): AutoCloseable {
                    val update = { changed(); notify() }
                    callbacks.add(update)
                    update()
                    return AutoCloseable { closes++ }
                }
                override fun readComplete() = rows
            }
            CompleteSubscriptionObservationAdapter({ 34 }, source, { it(); true }, reads)
        }, reads)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> state(activity: MainActivity, name: String) =
        MainActivity::class.java.getDeclaredField(name + "$" + "delegate")
            .apply { isAccessible = true }.get(activity) as MutableState<T>
    private fun refresh(activity: MainActivity) {
        MainActivity::class.java.getDeclaredMethod("refreshSims").apply { isAccessible = true }.invoke(activity)
    }
    private fun select(activity: MainActivity, id: Int) {
        MainActivity::class.java.getDeclaredMethod("selectSimForPreparation", Int::class.javaPrimitiveType)
            .apply { isAccessible = true }.invoke(activity, id)
    }

    private fun withActivity(saved: Int?, body: (MainActivity, Observations, () -> Unit, () -> Unit) -> Unit) {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).grantPermissions(Manifest.permission.READ_PHONE_STATE)
        CompleteListShadow.visible = listOf(info(7))
        CompleteListShadow.complete = listOf(info(7), info(8))
        CompleteListShadow.failCompleteRead = false
        CompleteListShadow.completeReads = 0
        assertTrue(app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit()
            .putInt("subscription_id", saved ?: SubscriptionManager.INVALID_SUBSCRIPTION_ID).commit())
        val observations = Observations()
        val host = Robolectric.buildActivity(MainActivity::class.java)
        val activity = host.get()
        activity.completeSelectionCoordinatorFactory = { observations.coordinator }
        host.setup()
        try { body(activity, observations, { host.pause(); Unit }, { host.resume(); Unit }) }
        finally {
            CompleteListShadow.failCompleteRead = false
            host.pause().stop().destroy()
            observations.coordinator.close()
            CompleteListShadow.visible = emptyList()
            CompleteListShadow.complete = emptyList()
        }
    }

    @Test fun completeListKeepsHiddenPeerAndItsSavedExplicitChoice() {
        withActivity(8) { activity, observations, _, _ ->
            assertEquals(listOf(7, 8), state<List<Pair<Int, String>>>(activity, "sims").value.map { it.first })
            assertEquals(8, state<Int?>(activity, "selectedSim").value)
            val held = checkNotNull(activity.currentCompleteSelectionPreparation())
            assertEquals(8, held.selected.subscriptionId)
            assertEquals(ObservedSubscriptionKind.EMBEDDED, held.selected.kind)
            assertEquals(listOf(7, 8), held.activeRows.map { it.subscriptionId })
            assertEquals(listOf(7), CompleteListShadow.visible.map { it.subscriptionId })
            assertEquals(2, observations.rows.size)
            assertTrue(CompleteListShadow.completeReads > 0)
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(activity.conversationRepliesEnabled)
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun absentSavedChoiceNeverSelectsFirstOrRemainingActiveProfile() {
        withActivity(null) { activity, observations, _, _ ->
            assertEquals(2, state<List<Pair<Int, String>>>(activity, "sims").value.size)
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertNull(activity.currentCompleteSelectionPreparation())
            assertTrue(observations.callbacks.isEmpty())
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun explicitPeerChoiceRetiresOldPreparationWithoutEnablingMessaging() {
        withActivity(7) { activity, observations, _, _ ->
            val old = checkNotNull(activity.currentCompleteSelectionPreparation())
            select(activity, 8)
            val fresh = checkNotNull(activity.currentCompleteSelectionPreparation())
            assertFalse(observations.coordinator.isCurrent(old))
            assertEquals(8, fresh.selected.subscriptionId)
            assertEquals(8, activity.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID))
            assertEquals(2, fresh.activeRows.size)
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(activity.conversationRepliesEnabled)
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun pauseWithdrawsHeldPreparationAndResumeMustObserveItAgain() {
        withActivity(7) { activity, observations, pause, resume ->
            val old = checkNotNull(activity.currentCompleteSelectionPreparation())
            pause()
            assertFalse(observations.coordinator.isCurrent(old))
            assertNull(activity.currentCompleteSelectionPreparation())
            assertEquals(7, state<Int?>(activity, "selectedSim").value)
            resume()
            val fresh = checkNotNull(activity.currentCompleteSelectionPreparation())
            assertNotSame(old, fresh)
            assertEquals(7, fresh.selected.subscriptionId)
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun failedCompleteReadWithdrawsPreparationAndPreservesUserData() {
        withActivity(8) { activity, observations, _, _ ->
            val old = checkNotNull(activity.currentCompleteSelectionPreparation())
            val userData = activity.getSharedPreferences("synthetic_complete_selection_data", Context.MODE_PRIVATE)
            assertTrue(userData.edit().putString("sentinel", "retain").commit())
            CompleteListShadow.failCompleteRead = true
            refresh(activity)
            assertFalse(observations.coordinator.isCurrent(old))
            assertNull(activity.currentCompleteSelectionPreparation())
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertEquals(SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                activity.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID))
            assertEquals("retain", userData.getString("sentinel", null))
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun disappearingSelectedPeerRemainsUnselectedAfterItReturns() {
        withActivity(8) { activity, observations, _, _ ->
            val old = checkNotNull(activity.currentCompleteSelectionPreparation())
            CompleteListShadow.complete = listOf(info(7))
            observations.rows = listOf(ProfileSubscriptionObservation(7, 40, false, 0, 0))
            refresh(activity)
            assertFalse(observations.coordinator.isCurrent(old))
            assertNull(activity.currentCompleteSelectionPreparation())
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertEquals(listOf(7), state<List<Pair<Int, String>>>(activity, "sims").value.map { it.first })
            CompleteListShadow.complete = listOf(info(7), info(8))
            refresh(activity)
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertNull(activity.currentCompleteSelectionPreparation())
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(activity.conversationRepliesEnabled)
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }
}
