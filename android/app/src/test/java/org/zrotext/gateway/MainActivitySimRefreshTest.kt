// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
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
import org.robolectric.shadows.ShadowSubscriptionManager.SubscriptionInfoBuilder
import java.util.UUID
import java.util.concurrent.Executor

/** Proposed source only. No device, SMS, HTTP or Keystore operation. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MainActivitySimRefreshTest {
    private fun id(value: Long) = UUID(0, value).toString()
    private fun refresh(activity: MainActivity) {
        MainActivity::class.java.getDeclaredMethod("refreshSims").apply { isAccessible = true }.invoke(activity)
    }
    @Suppress("UNCHECKED_CAST")
    private fun <T> state(activity: MainActivity, name: String) =
        MainActivity::class.java.getDeclaredField(name + "$" + "delegate")
            .apply { isAccessible = true }.get(activity) as MutableState<T>

    private fun withActivity(body: (MainActivity, SubscriptionManager) -> Unit) {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).grantPermissions(Manifest.permission.READ_PHONE_STATE)
        val manager = checkNotNull(app.getSystemService(SubscriptionManager::class.java))
        shadowOf(manager).setReadPhoneStatePermission(true)
        shadowOf(manager).setActiveSubscriptionInfos(
            SubscriptionInfoBuilder.newBuilder().setId(7).setSimSlotIndex(0).setDisplayName("Synthetic profile").build(),
            SubscriptionInfoBuilder.newBuilder().setId(8).setSimSlotIndex(1).setDisplayName("Synthetic peer").build())
        assertTrue(app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit()
            .putInt("subscription_id", 7).commit())
        val host = Robolectric.buildActivity(MainActivity::class.java).setup()
        try { body(host.get(), manager) }
        finally { shadowOf(manager).setReadPhoneStatePermission(true); host.pause().stop().destroy() }
    }

    @Test fun permissionReadFailureDuringRefreshCannotCrashOrKeepSavedSelection() {
        withActivity { activity, manager ->
            assertEquals(7, state<Int?>(activity, "selectedSim").value)
            // The app permission is still granted: only the later platform read refuses it.
            shadowOf(manager).setReadPhoneStatePermission(false)
            refresh(activity)
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertTrue(state<List<Pair<Int, String>>>(activity, "sims").value.isEmpty())
            assertEquals(SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                activity.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID))
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun failedRefreshRetiresLiveProfileAndWithdrawsReplyChoiceWithoutClearingUserData() {
        withActivity { activity, manager ->
            val source = object : ProfileObservationSource {
                override fun permissionGranted() = true
                override fun register(changed: () -> Unit): AutoCloseable { changed(); return AutoCloseable {} }
                override fun readComplete() = listOf(ProfileSubscriptionObservation(7, 40, true, 0, 0))
            }
            val persistence = object : ProfileChallengePersistence {
                private var ledger = ProfileChallengeLedger()
                override val serializationLock = Any()
                override fun read() = ledger
                override fun write(value: ProfileChallengeLedger): Boolean { ledger = value; return true }
            }
            val monitor = SimProfileMonitor(source, { it() }, Executor { it.run() })
            val fence = ProfileChallengeFence(persistence)
            val restore = SimProfileContinuity.replaceForTesting(monitor, fence)
            try {
                monitor.start()
                val candidate = checkNotNull(monitor.candidate(7))
                val key = ProfileChallengeKey(ProfileLineAuthority(id(1), id(2), id(3), 1), id(4))
                assertTrue(fence.reserveBeforeSigning(key, candidate))
                val permit = checkNotNull(fence.persistAcceptedAck(key, candidate))
                val installed = checkNotNull(monitor.currentTracker()).publishInstalled(permit) { true }
                assertNotNull(installed)
                state<Boolean>(activity, "conversationRepliesEnabled").value = true
                val preserved = activity.getSharedPreferences("sim_refresh_synthetic_data", Context.MODE_PRIVATE)
                assertTrue(preserved.edit().putString("sentinel", "retain").commit())
                shadowOf(manager).setReadPhoneStatePermission(false)
                refresh(activity)
                assertFalse(candidate.isCurrent())
                assertFalse(checkNotNull(installed).isCurrent())
                assertFalse(activity.conversationRepliesEnabled)
                assertEquals("retain", preserved.getString("sentinel", null))
                assertTrue(shadowOf(activity).allStartedServices.isEmpty())
            } finally { restore.close() }
        }
    }

    @Test fun readablePeerListAfterFailureNeverRecreatesSavedChoiceOrAuthority() {
        withActivity { activity, manager ->
            shadowOf(manager).setReadPhoneStatePermission(false)
            refresh(activity)
            shadowOf(manager).setReadPhoneStatePermission(true)
            refresh(activity)
            assertEquals(2, state<List<Pair<Int, String>>>(activity, "sims").value.size)
            assertNull(state<Int?>(activity, "selectedSim").value)
            assertFalse(activity.conversationRepliesEnabled)
            assertTrue(shadowOf(activity).allStartedServices.isEmpty())
        }
    }

    @Test fun readableListLosingSelectedProfileRetiresAuthorityWithoutSelectingPeer() {
        withActivity { activity, manager ->
            assertEquals(7, state<Int?>(activity, "selectedSim").value)
            val source = object : ProfileObservationSource {
                override fun permissionGranted() = true
                override fun register(changed: () -> Unit): AutoCloseable { changed(); return AutoCloseable {} }
                override fun readComplete() = listOf(
                    ProfileSubscriptionObservation(7, 40, true, 0, 0),
                    ProfileSubscriptionObservation(8, 40, true, 1, 1))
            }
            val persistence = object : ProfileChallengePersistence {
                private var ledger = ProfileChallengeLedger()
                override val serializationLock = Any()
                override fun read() = ledger
                override fun write(value: ProfileChallengeLedger): Boolean { ledger = value; return true }
            }
            val monitor = SimProfileMonitor(source, { it() }, Executor { it.run() })
            val fence = ProfileChallengeFence(persistence)
            val restore = SimProfileContinuity.replaceForTesting(monitor, fence)
            try {
                monitor.start()
                val candidate = checkNotNull(monitor.candidate(7))
                val key = ProfileChallengeKey(ProfileLineAuthority(id(1), id(2), id(3), 1), id(4))
                assertTrue(fence.reserveBeforeSigning(key, candidate))
                val permit = checkNotNull(fence.persistAcceptedAck(key, candidate))
                val installed = checkNotNull(checkNotNull(monitor.currentTracker()).publishInstalled(permit) { true })
                state<Boolean>(activity, "conversationRepliesEnabled").value = true
                // A successful platform read now exposes only the known peer profile.
                shadowOf(manager).setActiveSubscriptionInfos(SubscriptionInfoBuilder.newBuilder()
                    .setId(8).setSimSlotIndex(1).setDisplayName("Synthetic peer").build())
                refresh(activity)
                assertEquals(listOf(8), state<List<Pair<Int, String>>>(activity, "sims").value.map { it.first })
                assertNull(state<Int?>(activity, "selectedSim").value)
                assertEquals(SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                    activity.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                        .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID))
                assertFalse(candidate.isCurrent())
                assertFalse(installed.isCurrent())
                assertFalse(activity.conversationRepliesEnabled)
                assertTrue(shadowOf(activity).allStartedServices.isEmpty())
                // Repeated readable refresh cannot recreate the retired selected lease.
                refresh(activity)
                assertEquals(listOf(8), state<List<Pair<Int, String>>>(activity, "sims").value.map { it.first })
                assertNull(state<Int?>(activity, "selectedSim").value)
                assertFalse(installed.isCurrent())
                assertFalse(activity.conversationRepliesEnabled)
                assertTrue(shadowOf(activity).allStartedServices.isEmpty())
            } finally { restore.close() }
        }
    }
}
