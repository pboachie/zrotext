// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import androidx.room.Room
import java.util.concurrent.Executor
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk = [28])
class ConversationAndroidConnectionInputsTest {
    private val f = ConversationInputFixture
    private val context get() = RuntimeEnvironment.getApplication()
    private val db = Room.inMemoryDatabaseBuilder(context, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private var live: ConversationPhoneSession? = f.session
    private var dispatches = 0
    private val provider get() = ConversationAndroidConnectionInputs(context, db.attempts(), "fixture-existing-payload",
        Executor { it.run() }, { live }, object : ConversationSendTransport {
            override fun submit(message: String, attempt: String, scope: ConversationCaptureScope,
                                body: String): ConversationSubmission { dispatches++; error("No grant fixture") }
        })
    private fun line() = LocalLineBinding(accountId = f.scope.accountId, deviceId = f.scope.deviceId,
        lineId = f.scope.lineId, generation = 1, subscriptionId = 3, installedAtMs = 1, cardId = 4)
    @After fun close() { db.close() }

    @Test fun persistedLineSelectedSimAndPhysicalCardMustAllMatch() {
        val line = line(); val cards = listOf(ActiveSimCard(3, 4))
        fun loss(binding: LocalLineBinding? = line, selected: Int = 3, active: List<ActiveSimCard>? = cards) =
            ConversationAndroidConnectionInputs.localLoss(f.scope, binding, selected, active)
        assertNull(loss())
        assertEquals(ConversationStopReason.LINE_CHANGED, loss(line.copy(generation = 2)))
        assertEquals(ConversationStopReason.LINE_CHANGED, loss(line.copy(accountId = java.util.UUID.randomUUID().toString())))
        assertEquals(ConversationStopReason.SIM_CHANGED, loss(selected = 5))
        assertEquals(ConversationStopReason.SIM_CHANGED, loss(active = listOf(ActiveSimCard(3, 5))))
        assertEquals(ConversationStopReason.SIM_CHANGED, loss(active = listOf(ActiveSimCard(3, 4, true))))
        assertEquals(ConversationStopReason.SIM_CHANGED, loss(active = null))
        assertEquals(ConversationStopReason.SIM_CHANGED, loss(line.copy(cardId = null)))
    }
    @Test fun constructionAndFailedOpenPublishNoJournalsOrDispatch() {
        val record = PayloadKeyLifecycleFileStore.recordFile(context, "fixture-existing-payload")
        assertFalse(record.exists())
        val provider = provider
        assertFalse(record.exists())
        assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        f.refuse { provider.openForUserAction(f.session, f.scope, f.review, 0,
            ConversationConnectionBindings(ByteArray(65), ByteArray(32))) }
        assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        assertFalse(record.exists())
        assertEquals(0, dispatches)
    }
    @Test fun permissionSessionAndCloseLossFenceOwnedCallbacks() {
        val provider = provider
        val decision = ConversationPhoneDecision(f.session, f.scope, f.review, 0, { 1 }, { live })
        val owned = provider.Owned(f.session, f.scope, decision, ConversationJournalStores(context),
            Draft02AndroidTrustStorage(context))
        assertEquals(ConversationStopReason.PERMISSION_LOST, owned.loss())
        shadowOf(context).grantPermissions(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_PHONE_STATE)
        // API28 cannot establish card continuity, even with permissions or saved selection.
        context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit().putInt("subscription_id", 3).commit()
        assertEquals(ConversationStopReason.PERMISSION_LOST, owned.loss())
        assertNull(owned.observedLine(3))
        val other = provider.Owned(f.session, f.scope,
            ConversationPhoneDecision(f.session, f.scope, f.review, 0, { 1 }, { live }),
            ConversationJournalStores(context), Draft02AndroidTrustStorage(context))
        live = null
        assertEquals(ConversationStopReason.PHONE_SESSION_LOST, other.loss())
        live = f.session
        assertEquals(ConversationStopReason.PHONE_SESSION_LOST, other.loss())
        other.close()
        live = f.session; owned.close(); owned.close()
        assertEquals(ConversationStopReason.PHONE_SESSION_LOST, owned.loss())
        f.refuse { owned.requireLocal(f.scope) }
        f.refuse { owned.inputs }
        f.refuse { decision.approve(f.review.requestId, 7) }
        assertEquals(0, dispatches)
    }
    @Test fun throwingPresentationCloseStillClosesBothOwnedStoresAndAdmissionInputs() {
        val decision = ConversationPhoneDecision(f.session, f.scope, f.review, 0, { 1 }, { live })
        decision.observePresentation(object : ConversationPresentationPort {
            override fun observe(listener: (ConversationPresentationSnapshot) -> Unit) = AutoCloseable {
                error("Synthetic observation close failure")
            }
            override fun refresh() = Unit
            override fun approvePhoneReview(requestId: String, observedVersion: Long) = Unit
            override fun declinePhoneReview(requestId: String, observedVersion: Long) = Unit
            override fun requestStop(intervalId: String, observedVersion: Long) = Unit
        })
        val journals = ConversationJournalStores(context)
        val storage = Draft02AndroidTrustStorage(context)
        val owned = provider.Owned(f.session, f.scope, decision, journals, storage)
        f.refuse { owned.close() }
        try { journals.openForUserAction(); fail("Closed journals reopened") }
        catch (failure: ConversationJournalStores.Failure) { assertEquals(ConversationJournalStores.Reason.CLOSED, failure.reason) }
        try { storage.locked { keyState() }; fail("Closed trust store accepted") }
        catch (failure: Draft02TrustStore.Failure) { assertEquals(Draft02TrustStore.Status.IO_FAILURE, failure.status) }
        f.refuse { owned.inputs }
        owned.close()
    }
}
