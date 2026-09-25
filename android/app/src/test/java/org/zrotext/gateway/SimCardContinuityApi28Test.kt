// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class SimCardContinuityApi28Test {
    @Test fun api28ProvidesNoPublicCardIdentityObservation() {
        assertNull(SimCardContinuity.observe(RuntimeEnvironment.getApplication()))
    }

    @Test fun api28CannotActivateAttributeOrUploadEvenWithSyntheticCardValues() {
        val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
        val device = UUID.fromString("22222222-2222-4222-8222-222222222222")
        val line = "33333333-3333-4333-8333-333333333333"
        val binding = LocalLineBinding(accountId = account.toString(),
            deviceId = device.toString(), lineId = line, generation = 1,
            subscriptionId = 7, installedAtMs = 1000, cardId = 42)
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            assertFalse(dao.installVerifiedLineBinding(binding, listOf(ActiveSimCard(7, 42))))
            val token = "a".repeat(64)
            assertTrue(dao.recordLocalWithdrawal(token, "b".repeat(64),
                InboundClassification.OPT_OUT, 7, listOf(ActiveSimCard(7, 42)), 2000,
                ByteArray(30), ByteArray(12)))
            val row = dao.localWithdrawal(token)!!
            assertNull(row.lineId)
            assertNull(row.encryptedSender)
            assertTrue(dao.isRecipientSuppressed("b".repeat(64)))
            assertFalse(LineOptOutUploadGate.allows(row.copy(lineId = line,
                bindingGeneration = 1, encryptedSender = ByteArray(30),
                senderNonce = ByteArray(12)), binding, account, device, 7,
                listOf(ActiveSimCard(7, 42)), 2500))
        } finally { db.close() }
    }
}
