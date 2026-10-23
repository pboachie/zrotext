// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import androidx.room.util.TableInfo
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class LineActivationV2JournalRoomTest {
    private inline fun <R> SmsJournalDatabase.useJournal(block: (SmsJournalDatabase) -> R): R =
        java.io.Closeable { close() }.use { block(this) }

    @Test fun freshSchemaPersistsOnlyNonceFreeProvenanceAndColdReadGrantsNothing() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.runtime.accept(f.receipt(proof))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        val columns = TableInfo.read(f.db.openHelper.readableDatabase, "line_activation_v2").columns
        assertEquals(setOf("purpose", "challengeId", "accountId", "deviceId", "lineId", "generation",
            "expiresAtMs", "proofConnectionEpoch", "originHash", "signerFingerprint", "observationB64url",
            "state", "signatureDerB64url", "statementSha256", "signatureSha256", "confirmationSha256"), columns.keys)
        assertTrue(columns.values.all { it.type in setOf("TEXT", "INTEGER") })
        assertEquals(121, LineActivationV2JournalEncoding.decode(proof.observationB64url).size)
        assertTrue(binding.liveContinuity())
        assertNull(binding.copy(subscriptionId = binding.subscriptionId + 1).installedSelectionV2())
        assertFalse(binding.copy(slot = 2).liveContinuity())
        LineActivationV2SelectedLineMount.detach(f.owner)
        assertTrue(checkNotNull(f.db.lineActivationsV2().find("sms", f.challengeId.toString())).isInstalled())
        assertNull(binding.installedSelectionV2()); assertNull(binding.activatedSim()); assertFalse(binding.liveContinuity())
    }

    @Test fun reservationAndFinalTransactionRollBackWhenAuthorityRetiresAfterWrite() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        val dao = f.db.lineActivationsV2()
        val reserved = proof.copy(challengeId = UUID(0, 8).toString(), state = "reserved",
            signatureDerB64url = null, statementSha256 = null, signatureSha256 = null, confirmationSha256 = null)
        var checks = 0
        assertThrows(IllegalStateException::class.java) { dao.reserve(reserved) { checks++; check(checks == 1) } }
        assertNull(dao.find(reserved.purpose, reserved.challengeId))
        checks = 0
        assertThrows(IllegalStateException::class.java) {
            dao.recordFinal(proof, proof.binding(f.selected, f.now)) { checks++; check(checks == 1) }
        }
        assertNull(f.db.attempts().currentLineBinding())
        assertEquals("signed", dao.find(proof.purpose, proof.challengeId)?.state)
        assertFalse(dao.recordSigned(proof.copy(signatureSha256 = "f".repeat(64))) {})
        assertEquals(proof, dao.find(proof.purpose, proof.challengeId))
    }

    @Test fun nullCardOptOutCandidateStillRequiresLiveTupleGenerationAgeAndWholeSet() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof(); f.runtime.accept(f.receipt(proof))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        val dao = f.db.attempts()
        assertTrue(dao.recordLocalWithdrawal("a".repeat(64), "b".repeat(64), InboundClassification.OPT_OUT,
            f.selected, f.cards(), f.now + 1, ByteArray(32) { 1 }, ByteArray(12) { 2 }))
        val queued = checkNotNull(dao.nextLineOptOut(f.now))
        assertNull(binding.cardId)
        assertTrue(LineOptOutUploadGate.allows(queued, binding, f.account, f.device, f.selected, f.cards(), f.now + 2))
        assertNull(dao.nextLineOptOut(f.now + 2))
        f.db.openHelper.writableDatabase.execSQL("UPDATE local_inbound_withdrawals SET bindingGeneration = 2")
        assertNull(dao.nextLineOptOut(f.now))
        f.db.openHelper.writableDatabase.execSQL("UPDATE local_inbound_withdrawals SET bindingGeneration = 1")
        f.owner.retireAtEntry()
        assertNotNull(dao.nextLineOptOut(f.now))
        assertFalse(LineOptOutUploadGate.allows(queued, binding, f.account, f.device, f.selected, f.cards(), f.now + 2))
    }

    @Test fun versionThirteenUpgradePreservesLegacyPhysicalBindingAndIntroducesEmptyV2Journal() {
        val context = RuntimeEnvironment.getApplication()
        // Robolectric gives this test its own context; keep the native SQLite path short.
        val name = "v2.db"
        val legacy = LocalLineBinding(accountId = UUID(0, 1).toString(), deviceId = UUID(0, 2).toString(),
            lineId = UUID(0, 3).toString(), generation = 4, subscriptionId = 7, installedAtMs = 1, cardId = 20)
        try {
            val directory = checkNotNull(context.getDatabasePath(name).parentFile)
            directory.mkdirs()
            assertTrue("Database parent must exist before native SQLite opens it", directory.isDirectory)
            Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build().useJournal { db ->
                assertTrue(db.attempts().installVerifiedLineBinding(legacy, listOf(ActiveSimCard(7, 20))))
            }
            context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null).use { old ->
                old.execSQL("CREATE TABLE binding_v13 (slot INTEGER NOT NULL PRIMARY KEY, accountId TEXT NOT NULL, deviceId TEXT NOT NULL, lineId TEXT NOT NULL, generation INTEGER NOT NULL, subscriptionId INTEGER NOT NULL, installedAtMs INTEGER NOT NULL, cardId INTEGER DEFAULT NULL, continuityKind TEXT NOT NULL DEFAULT 'physical', profilePortIndex INTEGER DEFAULT NULL, profileLogicalSlotIndex INTEGER DEFAULT NULL, profileIncarnation TEXT DEFAULT NULL, profileObservationEpoch INTEGER DEFAULT NULL, profileLeaseId TEXT DEFAULT NULL)")
                old.execSQL("INSERT INTO binding_v13 SELECT slot,accountId,deviceId,lineId,generation,subscriptionId,installedAtMs,cardId,continuityKind,profilePortIndex,profileLogicalSlotIndex,profileIncarnation,profileObservationEpoch,profileLeaseId FROM local_line_binding")
                old.execSQL("DROP TABLE local_line_binding")
                old.execSQL("ALTER TABLE binding_v13 RENAME TO local_line_binding")
                old.execSQL("DROP TABLE line_activation_v2")
                old.version = 13
            }
            Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
                .addMigrations(SmsJournalDatabase.MIGRATION_13_14, SmsJournalDatabase.MIGRATION_14_15, SmsJournalDatabase.MIGRATION_15_16, SmsJournalDatabase.MIGRATION_16_17, SmsJournalDatabase.MIGRATION_17_18, SmsJournalDatabase.MIGRATION_18_19, SmsJournalDatabase.MIGRATION_19_20, SmsJournalDatabase.MIGRATION_20_21, SmsJournalDatabase.MIGRATION_21_22, SmsJournalDatabase.MIGRATION_22_23, SmsJournalDatabase.MIGRATION_23_24).build().useJournal { migrated ->
                    assertEquals(24, migrated.openHelper.readableDatabase.version)
                    assertEquals(legacy, migrated.attempts().currentLineBinding())
                    assertTrue(checkNotNull(migrated.attempts().currentLineBinding()).liveContinuity())
                    assertNull(migrated.lineActivationsV2().find("sms", UUID(0, 8).toString()))
                    migrated.openHelper.readableDatabase.query("SELECT COUNT(*) FROM line_activation_v2").use {
                        assertTrue(it.moveToFirst()); assertEquals(0, it.getInt(0))
                    }
                }
        } finally { context.deleteDatabase(name) }
    }
}
