// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.pm.ApplicationInfo
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import android.os.Build
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Historical data-schema controls on owned databases, not an old-APK or radio rehearsal. */
@RunWith(AndroidJUnit4::class)
class JournalDeviceUpgradeTest {
    @Test fun versionOnePlatformMigrationRetainsUnknownAttemptAcrossReopen() {
        withOwnedDatabase(1, ::seedVersionOne) { db, reopened ->
            val dao = db.attempts()
            if (!reopened) {
                assertEquals(SmsAttempt(ATTEMPT, 3, 1, AttemptState.SUBMITTING, 100, 100), dao.getAttempt(ATTEMPT))
                recoverJournalState(dao, 200)
            }
            val expected = SmsAttempt(ATTEMPT, 3, 1, AttemptState.UNKNOWN, 100, 200)
            assertEquals(expected, dao.getAttempt(ATTEMPT))
            assertEquals(listOf(SmsSegment(ATTEMPT, 0)), dao.getSegments(ATTEMPT))
            assertEquals(0L, count(db, "alpha_radio_events"))
            assertEquals(0L, count(db, "sealed_preparations"))
            assertNull(dao.currentLineBinding())
            assertThrows(SQLiteConstraintException::class.java) { dao.reserve(ATTEMPT, 3, 1, 300) }
            assertEquals(expected, dao.getAttempt(ATTEMPT))
            assertEquals(listOf(SmsSegment(ATTEMPT, 0)), dao.getSegments(ATTEMPT))
            assertEquals(0, dao.consumeRadioStart(ATTEMPT, OTHER_MESSAGE, 3, 1, 300))
            assertEquals(expected, dao.getAttempt(ATTEMPT))
        }
    }

    @Test fun versionElevenPlatformMigrationRetainsBoundEvidenceAndStopAcrossReopen() {
        withOwnedDatabase(11, ::seedVersionEleven) { db, reopened ->
            assertVersionElevenState(db)
            if (!reopened) recoverJournalState(db.attempts(), 300)
            assertVersionElevenState(db)
            assertThrows(SQLiteConstraintException::class.java) { db.attempts().reserve(ATTEMPT, 3, 1, 300) }
            assertEquals(0, db.attempts().consumeRadioStart(ATTEMPT, MESSAGE, 3, 1, 300))
            assertVersionElevenState(db)
        }
    }

    private fun isolatedContext(): Context {
        assumeTrue(InstrumentationRegistry.getArguments().getString("journalUpgradeIsolatedEmulator") == "true")
        assumeTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(context.packageName == "org.zrotext.gateway")
        assumeTrue(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        return context
    }

    private fun withOwnedDatabase(version: Int, seed: (SQLiteDatabase) -> Unit,
                                  verify: (SmsJournalDatabase, Boolean) -> Unit) {
        val context = isolatedContext() // Refuse before even choosing or opening a database.
        require(version == 1 || version == 11)
        val name = "journal-upgrade-v$version-${UUID.randomUUID()}.db"
        val path = context.getDatabasePath(name)
        assertTrue(listOf("", "-wal", "-shm", "-journal").none { File(path.path + it).exists() })
        var legacy: SQLiteDatabase? = null
        var room: SmsJournalDatabase? = null
        var owned = false
        try {
            val old = context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null)
            legacy = old
            owned = true
            old.setForeignKeyConstraintsEnabled(true)
            old.beginTransaction()
            try {
                legacyStatements(version).forEach(old::execSQL)
                seed(old)
                old.version = version
                old.setTransactionSuccessful()
            } finally {
                old.endTransaction()
            }
            assertHistoricalSchema(old, version)
            old.close()
            legacy = null

            val first = openCurrent(context, name, version)
            room = first
            val identity = assertCurrentSchema(first) // Force migration and generated Room validation.
            verify(first, false)
            assertEquals(identity, assertCurrentSchema(first))
            first.close()
            room = null

            val second = openCurrent(context, name, version)
            room = second
            assertEquals(identity, assertCurrentSchema(second))
            verify(second, true)
            assertEquals(identity, assertCurrentSchema(second))
        } finally {
            try {
                room?.close()
            } finally {
                try {
                    legacy?.close()
                } finally {
                    // Only this successfully opened unique database is owned by this invocation.
                    if (owned) {
                        assertTrue(context.deleteDatabase(name))
                        assertFalse(listOf("", "-wal", "-shm", "-journal").any { File(path.path + it).exists() })
                    }
                }
            }
        }
    }

    private fun openCurrent(context: Context, name: String, version: Int): SmsJournalDatabase {
        val migrations: Array<Migration> = if (version == 1) arrayOf(
            SmsJournalDatabase.MIGRATION_1_2, SmsJournalDatabase.MIGRATION_2_3,
            SmsJournalDatabase.MIGRATION_3_4, SmsJournalDatabase.MIGRATION_4_5,
            SmsJournalDatabase.MIGRATION_5_6, SmsJournalDatabase.MIGRATION_6_7,
            SmsJournalDatabase.MIGRATION_7_8, SmsJournalDatabase.MIGRATION_8_9,
            SmsJournalDatabase.MIGRATION_9_10, SmsJournalDatabase.MIGRATION_10_11,
            SmsJournalDatabase.MIGRATION_11_12, SmsJournalDatabase.MIGRATION_12_13,
        ) else arrayOf(SmsJournalDatabase.MIGRATION_11_12, SmsJournalDatabase.MIGRATION_12_13)
        return Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(*migrations).build()
    }

    private fun assertCurrentSchema(room: SmsJournalDatabase): String {
        val db = room.openHelper.writableDatabase
        assertEquals(13, db.version)
        val expectedBindingColumns = legacyColumns(11).getValue("local_line_binding") + listOf(
            Column("continuityKind", "TEXT", true, "'physical'"),
            Column("profilePortIndex", "INTEGER", false, "NULL"),
            Column("profileLogicalSlotIndex", "INTEGER", false, "NULL"),
            Column("profileIncarnation", "TEXT", false, "NULL"),
            Column("profileObservationEpoch", "INTEGER", false, "NULL"),
            Column("profileLeaseId", "TEXT", false, "NULL"),
        )
        val bindingColumns = mutableListOf<Column>()
        db.query("PRAGMA table_info(`local_line_binding`)").use { cursor ->
            while (cursor.moveToNext()) bindingColumns.add(Column(
                cursor.getString(cursor.getColumnIndexOrThrow("name")),
                cursor.getString(cursor.getColumnIndexOrThrow("type")),
                cursor.getInt(cursor.getColumnIndexOrThrow("notnull")) == 1,
                cursor.getColumnIndexOrThrow("dflt_value").let { if (cursor.isNull(it)) null else cursor.getString(it) },
                cursor.getInt(cursor.getColumnIndexOrThrow("pk")),
            ))
        }
        assertEquals(expectedBindingColumns, bindingColumns)
        db.query("PRAGMA foreign_key_check").use { assertFalse(it.moveToFirst()) }
        val tables = mutableSetOf<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'").use { cursor ->
            while (cursor.moveToNext()) {
                val table = cursor.getString(0)
                if (isApplicationTable(table)) tables.add(table)
            }
        }
        assertEquals(legacyColumns(11).keys + "sealed_preparations", tables)
        val indexes = mutableSetOf<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'index'").use { cursor ->
            while (cursor.moveToNext()) {
                val index = cursor.getString(0)
                if (!index.startsWith("sqlite_")) indexes.add(index)
            }
        }
        assertEquals(legacyIndexes(11).map { it.name }.toSet() + "index_sealed_preparations_attemptId", indexes)
        return db.query("SELECT identity_hash FROM room_master_table WHERE id = 42").use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            assertFalse(cursor.isNull(0))
            cursor.getString(0).also { assertTrue(it.isNotBlank()) }
        }
    }

    private fun seedVersionOne(db: SQLiteDatabase) {
        db.execSQL("INSERT INTO sms_attempts VALUES (?,3,1,'submitting',100,100)", arrayOf(ATTEMPT))
        db.execSQL("INSERT INTO sms_segments(attemptId,segmentIndex) VALUES (?,0)", arrayOf(ATTEMPT))
    }

    private fun seedVersionEleven(db: SQLiteDatabase) {
        db.execSQL("INSERT INTO sms_attempts VALUES (?,3,1,'unknown',100,100,1,?,?,?,?)",
            arrayOf(ATTEMPT, MESSAGE, ACCOUNT, DEVICE, ORIGIN))
        db.execSQL("INSERT INTO sms_segments VALUES (?,0,-1,NULL,NULL)", arrayOf(ATTEMPT))
        db.execSQL("INSERT INTO alpha_radio_events VALUES (?,?,?,'callback_conflict',150,0,1,NULL,?,?,?,NULL,NULL)",
            arrayOf(PENDING_EVENT, MESSAGE, ATTEMPT, ACCOUNT, DEVICE, ORIGIN))
        db.execSQL("INSERT INTO alpha_radio_events VALUES (?,?,?,'durable_submit_intent',100,NULL,1,200,?,?,?,NULL,NULL)",
            arrayOf(ACKED_EVENT, MESSAGE, ATTEMPT, ACCOUNT, DEVICE, ORIGIN))
        db.execSQL("INSERT INTO local_recipient_suppressions VALUES (?,100)", arrayOf(SENDER))
        db.execSQL("INSERT INTO local_line_binding VALUES (1,?,?,?,7,3,100,42)", arrayOf(ACCOUNT, DEVICE, LINE))
        db.execSQL("INSERT INTO local_inbound_withdrawals(dedupeToken,senderToken,classification,observedSubscriptionId,receivedAtMs) VALUES (?,?,'opt_out',3,150)",
            arrayOf(DEDUPE, SENDER))
    }

    private fun assertVersionElevenState(db: SmsJournalDatabase) {
        val dao = db.attempts()
        assertEquals(SmsAttempt(ATTEMPT, 3, 1, AttemptState.UNKNOWN, 100, 100, true,
            MESSAGE, ACCOUNT, DEVICE, ORIGIN), dao.getAttempt(ATTEMPT))
        assertEquals(listOf(SmsSegment(ATTEMPT, 0, -1)), dao.getSegments(ATTEMPT))
        val pending = AlphaRadioEvent(PENDING_EVENT, MESSAGE, ATTEMPT, "callback_conflict", 150,
            segmentIndex = 0, segmentCount = 1, accountId = ACCOUNT, deviceId = DEVICE, originHash = ORIGIN)
        val acknowledged = AlphaRadioEvent(ACKED_EVENT, MESSAGE, ATTEMPT, "durable_submit_intent", 100,
            segmentCount = 1, acknowledgedAtMs = 200, accountId = ACCOUNT, deviceId = DEVICE, originHash = ORIGIN)
        assertEquals(pending, dao.getAlphaEvent(PENDING_EVENT))
        assertEquals(acknowledged, dao.getAlphaEvent(ACKED_EVENT))
        assertEquals(pending, dao.nextAlphaEvent(ACCOUNT, DEVICE, ORIGIN))
        assertNull(dao.nextAlphaEvent(OTHER_ACCOUNT, DEVICE, ORIGIN))
        assertEquals(2L, count(db, "alpha_radio_events"))
        assertEquals(0L, count(db, "sealed_preparations"))
        assertTrue(dao.isRecipientSuppressed(SENDER))
        db.openHelper.readableDatabase.query("SELECT observedAtMs FROM local_recipient_suppressions WHERE senderToken = ?",
            arrayOf(SENDER)).use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            assertEquals(100L, cursor.getLong(0))
        }
        assertEquals(LocalLineBinding(accountId = ACCOUNT, deviceId = DEVICE, lineId = LINE,
            generation = 7, subscriptionId = 3, installedAtMs = 100, cardId = 42), dao.currentLineBinding())
        assertEquals("physical", dao.currentLineBinding()?.continuityKind)
        assertNull(dao.currentLineBinding()?.profileRecord())
        assertEquals(LocalInboundWithdrawal(DEDUPE, SENDER, "opt_out", 3, null, null, 150), dao.localWithdrawal(DEDUPE))
        assertNull(dao.nextLineOptOut(0))
        assertEquals(0L, count(db, "local_withdrawal_sequences"))
        assertEquals(1L, count(db, "local_inbound_withdrawals"))
        assertEquals(1L, count(db, "local_recipient_suppressions"))
        assertEquals(1L, count(db, "local_line_binding"))
    }

    private fun count(db: SmsJournalDatabase, table: String): Long =
        db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM `$table`").use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getLong(0)
        }

    private data class Column(val name: String, val type: String, val required: Boolean,
                              val default: String? = null, val primary: Int = 0)
    private data class LegacyIndex(val table: String, val name: String, val unique: Boolean,
                                   val columns: List<String>)

    private fun assertHistoricalSchema(db: SQLiteDatabase, version: Int) {
        assertEquals(version, db.version)
        db.rawQuery("PRAGMA foreign_key_check", null).use { assertFalse(it.moveToFirst()) }
        assertEquals(1L, db.rawQuery("PRAGMA foreign_keys", null).use { it.moveToFirst(); it.getLong(0) })
        val tables = mutableSetOf<String>()
        db.rawQuery("SELECT name FROM sqlite_master WHERE type = 'table'", null).use { cursor ->
            while (cursor.moveToNext()) {
                val table = cursor.getString(0)
                if (isApplicationTable(table)) tables.add(table)
                assertFalse(table == "room_master_table") // No invented historical identity.
            }
        }
        val expectedColumns = legacyColumns(version)
        assertEquals(expectedColumns.keys, tables)
        for ((table, expected) in expectedColumns) {
            val columns = mutableListOf<Column>()
            db.rawQuery("PRAGMA table_info(`$table`)", null).use { cursor ->
                while (cursor.moveToNext()) columns.add(Column(
                    cursor.getString(cursor.getColumnIndexOrThrow("name")),
                    cursor.getString(cursor.getColumnIndexOrThrow("type")),
                    cursor.getInt(cursor.getColumnIndexOrThrow("notnull")) == 1,
                    cursor.getColumnIndexOrThrow("dflt_value").let { if (cursor.isNull(it)) null else cursor.getString(it) },
                    cursor.getInt(cursor.getColumnIndexOrThrow("pk")),
                ))
            }
            assertEquals(expected, columns)
            val expectedParent = when (table) {
                "sms_segments", "alpha_radio_events", "inbound_windows" -> "sms_attempts"
                "inbound_events" -> "inbound_windows"
                "inbound_uploads" -> "inbound_events"
                else -> null
            }
            val foreign = mutableListOf<List<String>>()
            db.rawQuery("PRAGMA foreign_key_list(`$table`)", null).use { cursor ->
                while (cursor.moveToNext()) foreign.add(listOf("table", "from", "to", "on_update", "on_delete")
                    .map { cursor.getString(cursor.getColumnIndexOrThrow(it)) })
            }
            val key = if (table == "inbound_uploads") "eventId" else "attemptId"
            assertEquals(if (expectedParent == null) emptyList<List<String>>() else
                listOf(listOf(expectedParent, key, key, "NO ACTION", "CASCADE")), foreign)
        }
        val expectedIndexes = legacyIndexes(version)
        val named = mutableSetOf<String>()
        for (table in expectedColumns.keys) {
            db.rawQuery("PRAGMA index_list(`$table`)", null).use { cursor ->
                while (cursor.moveToNext()) {
                    val name = cursor.getString(cursor.getColumnIndexOrThrow("name"))
                    val unique = cursor.getInt(cursor.getColumnIndexOrThrow("unique")) == 1
                    val origin = cursor.getString(cursor.getColumnIndexOrThrow("origin"))
                    assertEquals(0, cursor.getInt(cursor.getColumnIndexOrThrow("partial")))
                    val columns = mutableListOf<String>()
                    db.rawQuery("PRAGMA index_info(`$name`)", null).use { info ->
                        while (info.moveToNext()) {
                            assertEquals(columns.size, info.getInt(info.getColumnIndexOrThrow("seqno")))
                            columns.add(info.getString(info.getColumnIndexOrThrow("name")))
                        }
                    }
                    if (origin == "pk") {
                        assertTrue(unique)
                        assertEquals(expectedColumns.getValue(table).filter { it.primary > 0 }
                            .sortedBy { it.primary }.map { it.name }, columns)
                    } else {
                        assertEquals("c", origin)
                        val expected = expectedIndexes.single { it.name == name }
                        assertEquals(table, expected.table)
                        assertEquals(expected.unique, unique)
                        assertEquals(expected.columns, columns)
                        named.add(name)
                    }
                }
            }
        }
        assertEquals(expectedIndexes.map { it.name }.toSet(), named)
    }

    private fun isApplicationTable(name: String): Boolean =
        !name.startsWith("sqlite_") && name != "android_metadata" && name != "room_master_table"

    // Independent historical annotations: c70eefbe (v1), b22e3cc1 (v11).
    // Kotlin nullable constructor defaults are not SQL defaults unless annotated.
    private fun legacyColumns(version: Int): Map<String, List<Column>> {
        val attempts = listOf(Column("attemptId", "TEXT", true, primary = 1),
            Column("subscriptionId", "INTEGER", true), Column("segmentCount", "INTEGER", true),
            Column("state", "TEXT", true), Column("createdAtMs", "INTEGER", true), Column("updatedAtMs", "INTEGER", true))
        val tables = linkedMapOf(
            "sms_attempts" to attempts,
            "sms_segments" to listOf(Column("attemptId", "TEXT", true, primary = 1),
                Column("segmentIndex", "INTEGER", true, primary = 2), Column("sentResultCode", "INTEGER", false),
                Column("deliveryResultCode", "INTEGER", false), Column("deliveryStatus", "INTEGER", false)),
        )
        if (version == 1) return tables
        tables["sms_attempts"] = attempts + listOf(Column("evidenceConflict", "INTEGER", true, "0"),
            Column("messageId", "TEXT", false, "NULL"), Column("accountId", "TEXT", false, "NULL"),
            Column("deviceId", "TEXT", false, "NULL"), Column("originHash", "TEXT", false, "NULL"))
        tables["alpha_radio_events"] = listOf(Column("eventId", "TEXT", true, primary = 1),
            Column("messageId", "TEXT", true), Column("attemptId", "TEXT", true), Column("evidence", "TEXT", true),
            Column("observedAtMs", "INTEGER", true), Column("segmentIndex", "INTEGER", false),
            Column("segmentCount", "INTEGER", false), Column("acknowledgedAtMs", "INTEGER", false),
            Column("accountId", "TEXT", false, "NULL"), Column("deviceId", "TEXT", false, "NULL"),
            Column("originHash", "TEXT", false, "NULL"), Column("quarantinedAtMs", "INTEGER", false, "NULL"),
            Column("quarantineReason", "TEXT", false, "NULL"))
        tables["inbound_windows"] = listOf(Column("attemptId", "TEXT", true, primary = 1),
            Column("messageId", "TEXT", true), Column("senderToken", "TEXT", true), Column("subscriptionId", "INTEGER", true),
            Column("opensAtMs", "INTEGER", true), Column("closesAtMs", "INTEGER", true))
        tables["inbound_events"] = listOf(Column("eventId", "TEXT", true, primary = 1),
            Column("attemptId", "TEXT", true), Column("messageId", "TEXT", true), Column("dedupeToken", "TEXT", true),
            Column("observedSubscriptionId", "INTEGER", false), Column("receivedAtMs", "INTEGER", true),
            Column("partCount", "INTEGER", true), Column("classification", "TEXT", true),
            Column("encryptedBody", "BLOB", false), Column("nonce", "BLOB", false))
        tables["inbound_uploads"] = listOf(Column("sequence", "INTEGER", true, primary = 1),
            Column("eventId", "TEXT", true), Column("accountId", "TEXT", false), Column("deviceId", "TEXT", false),
            Column("signatureDer", "BLOB", false), Column("acknowledgedAtMs", "INTEGER", false),
            Column("originHash", "TEXT", false, "NULL"), Column("quarantinedAtMs", "INTEGER", false, "NULL"),
            Column("quarantineReason", "TEXT", false, "NULL"))
        tables["local_recipient_suppressions"] = listOf(Column("senderToken", "TEXT", true, primary = 1),
            Column("observedAtMs", "INTEGER", true))
        tables["local_line_binding"] = listOf(Column("slot", "INTEGER", true, primary = 1),
            Column("accountId", "TEXT", true), Column("deviceId", "TEXT", true), Column("lineId", "TEXT", true),
            Column("generation", "INTEGER", true), Column("subscriptionId", "INTEGER", true),
            Column("installedAtMs", "INTEGER", true), Column("cardId", "INTEGER", false, "NULL"))
        tables["local_withdrawal_sequences"] = listOf(Column("sequence", "INTEGER", true, primary = 1),
            Column("eventId", "TEXT", true))
        tables["local_inbound_withdrawals"] = listOf(Column("dedupeToken", "TEXT", true, primary = 1),
            Column("senderToken", "TEXT", true), Column("classification", "TEXT", true),
            Column("observedSubscriptionId", "INTEGER", false), Column("lineId", "TEXT", false),
            Column("bindingGeneration", "INTEGER", false), Column("receivedAtMs", "INTEGER", true),
            Column("eventId", "TEXT", false, "NULL"), Column("deviceSequence", "INTEGER", false, "NULL"),
            Column("encryptedSender", "BLOB", false, "NULL"), Column("senderNonce", "BLOB", false, "NULL"),
            Column("signatureDer", "BLOB", false, "NULL"), Column("acknowledgedAtMs", "INTEGER", false, "NULL"))
        return tables
    }

    private fun legacyIndexes(version: Int): List<LegacyIndex> {
        val first = LegacyIndex("sms_segments", "index_sms_segments_attemptId", false, listOf("attemptId"))
        if (version == 1) return listOf(first)
        return listOf(first,
            LegacyIndex("alpha_radio_events", "index_alpha_radio_events_attemptId", false, listOf("attemptId")),
            LegacyIndex("alpha_radio_events", "index_alpha_radio_events_acknowledgedAtMs_observedAtMs", false, listOf("acknowledgedAtMs", "observedAtMs")),
            LegacyIndex("inbound_windows", "index_inbound_windows_senderToken", false, listOf("senderToken")),
            LegacyIndex("inbound_events", "index_inbound_events_attemptId", false, listOf("attemptId")),
            LegacyIndex("inbound_events", "index_inbound_events_dedupeToken", true, listOf("dedupeToken")),
            LegacyIndex("inbound_uploads", "index_inbound_uploads_eventId", true, listOf("eventId")),
            LegacyIndex("inbound_uploads", "index_inbound_uploads_acknowledgedAtMs_sequence", false, listOf("acknowledgedAtMs", "sequence")),
            LegacyIndex("local_withdrawal_sequences", "index_local_withdrawal_sequences_eventId", true, listOf("eventId")),
            LegacyIndex("local_inbound_withdrawals", "index_local_inbound_withdrawals_senderToken", false, listOf("senderToken")),
            LegacyIndex("local_inbound_withdrawals", "index_local_inbound_withdrawals_eventId", true, listOf("eventId")),
            LegacyIndex("local_inbound_withdrawals", "index_local_inbound_withdrawals_acknowledgedAtMs_deviceSequence", false, listOf("acknowledgedAtMs", "deviceSequence")),
        )
    }

    // Historical DDL is transcribed independently; no current migration constructs these fixtures.
    private fun legacyStatements(version: Int): List<String> = if (version == 1) VERSION_ONE_DDL else VERSION_ELEVEN_DDL

    private companion object {
        const val ATTEMPT = "11111111-1111-4111-8111-111111111111"
        const val MESSAGE = "22222222-2222-4222-8222-222222222222"
        const val OTHER_MESSAGE = "33333333-3333-4333-8333-333333333333"
        const val ACCOUNT = "44444444-4444-4444-8444-444444444444"
        const val DEVICE = "55555555-5555-4555-8555-555555555555"
        const val LINE = "66666666-6666-4666-8666-666666666666"
        const val PENDING_EVENT = "77777777-7777-4777-8777-777777777777"
        const val ACKED_EVENT = "88888888-8888-4888-8888-888888888888"
        const val OTHER_ACCOUNT = "99999999-9999-4999-8999-999999999999"
        val ORIGIN = "a".repeat(64)
        val SENDER = "b".repeat(64)
        val DEDUPE = "c".repeat(64)
        val VERSION_ONE_DDL = listOf(
            "CREATE TABLE sms_attempts (attemptId TEXT NOT NULL PRIMARY KEY, subscriptionId INTEGER NOT NULL, segmentCount INTEGER NOT NULL, state TEXT NOT NULL, createdAtMs INTEGER NOT NULL, updatedAtMs INTEGER NOT NULL)",
            "CREATE TABLE sms_segments (attemptId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, sentResultCode INTEGER, deliveryResultCode INTEGER, deliveryStatus INTEGER, PRIMARY KEY(attemptId,segmentIndex), FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE INDEX index_sms_segments_attemptId ON sms_segments(attemptId)",
        )
        val VERSION_ELEVEN_DDL = listOf(
            "CREATE TABLE sms_attempts (attemptId TEXT NOT NULL PRIMARY KEY, subscriptionId INTEGER NOT NULL, segmentCount INTEGER NOT NULL, state TEXT NOT NULL, createdAtMs INTEGER NOT NULL, updatedAtMs INTEGER NOT NULL, evidenceConflict INTEGER NOT NULL DEFAULT 0, messageId TEXT DEFAULT NULL, accountId TEXT DEFAULT NULL, deviceId TEXT DEFAULT NULL, originHash TEXT DEFAULT NULL)",
            "CREATE TABLE sms_segments (attemptId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, sentResultCode INTEGER, deliveryResultCode INTEGER, deliveryStatus INTEGER, PRIMARY KEY(attemptId,segmentIndex), FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE INDEX index_sms_segments_attemptId ON sms_segments(attemptId)",
            "CREATE TABLE alpha_radio_events (eventId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, attemptId TEXT NOT NULL, evidence TEXT NOT NULL, observedAtMs INTEGER NOT NULL, segmentIndex INTEGER, segmentCount INTEGER, acknowledgedAtMs INTEGER, accountId TEXT DEFAULT NULL, deviceId TEXT DEFAULT NULL, originHash TEXT DEFAULT NULL, quarantinedAtMs INTEGER DEFAULT NULL, quarantineReason TEXT DEFAULT NULL, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE INDEX index_alpha_radio_events_attemptId ON alpha_radio_events(attemptId)",
            "CREATE INDEX index_alpha_radio_events_acknowledgedAtMs_observedAtMs ON alpha_radio_events(acknowledgedAtMs,observedAtMs)",
            "CREATE TABLE inbound_windows (attemptId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, senderToken TEXT NOT NULL, subscriptionId INTEGER NOT NULL, opensAtMs INTEGER NOT NULL, closesAtMs INTEGER NOT NULL, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE INDEX index_inbound_windows_senderToken ON inbound_windows(senderToken)",
            "CREATE TABLE inbound_events (eventId TEXT NOT NULL PRIMARY KEY, attemptId TEXT NOT NULL, messageId TEXT NOT NULL, dedupeToken TEXT NOT NULL, observedSubscriptionId INTEGER, receivedAtMs INTEGER NOT NULL, partCount INTEGER NOT NULL, classification TEXT NOT NULL, encryptedBody BLOB, nonce BLOB, FOREIGN KEY(attemptId) REFERENCES inbound_windows(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE INDEX index_inbound_events_attemptId ON inbound_events(attemptId)",
            "CREATE UNIQUE INDEX index_inbound_events_dedupeToken ON inbound_events(dedupeToken)",
            "CREATE TABLE inbound_uploads (sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, eventId TEXT NOT NULL, accountId TEXT, deviceId TEXT, signatureDer BLOB, acknowledgedAtMs INTEGER, originHash TEXT DEFAULT NULL, quarantinedAtMs INTEGER DEFAULT NULL, quarantineReason TEXT DEFAULT NULL, FOREIGN KEY(eventId) REFERENCES inbound_events(eventId) ON UPDATE NO ACTION ON DELETE CASCADE)",
            "CREATE UNIQUE INDEX index_inbound_uploads_eventId ON inbound_uploads(eventId)",
            "CREATE INDEX index_inbound_uploads_acknowledgedAtMs_sequence ON inbound_uploads(acknowledgedAtMs,sequence)",
            "CREATE TABLE local_recipient_suppressions (senderToken TEXT NOT NULL PRIMARY KEY, observedAtMs INTEGER NOT NULL)",
            "CREATE TABLE local_line_binding (slot INTEGER NOT NULL PRIMARY KEY, accountId TEXT NOT NULL, deviceId TEXT NOT NULL, lineId TEXT NOT NULL, generation INTEGER NOT NULL, subscriptionId INTEGER NOT NULL, installedAtMs INTEGER NOT NULL, cardId INTEGER DEFAULT NULL)",
            "CREATE TABLE local_withdrawal_sequences (sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, eventId TEXT NOT NULL)",
            "CREATE UNIQUE INDEX index_local_withdrawal_sequences_eventId ON local_withdrawal_sequences(eventId)",
            "CREATE TABLE local_inbound_withdrawals (dedupeToken TEXT NOT NULL PRIMARY KEY, senderToken TEXT NOT NULL, classification TEXT NOT NULL, observedSubscriptionId INTEGER, lineId TEXT, bindingGeneration INTEGER, receivedAtMs INTEGER NOT NULL, eventId TEXT DEFAULT NULL, deviceSequence INTEGER DEFAULT NULL, encryptedSender BLOB DEFAULT NULL, senderNonce BLOB DEFAULT NULL, signatureDer BLOB DEFAULT NULL, acknowledgedAtMs INTEGER DEFAULT NULL)",
            "CREATE INDEX index_local_inbound_withdrawals_senderToken ON local_inbound_withdrawals(senderToken)",
            "CREATE UNIQUE INDEX index_local_inbound_withdrawals_eventId ON local_inbound_withdrawals(eventId)",
            "CREATE INDEX index_local_inbound_withdrawals_acknowledgedAtMs_deviceSequence ON local_inbound_withdrawals(acknowledgedAtMs,deviceSequence)",
        )
    }
}
