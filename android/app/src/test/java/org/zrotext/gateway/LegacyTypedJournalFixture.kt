// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/** Synthetic historical reconstruction ONLY. Current Room creates future typed tables;
 * lowering user_version without removing them is not an old schema. Every such table must
 * be proved empty before any drop. Actual old typed facts are reconstructed separately and
 * remain covered by their original migration assertions. No production migration uses this. */
internal object LegacyTypedJournalFixture {
    fun removeEmptyFutureTables(db: SQLiteDatabase) = remove({ db.rawQuery(it, null) }, { db.execSQL(it) })
    fun removeEmptyFutureTables(db: SupportSQLiteDatabase) = remove({ db.query(it) }, { db.execSQL(it) })
    fun removeEmptyOutcomeTables(db: SupportSQLiteDatabase) {
        db.query("SELECT COUNT(*) FROM typed_submit03 WHERE closureProofState IS NOT NULL").use {
            assertTrue(it.moveToFirst()); assertEquals("Future proof eligibility must be absent", 0L, it.getLong(0))
        }
        remove({ db.query(it) }, { db.execSQL(it) },
            listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages", "typed_outcome03_uploads", "typed_outcome03_reports"))
        restoreVersion25Submit(db)
    }

    /** Exact historical21->22 table/index DDL plus22->23 additions, from immutable
     * pre26 source9229091c3bf944fbc1d74789a12691a039989673. No DROP COLUMN support
     * is assumed. Callers first prove ALL future tables empty and remove them. */
    fun restoreVersion25Submit(db: SupportSQLiteDatabase) {
        val proofTables = listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages")
        for (table in proofTables) db.query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$table'").use {
            assertTrue(it.moveToFirst()); assertEquals("Future proof table must already be absent", 0L, it.getLong(0))
        }
        db.query("SELECT COUNT(*) FROM typed_submit03 WHERE closureProofState IS NOT NULL AND (closingId IS NULL OR phase != 'closed_no_submit' OR closureProofState != 'eligible:' || closingId)").use {
            assertTrue(it.moveToFirst()); assertEquals("Started or unknown proof metadata cannot be removed", 0L, it.getLong(0))
        }
        val columns = listOf("attemptId", "eventId", "accountId", "deviceId", "messageId", "commandB64url", "commandSha256", "originalEnrolledPoint", "originalEnrolledKeyId", "phase", "ackSha256", "entryReservedMs", "closureB64url", "closureSha256", "conflict", "originalOriginSha256", "lastCallbackOrdinal", "closingId", "closingFrom")
        val actualColumns = db.query("PRAGMA table_info(typed_submit03)").use { c ->
            buildList { while (c.moveToNext()) add(c.getString(1)) }
        }
        assertEquals(columns + "closureProofState", actualColumns)
        val tables = db.query("SELECT name FROM sqlite_master WHERE type='table'").use { c ->
            buildList { while (c.moveToNext()) add(c.getString(0)) }
        }
        for (table in tables) db.query("PRAGMA foreign_key_list(`$table`)").use { c ->
            while (c.moveToNext()) assertTrue("Historical reconstruction cannot drop a referenced table", c.getString(2) != "typed_submit03" && table != "typed_submit03")
        }
        db.query("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='typed_submit03'").use {
            assertTrue(it.moveToFirst()); assertEquals("Historical reconstruction cannot discard triggers", 0L, it.getLong(0))
        }
        db.query("SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND instr(lower(sql), 'typed_submit03') > 0").use {
            assertTrue(it.moveToFirst()); assertEquals("Historical reconstruction cannot rewrite view references", 0L, it.getLong(0))
        }
        fun rows() = db.query("SELECT ${columns.joinToString(",")} FROM typed_submit03 ORDER BY attemptId").use { c ->
            buildList { while (c.moveToNext()) add(columns.indices.map { c.getType(it) to if (c.isNull(it)) null else c.getString(it) }) }
        }
        fun indexes() = db.query("PRAGMA index_list(typed_submit03)").use { c ->
            buildList {
                while (c.moveToNext()) {
                    val name = c.getString(1)
                    if (name.startsWith("sqlite_autoindex_")) continue // PRIMARY KEY is in the exact old DDL.
                    val indexed = db.query("PRAGMA index_info(`$name`)").use { i -> buildList { while (i.moveToNext()) add(i.getString(2)) } }
                    add("$name:${c.getInt(2)}:${indexed.joinToString(",")}")
                }
            }.sorted()
        }
        val beforeRows = rows(); val beforeIndexes = indexes()
        assertEquals(listOf("index_typed_submit03_accountId_messageId:1:accountId,messageId", "index_typed_submit03_eventId:1:eventId"), beforeIndexes)
        db.beginTransaction()
        try {
            // The old15 columns, original PRIMARY KEY and four actual nullable additions.
            db.execSQL("CREATE TABLE typed_submit03_history25 (attemptId TEXT NOT NULL, eventId TEXT NOT NULL, accountId TEXT NOT NULL, deviceId TEXT NOT NULL, messageId TEXT NOT NULL, commandB64url TEXT NOT NULL, commandSha256 TEXT NOT NULL, originalEnrolledPoint TEXT NOT NULL, originalEnrolledKeyId TEXT NOT NULL, phase TEXT NOT NULL, ackSha256 TEXT, entryReservedMs INTEGER, closureB64url TEXT, closureSha256 TEXT, conflict INTEGER NOT NULL, PRIMARY KEY(attemptId))")
            db.execSQL("ALTER TABLE typed_submit03_history25 ADD COLUMN originalOriginSha256 TEXT")
            db.execSQL("ALTER TABLE typed_submit03_history25 ADD COLUMN lastCallbackOrdinal INTEGER")
            db.execSQL("ALTER TABLE typed_submit03_history25 ADD COLUMN closingId TEXT")
            db.execSQL("ALTER TABLE typed_submit03_history25 ADD COLUMN closingFrom INTEGER")
            val names = columns.joinToString(",")
            db.execSQL("INSERT INTO typed_submit03_history25 ($names) SELECT $names FROM typed_submit03")
            db.execSQL("DROP TABLE typed_submit03")
            db.execSQL("ALTER TABLE typed_submit03_history25 RENAME TO typed_submit03")
            db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_typed_submit03_eventId ON typed_submit03(eventId)")
            db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_typed_submit03_accountId_messageId ON typed_submit03(accountId, messageId)")
            assertEquals(beforeRows, rows()); assertEquals(beforeIndexes, indexes())
            db.setTransactionSuccessful()
        } finally { db.endTransaction() }
    }

    private val future = listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages", "typed_outcome03_uploads", "typed_outcome03_reports", "typed_submit03_requests", "typed_history03_clocks", "typed_history03_sources",
        "typed_callback03", "typed_submit03")
    private fun remove(query: (String) -> Cursor, execute: (String) -> Unit, tables: List<String> = future) {
        fun exists(table: String) = query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$table'").use {
            assertTrue(it.moveToFirst()); it.getLong(0) == 1L
        }
        val present = tables.filter(::exists)
        // Check ALL before removing ANY: populated history can never be erased by scaffolding.
        for (table in present) query("SELECT COUNT(*) FROM $table").use {
            assertTrue(it.moveToFirst()); assertEquals("Future fixture table must be empty: $table", 0L, it.getLong(0))
        }
        for (table in present) execute("DROP TABLE $table")
        for (table in tables) assertTrue("Future table must be absent from historical fixture: $table", !exists(table))
    }
}
