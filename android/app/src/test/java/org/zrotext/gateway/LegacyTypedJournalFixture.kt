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
        db.execSQL("ALTER TABLE typed_submit03 DROP COLUMN closureProofState")
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
