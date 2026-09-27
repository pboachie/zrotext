// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction

/** Permanent, bounded candidate replay fence. No peer, ciphertext, key or plaintext is retained. */
@Entity(tableName = "sealed_preparations", primaryKeys = ["accountId", "messageId"],
    indices = [Index(value = ["attemptId"], unique = true)])
data class SealedPreparationRecord(
    val accountId: String, val messageId: String, val attemptId: String,
    val unsignedDigest: String, val grantDigest: String,
    val state: String = "preparing", val segmentCount: Int? = null
) {
    override fun toString() = "SealedPreparationRecord(redacted)"
}

@Dao
abstract class SealedPreparationDao {
    @Query("SELECT COUNT(*) FROM sealed_preparations")
    abstract fun count(): Int

    @Query("SELECT * FROM sealed_preparations WHERE accountId = :account AND messageId = :message")
    abstract fun find(account: String, message: String): SealedPreparationRecord?

    @Query("SELECT * FROM sealed_preparations WHERE attemptId = :attempt")
    protected abstract fun byAttempt(attempt: String): SealedPreparationRecord?

    @Query("SELECT * FROM local_line_binding WHERE slot = 1")
    protected abstract fun line(): LocalLineBinding?

    @Insert
    protected abstract fun insert(record: SealedPreparationRecord)

    @Query("UPDATE sealed_preparations SET state = 'prepared', segmentCount = :segments WHERE accountId = :account AND messageId = :message AND attemptId = :attempt AND unsignedDigest = :digest AND grantDigest = :grant AND state = 'preparing'")
    protected abstract fun prepared(account: String, message: String, attempt: String,
                                    digest: String, grant: String, segments: Int): Int

    @Query("UPDATE sealed_preparations SET state = 'aborted' WHERE accountId = :account AND messageId = :message AND attemptId = :attempt AND state IN ('preparing', 'prepared')")
    abstract fun abort(account: String, message: String, attempt: String): Int

    /** Transaction acquisition can block. Revalidate only after it has completed. Never evict. */
    @Transaction
    open fun reserve(record: SealedPreparationRecord, checkCurrentLine: (LocalLineBinding?) -> Unit) {
        checkCurrentLine(line())
        require(record.state == "preparing" && record.segmentCount == null &&
            listOf(record.accountId, record.messageId, record.attemptId).all { id ->
                runCatching { java.util.UUID.fromString(id).toString() == id && java.util.UUID.fromString(id) != java.util.UUID(0, 0) }.getOrDefault(false)
            } && record.unsignedDigest.matches(HEX) && record.grantDigest.matches(HEX)) { "Preparation shape" }
        check(count() < CAPACITY) { "Preparation capacity exhausted" }
        check(find(record.accountId, record.messageId) == null && byAttempt(record.attemptId) == null) {
            "Preparation already reserved"
        }
        insert(record)
        checkCurrentLine(line()) // Including time spent writing/acquiring SQLite locks.
    }

    /** The last line-generation/continuity check and CAS share this Room transaction. */
    @Transaction
    open fun finish(record: SealedPreparationRecord, segments: Int,
                    checkCurrentLine: (LocalLineBinding?) -> Unit) {
        require(segments in 1..6) { "Preparation segment limit" }
        checkCurrentLine(line())
        check(prepared(record.accountId, record.messageId, record.attemptId,
            record.unsignedDigest, record.grantDigest, segments) == 1) { "Preparation state changed" }
        checkCurrentLine(line())
    }

    companion object {
        const val CAPACITY = 1024
        private val HEX = Regex("[0-9a-f]{64}")
    }
}
