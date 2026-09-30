// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Transaction

/** Separate dormant database: no receiver, service or production builder opens it. */
@Database(entities = [ConversationInstallation::class, ConversationReceipt::class, ConversationClosedInterval::class], version = 1,
    exportSchema = false)
abstract class ConversationCaptureDatabase : RoomDatabase() {
    abstract fun journal(): ConversationCaptureDao
}

@Entity(tableName = "conversation_closed_intervals")
data class ConversationClosedInterval(@PrimaryKey val intervalId: String) {
    override fun toString() = "ConversationClosedInterval(redacted)"
}

@Entity(tableName = "conversation_installation")
data class ConversationInstallation(
    @PrimaryKey val slot: Int = 1,
    val intervalId: String,
    val receiptId: String,
    val transcriptDigest: String,
    val protectedScope: ByteArray,
    val nonce: ByteArray,
    val state: String = "prepared"
) {
    override fun toString() = "ConversationInstallation(redacted)"
}

/** A receipt fence survives content purge. Replaying a discarded receipt cannot capture it later. */
@Entity(tableName = "conversation_receipts")
data class ConversationReceipt(
    @PrimaryKey val token: String,
    val firstObservedAtMs: Long,
    val captureId: String? = null,
    val intervalId: String? = null,
    val protectedCapture: ByteArray? = null,
    val nonce: ByteArray? = null
) {
    override fun toString() = "ConversationReceipt(redacted)"
}

@Dao
abstract class ConversationCaptureDao {
    @Query("SELECT COUNT(*) FROM conversation_closed_intervals WHERE intervalId = :interval")
    abstract fun isClosed(interval: String): Int

    @Query("SELECT COUNT(*) FROM conversation_closed_intervals")
    protected abstract fun closedCount(): Int

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    protected abstract fun insertClosed(value: ConversationClosedInterval)

    @Query("SELECT * FROM conversation_installation WHERE slot = 1")
    abstract fun installation(): ConversationInstallation?

    @Insert
    protected abstract fun insertInstallation(value: ConversationInstallation)

    @Query("DELETE FROM conversation_installation WHERE slot = 1 AND state = 'closed'")
    protected abstract fun removeClosedInstallation(): Int

    @Query("UPDATE conversation_installation SET state = :state WHERE slot = 1 AND intervalId = :interval AND state IN ('prepared', 'installed')")
    protected abstract fun setState(interval: String, state: String): Int

    @Query("SELECT * FROM conversation_receipts WHERE token = :token")
    abstract fun receipt(token: String): ConversationReceipt?

    @Query("SELECT COUNT(*) FROM conversation_receipts")
    abstract fun receiptCount(): Int

    @Query("SELECT COUNT(*) FROM conversation_receipts WHERE protectedCapture IS NOT NULL")
    abstract fun contentCount(): Int

    @Insert
    protected abstract fun insertReceipt(value: ConversationReceipt)

    @Query("UPDATE conversation_receipts SET captureId = :capture, intervalId = :interval, protectedCapture = :content, nonce = :nonce WHERE token = :token AND captureId IS NULL")
    protected abstract fun completeReceipt(token: String, capture: String, interval: String,
                                           content: ByteArray, nonce: ByteArray): Int

    @Query("UPDATE conversation_receipts SET captureId = NULL, intervalId = NULL, protectedCapture = NULL, nonce = NULL WHERE token = :token")
    protected abstract fun discardReceipt(token: String): Int

    @Query("UPDATE conversation_receipts SET protectedCapture = NULL, nonce = NULL WHERE firstObservedAtMs < :cutoff")
    abstract fun purgeContentBefore(cutoff: Long): Int

    @Transaction
    open fun prepare(value: ConversationInstallation, checkLive: () -> Unit) {
        checkLive()
        check(isClosed(value.intervalId) == 0) { "Interval was closed" }
        check(closedCount() < RECEIPT_CAPACITY) { "Closure fence capacity exhausted" }
        val existing = installation()
        if (existing != null && existing.state != "closed") {
            check(existing.intervalId == value.intervalId && existing.receiptId == value.receiptId &&
                existing.transcriptDigest == value.transcriptDigest &&
                existing.protectedScope.contentEquals(value.protectedScope) &&
                existing.nonce.contentEquals(value.nonce)) { "Installation already prepared" }
        } else {
            removeClosedInstallation()
            insertInstallation(value)
        }
        checkLive()
    }

    @Transaction
    open fun installed(interval: String, checkLive: () -> Unit) {
        checkLive()
        check(setState(interval, "installed") == 1) { "Installation is closed" }
        checkLive()
    }

    @Transaction
    open fun close(interval: String) {
        val existing = installation()
        check(existing == null || existing.intervalId == interval) { "Installation identity changed" }
        check(isClosed(interval) != 0 || closedCount() < RECEIPT_CAPACITY) { "Closed interval capacity exhausted" }
        insertClosed(ConversationClosedInterval(interval))
        if (existing != null && existing.state != "closed") check(setState(interval, "closed") == 1)
    }

    /** Commit the first-receipt fence before encryption or any body upgrade can begin. */
    @Transaction
    open fun reserveReceipt(token: String, observedAt: Long): Boolean {
        if (receipt(token) != null) return false
        check(receiptCount() < RECEIPT_CAPACITY) { "Receipt fence capacity exhausted" }
        insertReceipt(ConversationReceipt(token, observedAt))
        return true
    }

    /** Only the same first-receipt call may upgrade its committed fence; replay never calls this. */
    @Transaction
    open fun finishReceipt(token: String, onFailure: () -> Unit,
                           build: (Boolean) -> ConversationReceipt): ConversationReceipt {
        val discard = checkNotNull(receipt(token))
        check(discard.captureId == null && discard.protectedCapture == null)
        return try {
            val value = build(contentCount() < CONTENT_CAPACITY)
            check(value.token == token && value.firstObservedAtMs == discard.firstObservedAtMs) { "Receipt identity changed" }
            if (value.protectedCapture != null) {
                check(completeReceipt(token, checkNotNull(value.captureId), checkNotNull(value.intervalId),
                    value.protectedCapture, checkNotNull(value.nonce)) == 1)
            }
            // Recheck after encryption and writes. Failure commits only the original receipt fence.
            val after = build(value.protectedCapture != null)
            check(after.captureId == value.captureId && after.intervalId == value.intervalId) {
                "Capture admission changed"
            }
            value
        } catch (_: Exception) {
            onFailure()
            check(discardReceipt(token) == 1)
            discard
        }
    }

    companion object {
        const val CONTENT_CAPACITY = 128
        const val RECEIPT_CAPACITY = 1024
    }
}
