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
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Separate content journal, opened only by the explicit conversation installation. */
@Database(entities = [ConversationInstallation::class, ConversationReceipt::class, ConversationClosedInterval::class, ConversationWireCapture::class], version = 3,
    exportSchema = false)
abstract class ConversationCaptureDatabase : RoomDatabase() {
    abstract fun journal(): ConversationCaptureDao
    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS conversation_wire_captures (sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, token TEXT NOT NULL, captureId TEXT NOT NULL, intervalId TEXT NOT NULL, protectedEnvelope BLOB, nonce BLOB)")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_conversation_wire_captures_token ON conversation_wire_captures(token)")
            }
        }
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Unknown older uploads remain pending, with their exact protected bytes intact.
                db.execSQL("ALTER TABLE conversation_wire_captures ADD COLUMN acknowledgedDigest TEXT")
            }
        }
    }
}

/** Counter and receipt identity survive ciphertext purge; retries never create another envelope. */
@Entity(tableName = "conversation_wire_captures", indices = [androidx.room.Index(value = ["token"], unique = true)])
data class ConversationWireCapture(
    @PrimaryKey(autoGenerate = true) val sequence: Long = 0,
    val token: String, val captureId: String, val intervalId: String,
    val protectedEnvelope: ByteArray? = null, val nonce: ByteArray? = null,
    val acknowledgedDigest: String? = null
) { override fun toString() = "ConversationWireCapture(redacted)" }

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
    @Query("SELECT * FROM conversation_wire_captures WHERE token=:token")
    abstract fun wireCapture(token: String): ConversationWireCapture?
    @Query("SELECT COUNT(*) FROM conversation_wire_captures")
    protected abstract fun wireCount(): Int
    @Insert protected abstract fun insertWire(value: ConversationWireCapture): Long
    @Query("UPDATE conversation_wire_captures SET protectedEnvelope=:content,nonce=:nonce WHERE sequence=:sequence AND protectedEnvelope IS NULL AND nonce IS NULL AND acknowledgedDigest IS NULL")
    protected abstract fun setWire(sequence: Long, content: ByteArray, nonce: ByteArray): Int
    @Query("UPDATE conversation_wire_captures SET protectedEnvelope=NULL,nonce=NULL WHERE intervalId=:interval")
    protected abstract fun clearWire(interval: String): Int
    @Query("UPDATE conversation_wire_captures SET protectedEnvelope=NULL,nonce=NULL WHERE token IN (SELECT token FROM conversation_receipts WHERE firstObservedAtMs<:cutoff)")
    protected abstract fun purgeWireBefore(cutoff: Long): Int

    @Query("UPDATE conversation_wire_captures SET acknowledgedDigest=:digest,protectedEnvelope=NULL,nonce=NULL WHERE sequence=:sequence AND acknowledgedDigest IS NULL")
    protected abstract fun acknowledgeWire(sequence: Long, digest: String): Int
    @Query("UPDATE conversation_receipts SET protectedCapture=NULL,nonce=NULL WHERE token=:token")
    protected abstract fun clearReceiptContent(token: String): Int

    /** The authenticated exact ACK commits its tombstone and retires both ciphertexts together. */
    @Transaction open fun acknowledgeCapture(expected: ConversationWireCapture, observedAt: Long,
                                             digest: String, checkLive: () -> Unit) {
        checkLive(); check(isClosed(expected.intervalId) == 0)
        require(Regex("[0-9a-f]{64}").matches(digest))
        val receipt = checkNotNull(receipt(expected.token))
        check(receipt.captureId == expected.captureId && receipt.intervalId == expected.intervalId &&
            receipt.firstObservedAtMs == observedAt)
        val stored = checkNotNull(wireCapture(expected.token))
        check(stored.sequence == expected.sequence && stored.captureId == expected.captureId &&
            stored.intervalId == expected.intervalId)
        if (stored.acknowledgedDigest != null) {
            check(stored.acknowledgedDigest == digest && stored.protectedEnvelope == null &&
                stored.nonce == null && receipt.protectedCapture == null && receipt.nonce == null)
        } else {
            check(receipt.protectedCapture != null && receipt.nonce != null)
            check(checkNotNull(stored.protectedEnvelope).contentEquals(checkNotNull(expected.protectedEnvelope)) &&
                checkNotNull(stored.nonce).contentEquals(checkNotNull(expected.nonce)))
            check(acknowledgeWire(stored.sequence, digest) == 1)
            check(clearReceiptContent(stored.token) == 1)
        }
        // A loss after either write rolls back the ACK and both removals, including on duplicates.
        checkLive()
    }

    @Transaction open fun reserveWire(token: String, capture: String, interval: String, checkLive: () -> Unit): ConversationWireCapture {
        checkLive()
        val receipt = checkNotNull(receipt(token))
        check(receipt.captureId == capture && receipt.intervalId == interval && receipt.protectedCapture != null)
        check(isClosed(interval) == 0)
        val old = wireCapture(token)
        if (old != null) {
            check(old.captureId == capture && old.intervalId == interval && old.sequence > 0)
            checkLive(); return old
        }
        check(wireCount() < RECEIPT_CAPACITY)
        val sequence = insertWire(ConversationWireCapture(token=token,captureId=capture,intervalId=interval))
        check(sequence > 0); checkLive()
        return checkNotNull(wireCapture(token))
    }
    @Transaction open fun storeWire(row: ConversationWireCapture, content: ByteArray, nonce: ByteArray, checkLive: () -> Unit) {
        checkLive(); check(isClosed(row.intervalId) == 0)
        val receipt = checkNotNull(receipt(row.token))
        check(receipt.captureId == row.captureId && receipt.intervalId == row.intervalId && receipt.protectedCapture != null)
        val old = checkNotNull(wireCapture(row.token))
        check(old.sequence == row.sequence && old.captureId == row.captureId && old.intervalId == row.intervalId)
        check(setWire(row.sequence,content,nonce) == 1)
        checkLive()
    }
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
    protected abstract fun purgeReceiptsBefore(cutoff: Long): Int
    @Transaction open fun purgeContentBefore(cutoff: Long): Int {
        purgeWireBefore(cutoff)
        return purgeReceiptsBefore(cutoff)
    }

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
        clearWire(interval)
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
