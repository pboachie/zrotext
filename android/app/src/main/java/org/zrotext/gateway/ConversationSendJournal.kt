// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.*

/** New dormant database; no production builder opens it or upgrades capture storage. */
@Database(entities = [ConversationSendReceipt::class, ConversationSendClosed::class], version = 1, exportSchema = false)
abstract class ConversationSendDatabase : RoomDatabase() { abstract fun sends(): ConversationSendDao }

@Entity(tableName = "conversation_send_closed")
data class ConversationSendClosed(@PrimaryKey val interval: String) {
    override fun toString() = "ConversationSendClosed(redacted)"
}

@Entity(tableName = "conversation_send_receipts")
data class ConversationSendReceipt(
    @PrimaryKey val message: String, val interval: String, val evidenceDigest: String,
    val deadline: Long, val protectedPayload: ByteArray?, val nonce: ByteArray?,
    val state: String = "confirmed", val attempt: String? = null
) { override fun toString() = "ConversationSendReceipt(redacted)" }

@Dao
abstract class ConversationSendDao {
    @Query("SELECT * FROM conversation_send_receipts WHERE message=:message")
    abstract fun receipt(message: String): ConversationSendReceipt?
    @Query("SELECT COUNT(*) FROM conversation_send_receipts")
    abstract fun count(): Int
    @Query("SELECT COUNT(*) FROM conversation_send_receipts WHERE protectedPayload IS NOT NULL")
    abstract fun contentCount(): Int
    @Query("SELECT COUNT(*) FROM conversation_send_closed WHERE interval=:interval")
    abstract fun closed(interval: String): Int
    @Query("SELECT COUNT(*) FROM conversation_send_closed")
    protected abstract fun closedCount(): Int
    @Insert protected abstract fun insertReceipt(value: ConversationSendReceipt)
    @Insert(onConflict = OnConflictStrategy.IGNORE) protected abstract fun insertClosed(value: ConversationSendClosed)
    @Query("UPDATE conversation_send_receipts SET state='claimed',attempt=:attempt WHERE message=:message AND state='confirmed'")
    protected abstract fun setClaimed(message: String, attempt: String): Int
    @Query("UPDATE conversation_send_receipts SET state=:state WHERE message=:message AND attempt=:attempt AND state='claimed'")
    protected abstract fun finish(message: String, attempt: String, state: String): Int
    @Query("UPDATE conversation_send_receipts SET state='cancelled',protectedPayload=NULL,nonce=NULL WHERE interval=:interval AND state='confirmed'")
    protected abstract fun cancelPending(interval: String)
    @Query("UPDATE conversation_send_receipts SET protectedPayload=NULL,nonce=NULL WHERE deadline<:cutoff")
    abstract fun purgePayloadBefore(cutoff: Long): Int

    @Transaction open fun receive(value: ConversationSendReceipt) {
        check(closed(value.interval) == 0) { "Interval closed" }
        val old = receipt(value.message)
        if (old != null) {
            check(old.interval == value.interval && old.evidenceDigest == value.evidenceDigest && old.deadline == value.deadline) { "Confirmed identity changed" }
            return // Never rewrite encrypted payload, state, attempt or purged content.
        }
        check(count() < FENCE_CAPACITY && contentCount() < CONTENT_CAPACITY) { "Send journal full" }
        insertReceipt(value)
    }
    @Transaction open fun claim(message: String, attempt: String) {
        val row = checkNotNull(receipt(message))
        check(closed(row.interval) == 0 && row.protectedPayload != null && row.nonce != null)
        check(setClaimed(message, attempt) == 1) { "Send was already claimed or closed" }
    }
    @Transaction open fun recordOutcome(message: String, attempt: String, state: String) {
        check(state in listOf("submitted", "unknown"))
        check(finish(message, attempt, state) == 1) { "Attempt identity changed" }
    }
    @Transaction open fun close(interval: String) {
        check(closed(interval) != 0 || closedCount() < FENCE_CAPACITY) { "Closure journal full" }
        insertClosed(ConversationSendClosed(interval)); cancelPending(interval)
    }
    companion object { const val FENCE_CAPACITY = 1024; const val CONTENT_CAPACITY = 128 }
}
