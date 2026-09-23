// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.app.Application
import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import java.util.concurrent.Executors

/** A stable ID is reserved exactly once before any SmsManager call. No body or recipient is stored. */
@Entity(tableName = "sms_attempts")
data class SmsAttempt(
    @PrimaryKey val attemptId: String,
    val subscriptionId: Int,
    val segmentCount: Int,
    val state: String,
    val createdAtMs: Long,
    val updatedAtMs: Long,
    @ColumnInfo(defaultValue = "0") val evidenceConflict: Boolean = false
)

@Entity(
    tableName = "sms_segments",
    primaryKeys = ["attemptId", "segmentIndex"],
    foreignKeys = [ForeignKey(
        entity = SmsAttempt::class,
        parentColumns = ["attemptId"],
        childColumns = ["attemptId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index("attemptId")]
)
data class SmsSegment(
    val attemptId: String,
    val segmentIndex: Int,
    val sentResultCode: Int? = null,
    val deliveryResultCode: Int? = null,
    val deliveryStatus: Int? = null
)

internal object DeliveryStatus {
    const val RECEIVED = 0
    const val FAILED = 1
    const val UNVERIFIED = 2
}

/** Derivation uses callback evidence only; absence of a callback never proves no submission. */
internal object AttemptState {
    const val SUBMITTING = "submitting"
    const val UNKNOWN = "unknown"
    const val SUBMITTED = "submitted"
    const val DELIVERED = "delivered"
    const val DELIVERY_FAILED = "delivery_failed"
    const val DELIVERY_UNKNOWN = "delivery_unknown"
    const val FAILED = "failed"
    const val PARTIAL_FAILURE = "partial_failure"
    const val NOT_SUBMITTED = "not_submitted"

    fun fromEvidence(prior: String, segments: List<SmsSegment>): String {
        if (prior == NOT_SUBMITTED) return NOT_SUBMITTED
        if (segments.isEmpty() || segments.any { it.sentResultCode == null }) {
            return if (prior == SUBMITTING) SUBMITTING else UNKNOWN
        }
        val sent = segments.count { it.sentResultCode == Activity.RESULT_OK }
        if (sent == 0) return FAILED
        if (sent != segments.size) return PARTIAL_FAILURE
        if (segments.any { it.deliveryStatus == DeliveryStatus.FAILED }) {
            return DELIVERY_FAILED
        }
        if (segments.all { it.deliveryStatus == DeliveryStatus.RECEIVED }) return DELIVERED
        return if (prior == DELIVERY_UNKNOWN) DELIVERY_UNKNOWN else SUBMITTED
    }
}

/** A callback may be replayed, or a later status report may resolve an unverified one. */
internal object CallbackEvidence {
    enum class Decision { STORE, IGNORE, CONFLICT }

    fun sent(previous: Int?, incoming: Int): Decision = when {
        previous == null -> Decision.STORE
        previous == incoming -> Decision.IGNORE
        else -> Decision.CONFLICT
    }

    fun delivery(previous: Int?, incoming: Int): Decision = when {
        previous == null -> Decision.STORE
        previous == DeliveryStatus.UNVERIFIED && incoming != DeliveryStatus.UNVERIFIED -> Decision.STORE
        previous != DeliveryStatus.UNVERIFIED && incoming != DeliveryStatus.UNVERIFIED && previous != incoming -> Decision.CONFLICT
        else -> Decision.IGNORE
    }
}

@Dao
abstract class SmsAttemptDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertAttempt(attempt: SmsAttempt)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertSegments(segments: List<SmsSegment>)

    @Query("SELECT * FROM sms_attempts WHERE attemptId = :attemptId")
    abstract fun getAttempt(attemptId: String): SmsAttempt?

    @Query("SELECT * FROM sms_segments WHERE attemptId = :attemptId ORDER BY segmentIndex")
    abstract fun getSegments(attemptId: String): List<SmsSegment>

    @Query("SELECT * FROM sms_segments WHERE attemptId = :attemptId AND segmentIndex = :index")
    abstract fun getSegment(attemptId: String, index: Int): SmsSegment?

    @Query("UPDATE sms_attempts SET state = :state, updatedAtMs = :now WHERE attemptId = :attemptId")
    abstract fun setState(attemptId: String, state: String, now: Long)

    @Query("UPDATE sms_attempts SET state = 'unknown', evidenceConflict = 1, updatedAtMs = :now WHERE attemptId = :attemptId")
    abstract fun markCallbackConflict(attemptId: String, now: Long)

    @Query("UPDATE sms_segments SET sentResultCode = :result WHERE attemptId = :attemptId AND segmentIndex = :index AND sentResultCode IS NULL")
    abstract fun recordSent(attemptId: String, index: Int, result: Int): Int

    @Query("UPDATE sms_segments SET deliveryResultCode = :result, deliveryStatus = :status WHERE attemptId = :attemptId AND segmentIndex = :index AND (deliveryStatus IS NULL OR (deliveryStatus = 2 AND :status != 2))")
    abstract fun recordDelivery(attemptId: String, index: Int, result: Int, status: Int): Int

    @Query("UPDATE sms_attempts SET state = 'unknown', updatedAtMs = :now WHERE state = 'submitting'")
    abstract fun markInterrupted(now: Long)

    @Query("UPDATE sms_attempts SET state = 'unknown', updatedAtMs = :now WHERE attemptId = :attemptId AND state = 'submitting'")
    abstract fun markStalledSubmission(attemptId: String, now: Long)

    @Query("UPDATE sms_attempts SET state = 'delivery_unknown', updatedAtMs = :now WHERE state = 'submitted' AND updatedAtMs < :cutoff")
    abstract fun markTimedOutDeliveries(cutoff: Long, now: Long)

    @Transaction
    open fun reserve(attemptId: String, subscriptionId: Int, segmentCount: Int, now: Long) {
        require(segmentCount in 1..6)
        insertAttempt(SmsAttempt(attemptId, subscriptionId, segmentCount, AttemptState.SUBMITTING, now, now))
        insertSegments((0 until segmentCount).map { SmsSegment(attemptId, it) })
    }

    @Transaction
    open fun recordCallback(attemptId: String, index: Int, delivery: Boolean, result: Int, deliveryStatus: Int?, now: Long) {
        val attempt = getAttempt(attemptId) ?: return
        if (index !in 0 until attempt.segmentCount) return
        val segment = getSegment(attemptId, index) ?: run {
            markCallbackConflict(attemptId, now)
            return
        }
        val impossibleCallback = attempt.state == AttemptState.NOT_SUBMITTED
        val status = deliveryStatus ?: DeliveryStatus.UNVERIFIED
        val decision = if (delivery) CallbackEvidence.delivery(segment.deliveryStatus, status)
                       else CallbackEvidence.sent(segment.sentResultCode, result)
        when (decision) {
            CallbackEvidence.Decision.IGNORE -> {
                if (impossibleCallback) markCallbackConflict(attemptId, now)
                return
            }
            CallbackEvidence.Decision.CONFLICT -> {
                markCallbackConflict(attemptId, now)
                return
            }
            CallbackEvidence.Decision.STORE -> Unit
        }
        val changed = if (delivery) recordDelivery(attemptId, index, result, status)
                      else recordSent(attemptId, index, result)
        if (changed == 0) return // A replay cannot rewrite settled evidence.
        val segments = getSegments(attemptId)
        if (impossibleCallback || segments.size != attempt.segmentCount) {
            markCallbackConflict(attemptId, now)
            return
        }
        setState(attemptId,
            if (attempt.evidenceConflict) AttemptState.UNKNOWN
            else AttemptState.fromEvidence(attempt.state, segments), now)
    }
}

@Database(entities = [SmsAttempt::class, SmsSegment::class], version = 2, exportSchema = false)
abstract class SmsJournalDatabase : RoomDatabase() {
    abstract fun attempts(): SmsAttemptDao

    companion object {
        @Volatile private var instance: SmsJournalDatabase? = null

        fun get(context: Context): SmsJournalDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext, SmsJournalDatabase::class.java, "sms_attempts.db"
            ).addMigrations(MIGRATION_1_2).build().also { instance = it }
        }

        internal val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE sms_attempts ADD COLUMN evidenceConflict INTEGER NOT NULL DEFAULT 0")
            }
        }
    }
}

/** Serializes restart reconciliation, submit intents, and callback writes off the main thread. */
internal object JournalRuntime {
    val io = Executors.newSingleThreadExecutor()
    val timeouts = Executors.newSingleThreadScheduledExecutor()
}

class GatewayApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val app = applicationContext
        JournalRuntime.io.execute {
            val now = System.currentTimeMillis()
            val dao = SmsJournalDatabase.get(app).attempts()
            dao.markInterrupted(now)
            dao.markTimedOutDeliveries(now - DELIVERY_RECEIPT_TIMEOUT_MS, now)
        }
    }

    companion object {
        private const val DELIVERY_RECEIPT_TIMEOUT_MS = 24L * 60 * 60 * 1000
    }
}
