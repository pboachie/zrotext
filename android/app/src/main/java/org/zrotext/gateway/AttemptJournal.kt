// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.app.Application
import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
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
import java.util.UUID
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
    @ColumnInfo(defaultValue = "0") val evidenceConflict: Boolean = false,
    @ColumnInfo(defaultValue = "NULL") val messageId: String? = null
)

/** One event ID and its exact payload stay in Room until the writer acknowledges them. */
@Entity(
    tableName = "alpha_radio_events",
    foreignKeys = [ForeignKey(
        entity = SmsAttempt::class,
        parentColumns = ["attemptId"],
        childColumns = ["attemptId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index("attemptId"), Index(value = ["acknowledgedAtMs", "observedAtMs"])]
)
data class AlphaRadioEvent(
    @PrimaryKey val eventId: String,
    val messageId: String,
    val attemptId: String,
    val evidence: String,
    val observedAtMs: Long,
    val segmentIndex: Int? = null,
    val segmentCount: Int? = null,
    val acknowledgedAtMs: Long? = null
)

/** The one locally approved sender/SIM window is bound to the durable alpha attempt. */
@Entity(
    tableName = "inbound_windows",
    foreignKeys = [ForeignKey(
        entity = SmsAttempt::class,
        parentColumns = ["attemptId"], childColumns = ["attemptId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index("senderToken")]
)
data class InboundWindow(
    @PrimaryKey val attemptId: String,
    val messageId: String,
    val senderToken: String,
    val subscriptionId: Int,
    val opensAtMs: Long,
    val closesAtMs: Long
)

/** Only locally encrypted content is retained. Unverified evidence has no body. */
@Entity(
    tableName = "inbound_events",
    foreignKeys = [ForeignKey(
        entity = InboundWindow::class,
        parentColumns = ["attemptId"], childColumns = ["attemptId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index("attemptId"), Index(value = ["dedupeToken"], unique = true)]
)
data class InboundEvent(
    @PrimaryKey val eventId: String,
    val attemptId: String,
    val messageId: String,
    val dedupeToken: String,
    val observedSubscriptionId: Int?,
    val receivedAtMs: Long,
    val partCount: Int,
    val classification: String,
    val encryptedBody: ByteArray?,
    val nonce: ByteArray?
)

/** An auto-incremented per-install sequence and signature survive socket restarts. */
@Entity(
    tableName = "inbound_uploads",
    foreignKeys = [ForeignKey(
        entity = InboundEvent::class,
        parentColumns = ["eventId"], childColumns = ["eventId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index(value = ["eventId"], unique = true),
        Index(value = ["acknowledgedAtMs", "sequence"])]
)
data class InboundUpload(
    @PrimaryKey(autoGenerate = true) val sequence: Long = 0,
    val eventId: String,
    val accountId: String? = null,
    val deviceId: String? = null,
    val signatureDer: ByteArray? = null,
    val acknowledgedAtMs: Long? = null
)

internal object InboundClassification {
    const val CAPTURED_LOCAL = "captured_local"
    const val SIM_UNVERIFIED = "sim_unverified"
    const val SEND_UNVERIFIED = "send_unverified"
    const val ENCRYPTION_UNVERIFIED = "encryption_unverified"
}

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
    const val RESERVED = "reserved"
    const val RADIO_STARTED = "radio_started"
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
            return if (prior == SUBMITTING || prior == RADIO_STARTED) SUBMITTING else UNKNOWN
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
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertInboundUpload(upload: InboundUpload): Long

    @Query("SELECT u.* FROM inbound_uploads u JOIN inbound_events i ON i.eventId = u.eventId WHERE u.acknowledgedAtMs IS NULL AND i.receivedAtMs >= :minimumObservedAtMs ORDER BY u.sequence LIMIT 1")
    abstract fun nextInboundUpload(minimumObservedAtMs: Long): InboundUpload?

    @Query("SELECT * FROM inbound_uploads WHERE eventId = :eventId LIMIT 1")
    abstract fun inboundUpload(eventId: String): InboundUpload?

    @Query("SELECT * FROM inbound_events WHERE eventId = :eventId LIMIT 1")
    abstract fun inboundByEventId(eventId: String): InboundEvent?

    @Query("UPDATE inbound_uploads SET accountId = :accountId, deviceId = :deviceId, signatureDer = :signature WHERE eventId = :eventId AND accountId IS NULL AND deviceId IS NULL AND signatureDer IS NULL AND acknowledgedAtMs IS NULL")
    abstract fun signInboundUpload(eventId: String, accountId: String, deviceId: String,
                                   signature: ByteArray): Int

    @Query("UPDATE inbound_uploads SET acknowledgedAtMs = :now WHERE eventId = :eventId AND acknowledgedAtMs IS NULL AND signatureDer IS NOT NULL")
    abstract fun acknowledgeInboundUpload(eventId: String, now: Long): Int

    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertInboundWindow(window: InboundWindow)

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    abstract fun insertInboundEvent(event: InboundEvent): Long

    @Query("SELECT * FROM inbound_windows WHERE senderToken = :senderToken AND opensAtMs <= :now AND closesAtMs > :now ORDER BY opensAtMs DESC LIMIT 2")
    abstract fun activeInboundWindows(senderToken: String, now: Long): List<InboundWindow>

    @Query("SELECT * FROM inbound_events WHERE dedupeToken = :dedupeToken LIMIT 1")
    abstract fun inboundByDedupe(dedupeToken: String): InboundEvent?

    @Query("SELECT * FROM inbound_events WHERE attemptId = :attemptId ORDER BY rowid")
    abstract fun inboundForAttempt(attemptId: String): List<InboundEvent>

    /** A duplicate broadcast cannot create another local event. Unknown SIM/send has no body. */
    @Transaction
    open fun recordInbound(
        window: InboundWindow, dedupeToken: String, observedSubscriptionId: Int?,
        partCount: Int, receivedAtMs: Long, encryptedBody: ByteArray?, nonce: ByteArray?
    ): InboundEvent? {
        if (partCount !in 1..6 || receivedAtMs < window.opensAtMs ||
            receivedAtMs >= window.closesAtMs ||
            activeInboundWindows(window.senderToken, receivedAtMs).singleOrNull()?.attemptId !=
                window.attemptId) return null
        if (observedSubscriptionId != null && observedSubscriptionId != window.subscriptionId) return null
        inboundByDedupe(dedupeToken)?.let { return it }
        val attempt = getAttempt(window.attemptId) ?: return null
        val sent = attempt.state in setOf(AttemptState.SUBMITTED, AttemptState.DELIVERED,
            AttemptState.DELIVERY_FAILED, AttemptState.DELIVERY_UNKNOWN) &&
            !attempt.evidenceConflict && getSegments(attempt.attemptId).let { segments ->
                segments.size == attempt.segmentCount &&
                    segments.all { it.sentResultCode == Activity.RESULT_OK }
            }
        val classification = when {
            observedSubscriptionId == null -> InboundClassification.SIM_UNVERIFIED
            !sent -> InboundClassification.SEND_UNVERIFIED
            encryptedBody == null || nonce?.size != 12 || encryptedBody.size < 16 ->
                InboundClassification.ENCRYPTION_UNVERIFIED
            else -> InboundClassification.CAPTURED_LOCAL
        }
        val event = InboundEvent(UUID.randomUUID().toString(), window.attemptId,
            window.messageId, dedupeToken, observedSubscriptionId, receivedAtMs, partCount,
            classification,
            if (classification == InboundClassification.CAPTURED_LOCAL) encryptedBody else null,
            if (classification == InboundClassification.CAPTURED_LOCAL) nonce else null)
        return if (insertInboundEvent(event) != -1L) {
            if (classification == InboundClassification.CAPTURED_LOCAL) {
                check(insertInboundUpload(InboundUpload(eventId = event.eventId)) > 0)
            }
            event
        } else inboundByDedupe(dedupeToken)
    }

    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertAttempt(attempt: SmsAttempt)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertSegments(segments: List<SmsSegment>)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    abstract fun insertAlphaEvent(event: AlphaRadioEvent)

    @Query("SELECT * FROM alpha_radio_events WHERE eventId = :eventId")
    abstract fun getAlphaEvent(eventId: String): AlphaRadioEvent?

    @Query("SELECT * FROM alpha_radio_events WHERE acknowledgedAtMs IS NULL ORDER BY rowid LIMIT 1")
    abstract fun nextAlphaEvent(): AlphaRadioEvent?

    @Query("SELECT e.* FROM alpha_radio_events e JOIN sms_attempts a ON a.attemptId = e.attemptId WHERE e.evidence = 'durable_submit_intent' AND e.acknowledgedAtMs IS NULL AND a.state IN ('reserved','not_submitted') ORDER BY e.rowid")
    protected abstract fun orphanedAlphaIntents(): List<AlphaRadioEvent>

    @Query("UPDATE alpha_radio_events SET acknowledgedAtMs = :now WHERE eventId = :eventId AND acknowledgedAtMs IS NULL")
    abstract fun acknowledgeAlphaEvent(eventId: String, now: Long): Int

    @Query("SELECT * FROM sms_attempts WHERE attemptId = :attemptId")
    abstract fun getAttempt(attemptId: String): SmsAttempt?

    @Query("SELECT * FROM sms_segments WHERE attemptId = :attemptId ORDER BY segmentIndex")
    abstract fun getSegments(attemptId: String): List<SmsSegment>

    @Query("SELECT * FROM sms_segments WHERE attemptId = :attemptId AND segmentIndex = :index")
    abstract fun getSegment(attemptId: String, index: Int): SmsSegment?

    @Query("UPDATE sms_attempts SET state = :state, updatedAtMs = :now WHERE attemptId = :attemptId")
    abstract fun setState(attemptId: String, state: String, now: Long)

    @Query("UPDATE sms_attempts SET state = 'radio_started', updatedAtMs = :now WHERE attemptId = :attemptId AND messageId = :messageId AND subscriptionId = :subscriptionId AND segmentCount = :segmentCount AND state = 'submitting'")
    abstract fun consumeRadioStart(attemptId: String, messageId: String, subscriptionId: Int,
                                   segmentCount: Int, now: Long): Int

    @Query("UPDATE sms_attempts SET state = 'not_submitted', updatedAtMs = :now WHERE attemptId = :attemptId AND state = 'submitting' AND messageId IS NOT NULL")
    protected abstract fun markAcknowledgedNoRadioState(attemptId: String, now: Long): Int

    @Query("UPDATE sms_attempts SET state = 'not_submitted', updatedAtMs = :now WHERE attemptId = :attemptId AND state = 'radio_started' AND messageId IS NOT NULL")
    protected abstract fun markPreflightNoRadioState(attemptId: String, now: Long): Int

    @Query("SELECT EXISTS(SELECT 1 FROM alpha_radio_events WHERE attemptId = :attemptId AND evidence = 'proven_no_submit')")
    protected abstract fun hasNoRadioProof(attemptId: String): Boolean

    @Query("DELETE FROM alpha_radio_events WHERE attemptId = :attemptId AND evidence = 'proven_no_submit' AND acknowledgedAtMs IS NULL")
    protected abstract fun removePendingNoRadioProof(attemptId: String)

    private fun recordNoRadioProof(attemptId: String, now: Long) {
        val attempt = getAttempt(attemptId) ?: return
        val messageId = attempt.messageId ?: return
        if (attempt.state != AttemptState.NOT_SUBMITTED || attempt.evidenceConflict ||
            hasNoRadioProof(attemptId) || getSegments(attemptId).any {
                it.sentResultCode != null || it.deliveryResultCode != null || it.deliveryStatus != null
            }) return
        insertAlphaEvent(AlphaRadioEvent(UUID.randomUUID().toString(), messageId,
            attemptId, "proven_no_submit", now))
    }

    /** The state and proof are committed together, before a later grant can be issued. */
    @Transaction
    open fun markAcknowledgedNoRadio(attemptId: String, now: Long): Int {
        val changed = markAcknowledgedNoRadioState(attemptId, now)
        if (changed == 1) recordNoRadioProof(attemptId, now)
        return changed
    }

    /** The platform send call was never entered after the one-use local gate. */
    @Transaction
    open fun markPreflightNoRadio(attemptId: String, now: Long): Int {
        val changed = markPreflightNoRadioState(attemptId, now)
        if (changed == 1) recordNoRadioProof(attemptId, now)
        return changed
    }

    /** A replaced/expired stream cannot authorize a still-reserved intent. */
    @Transaction
    open fun retireOrphanedAlphaIntents(now: Long) {
        for (event in orphanedAlphaIntents()) {
            val attempt = getAttempt(event.attemptId) ?: continue
            if (attempt.state == AttemptState.RESERVED) {
                setState(event.attemptId, AttemptState.NOT_SUBMITTED, now)
            }
            check(acknowledgeAlphaEvent(event.eventId, now) == 1)
            recordNoRadioProof(event.attemptId, now)
        }
    }

    @Query("UPDATE sms_attempts SET state = 'unknown', evidenceConflict = 1, updatedAtMs = :now WHERE attemptId = :attemptId AND evidenceConflict = 0")
    abstract fun markCallbackConflict(attemptId: String, now: Long): Int

    /** Preserve the first conflict in the same transaction as the local unknown state. */
    private fun recordConflict(attempt: SmsAttempt, now: Long) {
        if (markCallbackConflict(attempt.attemptId, now) != 1) return
        val messageId = attempt.messageId ?: return
        removePendingNoRadioProof(attempt.attemptId)
        insertAlphaEvent(AlphaRadioEvent(UUID.randomUUID().toString(), messageId,
            attempt.attemptId, "callback_conflict", now))
    }

    @Query("UPDATE sms_segments SET sentResultCode = :result WHERE attemptId = :attemptId AND segmentIndex = :index AND sentResultCode IS NULL")
    abstract fun recordSent(attemptId: String, index: Int, result: Int): Int

    @Query("UPDATE sms_segments SET deliveryResultCode = :result, deliveryStatus = :status WHERE attemptId = :attemptId AND segmentIndex = :index AND (deliveryStatus IS NULL OR (deliveryStatus = 2 AND :status != 2))")
    abstract fun recordDelivery(attemptId: String, index: Int, result: Int, status: Int): Int

    @Query("UPDATE sms_attempts SET state = 'unknown', updatedAtMs = :now WHERE state IN ('submitting','radio_started')")
    abstract fun markInterrupted(now: Long)

    @Query("UPDATE sms_attempts SET state = 'not_submitted', updatedAtMs = :now WHERE state = 'reserved'")
    abstract fun markUnsentReservations(now: Long)

    @Query("UPDATE sms_attempts SET state = 'unknown', updatedAtMs = :now WHERE attemptId = :attemptId AND state IN ('submitting','radio_started')")
    abstract fun markStalledSubmission(attemptId: String, now: Long)

    @Query("UPDATE sms_attempts SET state = 'delivery_unknown', updatedAtMs = :now WHERE state = 'submitted' AND updatedAtMs < :cutoff")
    abstract fun markTimedOutDeliveries(cutoff: Long, now: Long)

    @Transaction
    open fun reserve(attemptId: String, subscriptionId: Int, segmentCount: Int, now: Long) {
        require(segmentCount in 1..6)
        insertAttempt(SmsAttempt(attemptId, subscriptionId, segmentCount, AttemptState.SUBMITTING, now, now))
        insertSegments((0 until segmentCount).map { SmsSegment(attemptId, it) })
    }

    /** The submit intent is persisted in the same transaction as the no-radio reservation. */
    @Transaction
    open fun reserveAlpha(
        attemptId: String, messageId: String, subscriptionId: Int,
        segmentCount: Int, intentEventId: String, now: Long,
        approvedSenderToken: String? = null
    ) {
        require(segmentCount in 1..6)
        require(listOf(attemptId, messageId, intentEventId).all {
            runCatching { UUID.fromString(it).toString() == it }.getOrDefault(false)
        })
        insertAttempt(SmsAttempt(attemptId, subscriptionId, segmentCount,
            AttemptState.RESERVED, now, now, messageId = messageId))
        insertSegments((0 until segmentCount).map { SmsSegment(attemptId, it) })
        insertAlphaEvent(AlphaRadioEvent(intentEventId, messageId, attemptId,
            "durable_submit_intent", now))
        if (approvedSenderToken != null) {
            require(approvedSenderToken.matches(Regex("[0-9a-f]{64}")))
            insertInboundWindow(InboundWindow(attemptId, messageId, approvedSenderToken,
                subscriptionId, now, Math.addExact(now, INBOUND_PILOT_WINDOW_MS)))
        }
    }

    /** A true ack can authorize this reservation only once in this process lifetime. */
    @Transaction
    open fun acknowledgeAlphaIntent(eventId: String, permitted: Boolean, now: Long): Boolean {
        val event = getAlphaEvent(eventId) ?: return false
        if (event.evidence != "durable_submit_intent" || event.acknowledgedAtMs != null) return false
        val attempt = getAttempt(event.attemptId) ?: return false
        if (attempt.state != AttemptState.RESERVED || attempt.messageId != event.messageId) {
            acknowledgeAlphaEvent(eventId, now)
            if (attempt.state == AttemptState.NOT_SUBMITTED) recordNoRadioProof(event.attemptId, now)
            return false
        }
        if (acknowledgeAlphaEvent(eventId, now) != 1) return false
        setState(event.attemptId,
            if (permitted) AttemptState.SUBMITTING else AttemptState.NOT_SUBMITTED, now)
        if (!permitted) recordNoRadioProof(event.attemptId, now)
        return permitted
    }

    @Transaction
    open fun recordCallback(attemptId: String, index: Int, delivery: Boolean, result: Int, deliveryStatus: Int?, now: Long) {
        val attempt = getAttempt(attemptId) ?: return
        if (index !in 0 until attempt.segmentCount) return
        val segment = getSegment(attemptId, index) ?: run {
            recordConflict(attempt, now)
            return
        }
        val impossibleCallback = attempt.state == AttemptState.NOT_SUBMITTED || attempt.state == AttemptState.RESERVED
        val status = deliveryStatus ?: DeliveryStatus.UNVERIFIED
        val decision = if (delivery) CallbackEvidence.delivery(segment.deliveryStatus, status)
                       else CallbackEvidence.sent(segment.sentResultCode, result)
        when (decision) {
            CallbackEvidence.Decision.IGNORE -> {
                if (impossibleCallback) recordConflict(attempt, now)
                return
            }
            CallbackEvidence.Decision.CONFLICT -> {
                recordConflict(attempt, now)
                return
            }
            CallbackEvidence.Decision.STORE -> Unit
        }
        val changed = if (delivery) recordDelivery(attemptId, index, result, status)
                      else recordSent(attemptId, index, result)
        if (changed == 0) return // A replay cannot rewrite settled evidence.
        val segments = getSegments(attemptId)
        if (impossibleCallback || segments.size != attempt.segmentCount) {
            recordConflict(attempt, now)
            return
        }
        val nextState = if (attempt.evidenceConflict) AttemptState.UNKNOWN
            else AttemptState.fromEvidence(attempt.state, segments)
        if (!delivery && attempt.messageId != null && !attempt.evidenceConflict) {
            insertAlphaEvent(AlphaRadioEvent(UUID.randomUUID().toString(), attempt.messageId,
                attemptId, if (result == Activity.RESULT_OK) "sent_callback_ok" else "sent_callback_failed",
                now, index, attempt.segmentCount))
        }
        if (attempt.messageId != null && nextState == AttemptState.DELIVERED &&
            attempt.state != AttemptState.DELIVERED) {
            insertAlphaEvent(AlphaRadioEvent(UUID.randomUUID().toString(), attempt.messageId,
                attemptId, "delivery_callback_ok", now))
        }
        setState(attemptId, nextState, now)
    }
}

private const val INBOUND_PILOT_WINDOW_MS = 24L * 60 * 60 * 1000

@Database(entities = [SmsAttempt::class, SmsSegment::class, AlphaRadioEvent::class,
    InboundWindow::class, InboundEvent::class, InboundUpload::class], version = 5, exportSchema = false)
abstract class SmsJournalDatabase : RoomDatabase() {
    abstract fun attempts(): SmsAttemptDao

    companion object {
        @Volatile private var instance: SmsJournalDatabase? = null

        fun get(context: Context): SmsJournalDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext, SmsJournalDatabase::class.java, "sms_attempts.db"
            ).addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
                .build().also { instance = it }
        }

        internal val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE sms_attempts ADD COLUMN evidenceConflict INTEGER NOT NULL DEFAULT 0")
            }
        }

        internal val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE sms_attempts ADD COLUMN messageId TEXT DEFAULT NULL")
                db.execSQL("CREATE TABLE IF NOT EXISTS alpha_radio_events (eventId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, attemptId TEXT NOT NULL, evidence TEXT NOT NULL, observedAtMs INTEGER NOT NULL, segmentIndex INTEGER, segmentCount INTEGER, acknowledgedAtMs INTEGER, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_alpha_radio_events_attemptId ON alpha_radio_events(attemptId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_alpha_radio_events_acknowledgedAtMs_observedAtMs ON alpha_radio_events(acknowledgedAtMs, observedAtMs)")
            }
        }

        internal val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS inbound_windows (attemptId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, senderToken TEXT NOT NULL, subscriptionId INTEGER NOT NULL, opensAtMs INTEGER NOT NULL, closesAtMs INTEGER NOT NULL, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_inbound_windows_senderToken ON inbound_windows(senderToken)")
                db.execSQL("CREATE TABLE IF NOT EXISTS inbound_events (eventId TEXT NOT NULL PRIMARY KEY, attemptId TEXT NOT NULL, messageId TEXT NOT NULL, dedupeToken TEXT NOT NULL, observedSubscriptionId INTEGER, receivedAtMs INTEGER NOT NULL, partCount INTEGER NOT NULL, classification TEXT NOT NULL, encryptedBody BLOB, nonce BLOB, FOREIGN KEY(attemptId) REFERENCES inbound_windows(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_inbound_events_attemptId ON inbound_events(attemptId)")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_inbound_events_dedupeToken ON inbound_events(dedupeToken)")
            }
        }

        internal val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS inbound_uploads (sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, eventId TEXT NOT NULL, accountId TEXT, deviceId TEXT, signatureDer BLOB, acknowledgedAtMs INTEGER, FOREIGN KEY(eventId) REFERENCES inbound_events(eventId) ON UPDATE NO ACTION ON DELETE CASCADE)")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_inbound_uploads_eventId ON inbound_uploads(eventId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_inbound_uploads_acknowledgedAtMs_sequence ON inbound_uploads(acknowledgedAtMs, sequence)")
                db.execSQL("INSERT INTO inbound_uploads(eventId) SELECT eventId FROM inbound_events WHERE classification = 'captured_local' ORDER BY rowid")
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
            dao.markUnsentReservations(now)
            dao.retireOrphanedAlphaIntents(now)
            dao.markTimedOutDeliveries(now - DELIVERY_RECEIPT_TIMEOUT_MS, now)
        }
    }

    companion object {
        private const val DELIVERY_RECEIPT_TIMEOUT_MS = 24L * 60 * 60 * 1000
    }
}
