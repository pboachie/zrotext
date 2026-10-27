// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import java.nio.ByteBuffer
import java.security.MessageDigest

/** This separate file contains only opaque IDs, keyed scope commitments and protected proofs.
 * Neither an ACTIVE row nor downloaded signatures can reconstruct the live installation handle.
 */
@Entity(tableName = "conversation_intervals03", indices = [androidx.room.Index(value = ["receiptId"], unique = true),
    androidx.room.Index(value = ["statementNonceSha256"], unique = true),
    androidx.room.Index(value = ["scopeToken", "state", "intervalExpiresMs"]),
    androidx.room.Index(value = ["budgetToken", "reservedMs"])])
data class ConversationInterval03Record(@PrimaryKey val intervalId: String, val scopeToken: String,
    val statementSha256: String, val intervalExpiresMs: Long, val state: String,
    val protectedProof: ByteArray, val nonce: ByteArray, val ownerSignatureSha256: String,
    val requestedMs: Long, val phoneSignatureSha256: String? = null, val approvedMs: Long? = null,
    val installedSignatureSha256: String? = null, val installedMs: Long? = null,
    val receiptId: String, val statementNonceSha256: String, val budgetToken: String, val reservedMs: Long = 0) {
    override fun toString() = "ConversationInterval03Record(redacted)"
    internal fun same(other: ConversationInterval03Record) = intervalId == other.intervalId &&
        scopeToken == other.scopeToken && statementSha256 == other.statementSha256 &&
        intervalExpiresMs == other.intervalExpiresMs && state == other.state && ownerSignatureSha256 == other.ownerSignatureSha256 &&
        requestedMs == other.requestedMs && phoneSignatureSha256 == other.phoneSignatureSha256 && approvedMs == other.approvedMs &&
        installedSignatureSha256 == other.installedSignatureSha256 && installedMs == other.installedMs &&
        receiptId == other.receiptId && statementNonceSha256 == other.statementNonceSha256 &&
        budgetToken == other.budgetToken && reservedMs == other.reservedMs &&
        protectedProof.contentEquals(other.protectedProof) && nonce.contentEquals(other.nonce)
    internal fun requireShape() {
        Profile03ClosedUnaccepted.uuid(intervalId); Profile03ClosedUnaccepted.uuid(receiptId)
        for (hash in listOfNotNull(scopeToken, budgetToken, statementSha256, statementNonceSha256, ownerSignatureSha256, phoneSignatureSha256, installedSignatureSha256))
            require(hash.matches(Regex("[0-9a-f]{64}")))
        require(requestedMs > 0 && reservedMs >= 0 && intervalExpiresMs > requestedMs && nonce.size == 12 && protectedProof.size in 16..4096)
        require(approvedMs == null || phoneSignatureSha256 != null && approvedMs >= requestedMs)
        require(installedSignatureSha256 == null || phoneSignatureSha256 != null && approvedMs != null)
        require(installedMs == null || installedSignatureSha256 != null && installedMs >= checkNotNull(approvedMs))
        when (state) {
            "approval_reserved" -> require(phoneSignatureSha256 == null)
            "approval_signed" -> require(phoneSignatureSha256 != null && approvedMs == null)
            "approved", "install_reserved" -> require(approvedMs != null && installedSignatureSha256 == null)
            "install_signed" -> require(installedSignatureSha256 != null && installedMs == null)
            "active" -> require(installedMs != null)
            "stopped", "expired" -> Unit
            else -> error("Interval journal phase")
        }
    }
}

@Dao
abstract class ConversationInterval03Dao {
    @Query("SELECT * FROM conversation_intervals03 WHERE intervalId = :id")
    abstract fun find(id: String): ConversationInterval03Record?
    @Query("SELECT COUNT(*) FROM conversation_intervals03 WHERE scopeToken = :scope AND state NOT IN ('stopped', 'expired') AND intervalExpiresMs > :now")
    protected abstract fun live(scope: String, now: Long): Int
    @Query("SELECT COUNT(*) FROM conversation_intervals03 WHERE budgetToken = :budget AND reservedMs > :since")
    protected abstract fun allocations(budget: String, since: Long): Int
    @Query("UPDATE conversation_intervals03 SET state = 'expired' WHERE scopeToken = :scope AND state NOT IN ('stopped', 'expired') AND intervalExpiresMs <= :now")
    protected abstract fun expireElapsed(scope: String, now: Long): Int
    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract fun insert(row: ConversationInterval03Record)
    @androidx.room.Update
    protected abstract fun update(row: ConversationInterval03Record): Int

    /** Only an explicit foreground decision invokes this writer, before hardware signing.
     * Existing UNKNOWN reservations are retained, including when the process has been lost.
     * A signed interval's setup expiry does not imply that server installation never happened.
     */
    @Transaction
    open fun reserve(row: ConversationInterval03Record, now: Long, ramCurrent: () -> Unit): ConversationInterval03Record {
        ramCurrent(); row.requireShape(); require(row.state == "approval_reserved" && row.intervalExpiresMs > now)
        require(now > 0 && row.requestedMs <= now && row.reservedMs == 0L) // Actual new-allocation instant.
        check(find(row.intervalId) == null && allocations(row.budgetToken, (now - DAY_MS).coerceAtLeast(0)) < 16)
        check(live(row.scopeToken, now) < 16)
        // Only one requested/unknown/active phone ceremony per peer is currently supported.
        // Setup timeout does not release an UNKNOWN signature; the actual interval must end.
        check(live(row.scopeToken, now) == 0)
        expireElapsed(row.scopeToken, now)
        val persisted = row.copy(reservedMs = now)
        insert(persisted); ramCurrent() // A lost source rolls back allocation, expiry and budget.
        return persisted
    }
    @Transaction
    open fun advance(old: ConversationInterval03Record, next: ConversationInterval03Record, ramCurrent: () -> Unit) {
        ramCurrent(); old.requireShape(); next.requireShape()
        check(checkNotNull(find(old.intervalId)).same(old))
        require(old.intervalId == next.intervalId && old.scopeToken == next.scopeToken &&
            old.statementSha256 == next.statementSha256 && old.intervalExpiresMs == next.intervalExpiresMs &&
            old.ownerSignatureSha256 == next.ownerSignatureSha256 && old.requestedMs == next.requestedMs &&
            old.receiptId == next.receiptId && old.statementNonceSha256 == next.statementNonceSha256 &&
            old.budgetToken == next.budgetToken && old.reservedMs > 0 && old.reservedMs == next.reservedMs &&
            (old.phoneSignatureSha256 == null || old.phoneSignatureSha256 == next.phoneSignatureSha256) &&
            (old.approvedMs == null || old.approvedMs == next.approvedMs) &&
            (old.installedSignatureSha256 == null || old.installedSignatureSha256 == next.installedSignatureSha256) &&
            (old.installedMs == null || old.installedMs == next.installedMs) &&
            (old.state to next.state) in TRANSITIONS)
        check(update(next) == 1); ramCurrent()
    }
    /** Local withdrawal is unconditional and irreversible. It retains all original proof bytes.
     * It does not claim that the server has received or acknowledged Stop.
     */
    @Transaction
    open fun stop(id: String) {
        val old = find(id) ?: return
        if (old.state != "stopped") check(update(old.copy(state = "stopped")) == 1)
    }
    companion object {
        private const val DAY_MS = 86_400_000L
        private val TRANSITIONS = setOf("approval_reserved" to "approval_signed", "approval_signed" to "approved",
            "approved" to "install_reserved", "install_reserved" to "install_signed", "install_signed" to "active")
    }
}

@Database(entities = [ConversationInterval03Record::class], version = 1, exportSchema = false)
abstract class ConversationInterval03Database : RoomDatabase() {
    abstract fun intervals(): ConversationInterval03Dao
    companion object { const val FILE = "zrotext-conversation-interval03.db" }
}

/** Exact protected originals. Zero means an absent original time, never a manufactured proof. */
internal class ConversationInterval03Proof(val statement: ConversationInterval03.Statement, owner: ByteArray,
    val requestedMs: Long, phone: ByteArray? = null, val approvedMs: Long? = null,
    installed: ByteArray? = null, val installedMs: Long? = null) {
    private val owner = owner.copyOf(); private val phone = phone?.copyOf(); private val installed = installed?.copyOf()
    init {
        require(this.owner.size == 64 && (this.phone == null || this.phone.size == 64) &&
            (this.installed == null || this.installed.size == 64) && (approvedMs == null || this.phone != null) &&
            (installedMs == null || this.installed != null) && (this.installed == null || this.phone != null))
        listOfNotNull(this.owner, this.phone, this.installed).forEach(ConversationInterval03::requireRaw)
        for (time in listOfNotNull(requestedMs, approvedMs, installedMs)) require(time in statement.issuedMs until statement.setupExpiresMs)
        require(approvedMs == null || approvedMs >= requestedMs)
        require(installedMs == null || installedMs >= checkNotNull(approvedMs))
    }
    fun ownerSignature() = owner.copyOf()
    fun phoneSignature() = phone?.copyOf()
    fun installedSignature() = installed?.copyOf()
    fun withPhone(signature: ByteArray) = ConversationInterval03Proof(statement, owner, requestedMs, signature)
    fun approved(at: Long) = ConversationInterval03Proof(statement, owner, requestedMs, checkNotNull(phone), at)
    fun withInstalled(signature: ByteArray) = ConversationInterval03Proof(statement, owner, requestedMs, checkNotNull(phone), checkNotNull(approvedMs), signature)
    fun installed(at: Long) = ConversationInterval03Proof(statement, owner, requestedMs, checkNotNull(phone), checkNotNull(approvedMs), checkNotNull(installed), at)
    fun bytes(): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val s = statement.bytes(); output.write(ByteBuffer.allocate(2).putShort(s.size.toShort()).array()); output.write(s)
        for (signature in listOf(owner, phone, installed)) { output.write(if (signature == null) 0 else 1); signature?.let(output::write) }
        for (time in listOf(requestedMs, approvedMs, installedMs)) output.write(ByteBuffer.allocate(8).putLong(time ?: 0).array())
        return output.toByteArray()
    }
    override fun toString() = "ConversationInterval03Proof(redacted)"
    companion object {
        fun decode(bytes: ByteArray): ConversationInterval03Proof {
            require(bytes.size in 788..1313)
            val b = ByteBuffer.wrap(bytes.copyOf()); val size = b.short.toInt() and 65535
            require(size in 695..1092 && b.remaining() >= size + 27)
            val statement = ConversationInterval03.Statement.decode(ByteArray(size).also(b::get))
            fun signature(): ByteArray? = when (b.get().toInt()) { 0 -> null; 1 -> ByteArray(64).also(b::get); else -> error("Stored proof presence") }
            val owner = checkNotNull(signature()); val phone = signature(); val installed = signature()
            fun time() = b.long.also { require(it >= 0) }.takeIf { it != 0L }
            val requestedAt = checkNotNull(time()); val approvedAt = time(); val installedAt = time()
            require(!b.hasRemaining())
            return ConversationInterval03Proof(statement, owner, requestedAt, phone, approvedAt, installed, installedAt)
        }
    }
}

/** Never creates a protection key, and never drops/rebuilds a missing or incompatible schema. */
internal class ConversationInterval03Store(context: Context, private val protection: ConversationJournalProtection,
    private val suppression: ConversationExistingSuppressionTokens) : AutoCloseable {
    private val application = checkNotNull(context.applicationContext)
    private var db: ConversationInterval03Database? = null
    @Synchronized fun openForDecision(): ConversationInterval03Dao {
        check(protection is ConversationExistingJournalProtection)
        protection.requireAvailable(); suppression.requireAvailable()
        return (db ?: Room.databaseBuilder(application, ConversationInterval03Database::class.java,
            ConversationInterval03Database.FILE).build().also { it.openHelper.writableDatabase; db = it }).intervals()
    }
    fun record(proof: ConversationInterval03Proof, state: String, reservedMs: Long = 0): ConversationInterval03Record {
        val s = proof.statement; val hash = Draft02OutboundPreparation.hex(s.sha256())
        val scope = ReviewedIntent03.uuid(s.account) + ReviewedIntent03.uuid(s.line) + ReviewedIntent03.uuid(s.binding) +
            suppression.sender(s.peer).toByteArray(Charsets.US_ASCII)
        val budget = MessageDigest.getInstance("SHA-256").digest(scope)
        val live = MessageDigest.getInstance("SHA-256").digest(scope + s.deviceSessionDigest)
        val bytes = proof.bytes()
        val sealed = try { protection.seal(Profile03ElectionEncoding.encode(bytes), aad(s.interval.toString(), hash)) } finally { bytes.fill(0) }
        return ConversationInterval03Record(s.interval.toString(), Draft02OutboundPreparation.hex(live), hash,
            s.intervalExpiresMs, state, sealed.ciphertext, sealed.nonce, digest(proof.ownerSignature()), proof.requestedMs,
            proof.phoneSignature()?.let(::digest), proof.approvedMs, proof.installedSignature()?.let(::digest), proof.installedMs,
            s.receipt.toString(), digest(s.nonce), Draft02OutboundPreparation.hex(budget), reservedMs)
            .also { it.requireShape() }
    }
    fun proof(row: ConversationInterval03Record): ConversationInterval03Proof {
        val text = protection.open(InboundVault.Sealed(row.protectedProof.copyOf(), row.nonce.copyOf()), aad(row.intervalId, row.statementSha256))
        val bytes = java.util.Base64.getUrlDecoder().decode(text)
        return try { require(Profile03ElectionEncoding.encode(bytes) == text)
            ConversationInterval03Proof.decode(bytes).also { require(it.statement.interval.toString() == row.intervalId &&
                Draft02OutboundPreparation.hex(it.statement.sha256()) == row.statementSha256 && it.statement.intervalExpiresMs == row.intervalExpiresMs &&
                digest(it.ownerSignature()) == row.ownerSignatureSha256 && it.requestedMs == row.requestedMs &&
                it.phoneSignature()?.let(::digest) == row.phoneSignatureSha256 && it.approvedMs == row.approvedMs &&
                it.installedSignature()?.let(::digest) == row.installedSignatureSha256 && it.installedMs == row.installedMs &&
                it.statement.receipt.toString() == row.receiptId && digest(it.statement.nonce) == row.statementNonceSha256) }
        } finally { bytes.fill(0) }
    }
    @Synchronized override fun close() { db?.close(); db = null }
    private fun aad(id: String, digest: String) = "zrotext-conversation-interval03-v1:$id:$digest"
    private fun digest(bytes: ByteArray) = Draft02OutboundPreparation.hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    override fun toString() = "ConversationInterval03Store(existing-protection-only)"
}
