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
import java.security.MessageDigest

/** Separate monotonic authority history, never a persisted current-lease or content handle. */
@Entity(tableName = "manifest_heads03")
data class Profile03ManifestHead(@PrimaryKey val electionId: String, val originalIdentity: String,
    val originalVersion: Long, val version: Long, val digest: String, val ancestry: String, val acceptedMs: Long,
    val tipVersion: Long, val tipDigest: String, val tipAncestry: String, val tipAcceptedMs: Long,
    val comparedMs: Long, val state: String, val manifestSha256: String, val ciphertext: ByteArray, val nonce: ByteArray) {
    internal fun requireShape() {
        Profile03ClosedUnaccepted.uuid(electionId)
        for (hash in listOf(originalIdentity, digest, ancestry, tipDigest, tipAncestry, manifestSha256)) require(hash.matches(Regex("[0-9a-f]{64}")))
        require(originalVersion > 0 && version >= originalVersion && tipVersion >= version && acceptedMs > 0 &&
            tipAcceptedMs >= acceptedMs && comparedMs >= tipAcceptedMs && state in setOf("progress", "prepared", "installed") &&
            ciphertext.size in 16..14_000 && nonce.size == 12)
        require((state == "progress") == (version < tipVersion))
        if (version == tipVersion) require(digest == tipDigest && ancestry == tipAncestry && acceptedMs == tipAcceptedMs)
    }
    private fun metadata() = listOf(electionId, originalIdentity, originalVersion, version, digest, ancestry, acceptedMs,
        tipVersion, tipDigest, tipAncestry, tipAcceptedMs, comparedMs, state, manifestSha256)
    internal fun same(other: Profile03ManifestHead) = metadata() == other.metadata() &&
        ciphertext.contentEquals(other.ciphertext) && nonce.contentEquals(other.nonce)
    override fun toString() = "Profile03ManifestHead(protected-history)"
}

@Entity(tableName = "manifest_entries03", primaryKeys = ["electionId", "version"],
    indices = [androidx.room.Index(value = ["openingId"], unique = true)])
data class Profile03ManifestEntryRecord(val electionId: String, val version: Long, val openingId: String,
    val priorAncestry: String, val ancestry: String, val acceptedMs: Long, val ciphertext: ByteArray, val nonce: ByteArray) {
    internal fun requireShape() {
        Profile03ClosedUnaccepted.uuid(electionId); Profile03ClosedUnaccepted.uuid(openingId)
        require(version > 0 && acceptedMs > 0 && priorAncestry.matches(Regex("[0-9a-f]{64}")) && ancestry.matches(Regex("[0-9a-f]{64}")) &&
            ciphertext.size in 16..15_000 && nonce.size == 12)
    }
    override fun toString() = "Profile03ManifestEntryRecord(protected-original)"
}

@Entity(tableName = "manifest_readbacks03")
data class Profile03ManifestReadback(@PrimaryKey val challengeId: String, val electionId: String, val version: Long,
    val digest: String, val ancestry: String, val deviceSessionDigest: String, val comparedMs: Long) {
    internal fun requireShape() {
        Profile03ClosedUnaccepted.uuid(challengeId); Profile03ClosedUnaccepted.uuid(electionId)
        require(version > 0 && comparedMs > 0)
        for (hash in listOf(digest, ancestry, deviceSessionDigest)) require(hash.matches(Regex("[0-9a-f]{64}")))
    }
    override fun toString() = "Profile03ManifestReadback(historical-only)"
}

@Dao
abstract class Profile03ManifestDao {
    @Query("SELECT * FROM manifest_heads03 WHERE electionId = :election")
    abstract fun head(election: String): Profile03ManifestHead?
    @Query("SELECT * FROM manifest_entries03 WHERE electionId = :election AND version > :after ORDER BY version LIMIT 8")
    abstract fun entries(election: String, after: Long): List<Profile03ManifestEntryRecord>
    @Query("SELECT * FROM manifest_entries03 WHERE electionId = :election AND version = :version")
    abstract fun entry(election: String, version: Long): Profile03ManifestEntryRecord?
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertHead(row: Profile03ManifestHead)
    @androidx.room.Update protected abstract fun updateHead(row: Profile03ManifestHead): Int
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertEntry(row: Profile03ManifestEntryRecord)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertReadback(row: Profile03ManifestReadback)

    /** Crypto is completed outside this writer. The callback is RAM-only current lifetime/time. */
    @Transaction open fun append(old: Profile03ManifestHead?, next: Profile03ManifestHead,
        rows: List<Profile03ManifestEntryRecord>, ramCurrent: () -> Unit) {
        ramCurrent(); next.requireShape(); require(next.state != "installed" && rows.size <= 8)
        val actual = head(next.electionId)
        check(if (old == null) actual == null else actual?.same(old) == true)
        if (old != null) {
            old.requireShape()
            require(next.originalIdentity == old.originalIdentity && next.originalVersion == old.originalVersion && next.version >= old.version &&
                next.tipVersion >= old.tipVersion && next.comparedMs >= old.comparedMs && next.acceptedMs >= old.acceptedMs)
            if (next.tipVersion == old.tipVersion) require(next.tipDigest == old.tipDigest && next.tipAncestry == old.tipAncestry && next.tipAcceptedMs == old.tipAcceptedMs)
            if (next.version == old.version) require(next.digest == old.digest && next.ancestry == old.ancestry && next.acceptedMs == old.acceptedMs && next.manifestSha256 == old.manifestSha256)
        }
        var version = old?.version ?: next.originalVersion
        var prefix = old?.ancestry
        for (row in rows) {
            row.requireShape(); require(version < Long.MAX_VALUE && row.electionId == next.electionId && row.version == version + 1)
            prefix?.let { require(row.priorAncestry == it) }
            insertEntry(row); version = row.version; prefix = row.ancestry
        }
        require(version == next.version); prefix?.let { require(it == next.ancestry) }
        if (old == null) insertHead(next) else check(updateHead(next) == 1)
        ramCurrent()
    }
    @Transaction open fun readback(old: Profile03ManifestHead, next: Profile03ManifestHead,
        receipt: Profile03ManifestReadback, ramCurrent: () -> Unit) {
        ramCurrent(); old.requireShape(); next.requireShape(); receipt.requireShape()
        check(head(old.electionId)?.same(old) == true)
        require(old.state in setOf("prepared", "installed") && next.state == "installed" &&
            next.copy(state = old.state, ciphertext = old.ciphertext, nonce = old.nonce).same(old) &&
            receipt.electionId == old.electionId && receipt.version == old.version && receipt.digest == old.digest &&
            receipt.ancestry == old.ancestry && receipt.comparedMs >= old.comparedMs)
        insertReadback(receipt); check(updateHead(next) == 1); ramCurrent()
    }
}

@Database(entities = [Profile03ManifestHead::class, Profile03ManifestEntryRecord::class, Profile03ManifestReadback::class],
    version = 1, exportSchema = false)
abstract class Profile03ManifestDatabase : RoomDatabase() {
    abstract fun manifests(): Profile03ManifestDao
    companion object { const val FILE = "zrotext-manifest-history03.db" }
}

/** Existing enrollment-provisioned protection only. Lost keys/schema fail closed; nothing is
 * recreated from a downloaded checkpoint, an acknowledgement row or a claimed highwater. */
internal class Profile03ManifestStore(context: Context, private val protection: ConversationExistingJournalProtection) : AutoCloseable {
    private val application = checkNotNull(context.applicationContext)
    private var db: Profile03ManifestDatabase? = null
    @Synchronized fun dao(): Profile03ManifestDao {
        protection.requireAvailable()
        return (db ?: Room.databaseBuilder(application, Profile03ManifestDatabase::class.java,
            Profile03ManifestDatabase.FILE).build().also { it.openHelper.writableDatabase; db = it }).manifests()
    }
    fun head(election: String, identity: String, originalVersion: Long, checkpoint: Profile03ManifestHistory.Checkpoint,
        page: Profile03ManifestHistory, state: String): Profile03ManifestHead {
        val blank = Profile03ManifestHead(election, identity, originalVersion, checkpoint.authority.version,
            hex(checkpoint.authority.digest), hex(checkpoint.ancestry()), checkpoint.acceptedMs,
            page.tipVersion, hex(page.tipDigest), hex(page.tipAncestry), page.tipAcceptedMs, page.comparedMs,
            state, hex(sha(checkpoint.authority.signedBytes)), byteArrayOf(), byteArrayOf())
        return protect(blank, checkpoint.authority.signedBytes)
    }
    fun installed(head: Profile03ManifestHead) = protect(head.copy(state = "installed"), manifest(head))
    private fun protect(head: Profile03ManifestHead, manifest: ByteArray): Profile03ManifestHead {
        val sealed = protection.seal(Profile03ElectionEncoding.encode(manifest), headAad(head))
        return head.copy(ciphertext = sealed.ciphertext, nonce = sealed.nonce).also { it.requireShape() }
    }
    fun manifest(head: Profile03ManifestHead): ByteArray {
        head.requireShape()
        return decode(protection.open(InboundVault.Sealed(head.ciphertext.copyOf(), head.nonce.copyOf()), headAad(head)), 366, 9753)
            .also { require(hex(sha(it)) == head.manifestSha256) }
    }
    fun entry(election: String, prior: ByteArray, prefix: ByteArray, entry: Profile03ManifestSuccessor.Entry): Profile03ManifestEntryRecord {
        val blank = Profile03ManifestEntryRecord(election, entry.statement.successorVersion, entry.statement.opening.toString(),
            hex(prior), hex(prefix), entry.acceptedMs, byteArrayOf(), byteArrayOf())
        val payload = entry.statement.bytes() + entry.signature() + entry.successor()
        val sealed = protection.seal(Profile03ElectionEncoding.encode(payload), entryAad(blank))
        return blank.copy(ciphertext = sealed.ciphertext, nonce = sealed.nonce).also { it.requireShape() }
    }
    fun entry(row: Profile03ManifestEntryRecord): Profile03ManifestSuccessor.Entry {
        row.requireShape()
        val bytes = decode(protection.open(InboundVault.Sealed(row.ciphertext.copyOf(), row.nonce.copyOf()), entryAad(row)), 943, 10_330)
        return Profile03ManifestSuccessor.Entry(Profile03ManifestSuccessor.Statement.decode(bytes.copyOfRange(0, 513)),
            bytes.copyOfRange(513, 577), bytes.copyOfRange(577, bytes.size), row.acceptedMs).also {
                require(it.statement.opening.toString() == row.openingId && it.statement.successorVersion == row.version)
            }
    }
    private fun headAad(h: Profile03ManifestHead) = "zrotext/android/manifest-head03/v1:" + hex(sha(
        listOf(h.electionId, h.originalIdentity, h.originalVersion, h.version, h.digest, h.ancestry, h.acceptedMs,
            h.tipVersion, h.tipDigest, h.tipAncestry, h.tipAcceptedMs, h.comparedMs, h.state, h.manifestSha256).joinToString("|").toByteArray(Charsets.US_ASCII)))
    private fun entryAad(r: Profile03ManifestEntryRecord) = "zrotext/android/manifest-entry03/v1:" + hex(sha(
        listOf(r.electionId, r.version, r.openingId, r.priorAncestry, r.ancestry, r.acceptedMs).joinToString("|").toByteArray(Charsets.US_ASCII)))
    private fun decode(text: String, min: Int, max: Int) = Profile03Json.binary(mapOf("value" to text), "value", min, max)
    @Synchronized override fun close() { db?.close(); db = null }
    override fun toString() = "Profile03ManifestStore(redacted)"
    companion object {
        private fun hex(b: ByteArray) = Draft02OutboundPreparation.hex(b)
        private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    }
}
