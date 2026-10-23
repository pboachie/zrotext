// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import java.security.MessageDigest

/** One installation-wide command, not one per server/line. No key, first-ever eligibility or
 * permission follows from a row or its absence. The original command is never replaced. */
@Entity(tableName = "protection_setup_command")
data class ProtectionSetupCommand(@PrimaryKey val slot: Int = 1, val setupId: String, val openingId: String, val commandId: String,
    val accountId: String, val deviceId: String, val originSha256: String,
    val enrolledSigningKeyId: String, val requestedMs: Long,
    val openingSubmitted: Boolean = false,
    val openingCandidateB64url: String? = null, val openingCandidateSha256: String? = null) {
    internal fun requireShape() {
        require(slot == 1 && requestedMs > 0)
        listOf(setupId, openingId, commandId, accountId, deviceId).forEach(Profile03ClosedUnaccepted::uuid)
        listOf(originSha256, enrolledSigningKeyId).forEach(::protectionSetupHash)
        require((openingCandidateB64url == null) == (openingCandidateSha256 == null))
        openingCandidateB64url?.let {
            require(openingSubmitted)
            protectionSetupPacket(checkNotNull(openingCandidateB64url), checkNotNull(openingCandidateSha256), 16_384)
        }
    }
    internal fun sameOriginal(other: ProtectionSetupCommand) = copy(openingSubmitted = false,
        openingCandidateB64url = null, openingCandidateSha256 = null) ==
        other.copy(openingSubmitted = false, openingCandidateB64url = null,
            openingCandidateSha256 = null)
    override fun toString() = "ProtectionSetupCommand(original-metadata-only)"
}

/** A committed entry is an irreversible provider-call burn. Missing evidence means UNKNOWN;
 * this journal cannot distinguish a lost return from a provider that did not run. Public result
 * evidence is retained verbatim, never private/symmetric key material or permission. */
@Entity(tableName = "protection_setup_providers", primaryKeys = ["kind"],
    indices = [androidx.room.Index(value = ["operationId"], unique = true)])
data class ProtectionSetupProvider(val kind: String, val commandId: String, val operationId: String,
    val enteredMs: Long, val evidenceB64url: String? = null, val evidenceSha256: String? = null) {
    internal fun requireShape() {
        require(kind in KINDS && enteredMs > 0)
        listOf(commandId, operationId).forEach(Profile03ClosedUnaccepted::uuid)
        require((evidenceB64url == null) == (evidenceSha256 == null))
        evidenceB64url?.let { protectionSetupPacket(it, checkNotNull(evidenceSha256), 512) }
    }
    override fun toString() = "ProtectionSetupProvider(permanent-entry-history)"
    companion object {
        // The conversation journal shares the established inbound AES alias.
        internal val KINDS = listOf("canary", "suppression_hmac", "journal_aes", "withdrawal_aes")
    }
}

/** No DML clears/replaces a command, burn or original evidence. All callbacks in these writers
 * are RAM-only lifetime checks. Network, files, framework and Keystore must remain outside.
 * Opening bytes are candidates, not verified proof. A future actual authenticated adapter must
 * independently verify them before any provider call; these APIs do not invoke a provider. */
@Dao
abstract class ProtectionSetupDao {
    @Query("SELECT * FROM protection_setup_command WHERE slot = 1")
    abstract fun command(): ProtectionSetupCommand?
    @Query("SELECT * FROM protection_setup_providers ORDER BY enteredMs,kind")
    abstract fun providers(): List<ProtectionSetupProvider>
    @Query("SELECT * FROM protection_setup_providers WHERE kind = :kind")
    abstract fun provider(kind: String): ProtectionSetupProvider?
    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract fun insertCommand(row: ProtectionSetupCommand)
    @Insert(onConflict = OnConflictStrategy.ABORT)
    protected abstract fun insertProvider(row: ProtectionSetupProvider)
    @Query("UPDATE protection_setup_command SET openingSubmitted = 1 WHERE slot = 1 AND commandId = :id AND openingSubmitted = 0")
    protected abstract fun submitted(id: String): Int
    @Query("UPDATE protection_setup_command SET openingCandidateB64url = :packet,openingCandidateSha256 = :digest WHERE slot = 1 AND commandId = :command AND openingId = :id AND openingSubmitted = 1 AND openingCandidateB64url IS NULL")
    protected abstract fun opening(command: String, id: String, packet: String, digest: String): Int
    @Query("UPDATE protection_setup_providers SET evidenceB64url = :packet,evidenceSha256 = :digest WHERE kind = :kind AND commandId = :command AND operationId = :operation AND evidenceB64url IS NULL AND evidenceSha256 IS NULL")
    protected abstract fun evidence(kind: String, command: String, operation: String, packet: String, digest: String): Int

    /** Reserving public local command metadata is not permission to initialize any aliases. */
    @Transaction
    open fun reserveCommand(row: ProtectionSetupCommand, ramCurrent: () -> Unit): ProtectionSetupCommand {
        ramCurrent(); row.requireShape()
        require(!row.openingSubmitted && row.openingCandidateB64url == null)
        val old = command()
        if (old != null) {
            old.requireShape(); check(old.sameOriginal(row))
            providers().forEach { it.requireShape(); check(it.commandId == old.commandId) }
            ramCurrent(); return old
        }
        check(providers().isEmpty()) { "Original setup history is incomplete" }
        insertCommand(row)
        return checkNotNull(command()).also { check(it == row); ramCurrent() }
    }

    /** Persist before sending. Cold/unknown delivery can only reconcile this exact command. */
    @Transaction
    open fun openingWillBeSubmitted(expected: ProtectionSetupCommand, ramCurrent: () -> Unit): ProtectionSetupCommand {
        ramCurrent(); expected.requireShape(); check(command() == expected)
        if (!expected.openingSubmitted) check(submitted(expected.commandId) == 1)
        return checkNotNull(command()).also { require(it.openingSubmitted); it.requireShape(); ramCurrent() }
    }

    /** Retain the received packet exactly; neither parsing nor verification occurs under Room. */
    @Transaction
    open fun retainOpeningCandidate(expected: ProtectionSetupCommand, id: String, packet: String,
        digest: String, ramCurrent: () -> Unit): ProtectionSetupCommand {
        ramCurrent(); expected.requireShape(); check(command() == expected)
        check(expected.openingId == id)
        val next = expected.copy(openingCandidateB64url = packet, openingCandidateSha256 = digest)
        next.requireShape()
        if (expected.openingCandidateB64url == null) check(opening(expected.commandId, id, packet, digest) == 1)
        else check(expected == next) { "Original opening cannot change" }
        return checkNotNull(command()).also { check(it == next); ramCurrent() }
    }

    /** Returns true only for a NEW negative burn. False is retained history, never a new call
     * permission. The runtime must obtain independent verified first-origin authority outside
     * this journal. An unresolved earlier provider cannot be skipped or automatically retried. */
    @Transaction
    open fun reserveProviderEntry(expected: ProtectionSetupCommand, row: ProtectionSetupProvider,
        ramCurrent: () -> Unit): Boolean {
        ramCurrent(); expected.requireShape(); row.requireShape()
        check(command() == expected && expected.openingCandidateB64url != null && row.commandId == expected.commandId)
        require(row.evidenceB64url == null)
        val existing = provider(row.kind)
        if (existing != null) {
            existing.requireShape(); check(existing.commandId == row.commandId && existing.operationId == row.operationId &&
                existing.enteredMs == row.enteredMs)
            ramCurrent(); return false
        }
        val rows = providers().onEach { it.requireShape(); check(it.commandId == expected.commandId) }
        val index = ProtectionSetupProvider.KINDS.indexOf(row.kind)
        check(rows.map { it.kind }.toSet() == ProtectionSetupProvider.KINDS.take(index).toSet() &&
            rows.all { it.evidenceB64url != null } && rows.all { it.enteredMs <= row.enteredMs })
        check(row.enteredMs >= expected.requestedMs && rows.none { it.operationId == row.operationId })
        insertProvider(row); ramCurrent(); return true
    }

    /** Can record an exact recovered public result on the same burned operation, without ever
     * repeating the provider call. Missing/changed results remain unresolved. */
    @Transaction
    open fun retainProviderEvidence(expected: ProtectionSetupProvider, packet: String, digest: String,
        ramCurrent: () -> Unit): ProtectionSetupProvider {
        ramCurrent(); expected.requireShape(); check(provider(expected.kind) == expected)
        val owner = checkNotNull(command()).also { it.requireShape() }
        check(owner.commandId == expected.commandId && owner.openingCandidateB64url != null)
        val next = expected.copy(evidenceB64url = packet, evidenceSha256 = digest).also { it.requireShape() }
        if (expected.evidenceB64url == null)
            check(evidence(expected.kind, expected.commandId, expected.operationId, packet, digest) == 1)
        else check(expected == next) { "Original provider evidence cannot change" }
        return checkNotNull(provider(expected.kind)).also { check(it == next); ramCurrent() }
    }
}

/** Passive classification does not open, sign, generate, pin, clear quarantine or select a
 * replacement origin. Every restart still needs genuine current actor and first-origin proof. */
internal object ProtectionSetupRecovery {
    enum class State { NO_LOCAL_COMMAND, RECONCILE_OPENING, VERIFY_OPENING, RECONCILE_PROVIDER_RESULT, CONTINUE_EXPLICIT_SETUP, NEED_ASSOCIATION }
    fun state(command: ProtectionSetupCommand?, rows: List<ProtectionSetupProvider>): State {
        if (command == null) { check(rows.isEmpty()); return State.NO_LOCAL_COMMAND }
        command.requireShape()
        rows.forEach { it.requireShape(); check(it.commandId == command.commandId) }
        check(rows.map { it.kind }.distinct().size == rows.size)
        check(rows.map { it.operationId }.distinct().size == rows.size)
        val kinds = rows.map { it.kind }.toSet()
        check(kinds == ProtectionSetupProvider.KINDS.take(rows.size).toSet())
        val ordered = rows.sortedBy { ProtectionSetupProvider.KINDS.indexOf(it.kind) }
        check(ordered.all { it.enteredMs >= command.requestedMs } &&
            ordered.zipWithNext().all { (first, second) -> first.enteredMs <= second.enteredMs })
        if (command.openingCandidateB64url == null) { check(rows.isEmpty()); return State.RECONCILE_OPENING }
        if (rows.isEmpty()) return State.VERIFY_OPENING
        if (rows.any { it.evidenceB64url == null }) {
            check(rows.count { it.evidenceB64url == null } == 1 && rows.lastByKind().evidenceB64url == null)
            return State.RECONCILE_PROVIDER_RESULT
        }
        return if (rows.size == ProtectionSetupProvider.KINDS.size) State.NEED_ASSOCIATION else State.CONTINUE_EXPLICIT_SETUP
    }
    private fun List<ProtectionSetupProvider>.lastByKind() = maxBy { ProtectionSetupProvider.KINDS.indexOf(it.kind) }
}

private fun protectionSetupHash(value: String) {
    require(value.matches(Regex("[0-9a-f]{64}")) && value.any { it != '0' })
}
private fun protectionSetupPacket(packet: String, digest: String, maximum: Int) {
    protectionSetupHash(digest)
    require(packet.length in 2..((maximum * 4 + 2) / 3))
    val bytes = java.util.Base64.getUrlDecoder().decode(packet)
    require(bytes.size in 1..maximum && Profile03ElectionEncoding.encode(bytes) == packet)
    require(Draft02OutboundPreparation.hex(MessageDigest.getInstance("SHA-256").digest(bytes)) == digest)
}
