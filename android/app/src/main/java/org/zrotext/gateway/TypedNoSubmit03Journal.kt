// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import java.util.concurrent.atomic.AtomicBoolean

/** Created with the FIRST local command before challenge I/O, never by migration/status.
 * Its append-only predecessor chain covers every local signature and transport burn. */
@Entity(tableName = "typed_no_submit03_lineages", indices = [Index(value = ["attemptId"], unique = true)])
internal data class TypedNoSubmit03Lineage(@PrimaryKey val closureId: String, val attemptId: String,
    val closureSha256: String, val originalCommandSha256: String, val rootRequestId: String, val currentRequestId: String,
    /** Positive integrity counts from the original command, NEVER MAX/empty-state repair. */
    val proofCount: Long = 1, val ioCount: Long = 0)

@Entity(tableName = "typed_no_submit03_proofs", indices = [Index("closureId"), Index(value = ["previousRequestId"], unique = true)])
internal data class TypedNoSubmit03Proof(@PrimaryKey val requestId: String, val attemptId: String,
    val closureId: String, val closureSha256: String, val commandSha256: String,
    val previousRequestId: String? = null, val previousChallengeId: String? = null,
    val previousCoreSha256: String? = null, val previousExpiresMs: Long? = null,
    val coreB64url: String? = null, val nonceB64url: String? = null,
    val signatureState: String = "unused", val signatureB64url: String? = null,
    val signatureClockId: String? = null, val signatureStatusId: String? = null,
    val acceptedMs: Long? = null) {
    fun requireOriginal(row: TypedSubmit03Record) {
        row.requireShape(); TypedNoSubmit03Wire.uuid(requestId)
        val closed = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
        require(row.phase == "closed_no_submit" && row.originalOriginSha256 != null &&
            row.attemptId == attemptId && closed.closureId == closureId && row.closureSha256 == closureSha256 && row.commandSha256 == commandSha256)
        require(listOf(previousChallengeId, previousCoreSha256, previousExpiresMs).all { (it == null) == (previousRequestId == null) })
        previousRequestId?.let { TypedNoSubmit03Wire.uuid(it); TypedNoSubmit03Wire.uuid(checkNotNull(previousChallengeId))
            require(checkNotNull(previousCoreSha256).matches(Regex("[0-9a-f]{64}")) && checkNotNull(previousExpiresMs) > 0) }
        require((coreB64url == null) == (nonceB64url == null) && signatureState in setOf("unused", "reserved", "result") &&
            (signatureB64url != null) == (signatureState == "result") && (signatureState == "unused" || coreB64url != null))
        require((signatureClockId == null) == (signatureState == "unused") && (signatureStatusId == null) == (signatureState == "unused"))
        signatureClockId?.let(TypedNoSubmit03Wire::uuid); signatureStatusId?.let(TypedNoSubmit03Wire::uuid)
        coreB64url?.let { challenge().core.requireOriginal(row, challenge().nonce()) }
        signatureB64url?.let {
            val raw = TypedSubmit03Record.unbase(it); require(raw.size == 64)
            val order = java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
            val r = java.math.BigInteger(1, raw.copyOfRange(0, 32)); val s = java.math.BigInteger(1, raw.copyOfRange(32, 64))
            require(r.signum() > 0 && r < order && s.signum() > 0 && s <= order.shiftRight(1))
        }
        acceptedMs?.let { require(signatureB64url != null && it in challenge().core.issuedMs until challenge().core.expiresMs) }
    }
    fun challenge(): TypedNoSubmit03Wire.Challenge {
        val core = TypedNoSubmit03Core.decode(TypedSubmit03Record.unbase(checkNotNull(coreB64url)))
        require(core.proofRequestId == requestId && core.id(5) == closureId)
        val previous = previousChallengeId?.let { TypedNoSubmit03Wire.Predecessor(it, checkNotNull(previousCoreSha256), core.issuedMs, core.challengeId) }
        return TypedNoSubmit03Wire.Challenge(core, TypedSubmit03Record.unbase(checkNotNull(nonceB64url)), previous)
    }
    override fun toString() = "TypedNoSubmit03Proof(permanent-signature-lineage)"
}

/** Every actual invocation gets its own COMMITTED envelope burn. A new explicit replay
 * keeps the same proof command; cold entered rows never remint a transport ticket. */
@Entity(tableName = "typed_no_submit03_io", indices = [Index("proofRequestId"), Index("closureId"), Index(value = ["proofRequestId", "kind", "replyB64url"])])
internal data class TypedNoSubmit03Io(@PrimaryKey val requestId: String, val proofRequestId: String, val closureId: String,
    val kind: String, val connectionEpoch: Long, val requestB64url: String, val replyB64url: String? = null) {
    fun bytes() = TypedSubmit03Record.unbase(requestB64url)
}
/** Exact before/after receipt returned by the SAME writer, escaping only after Room
 * COMMIT. Advancing a captured action uses this receipt, never an unrelated later read. */
internal class TypedNoSubmit03First internal constructor(val before: TypedSubmit03Record,
    val after: TypedSubmit03Record, val proof: TypedNoSubmit03Proof) {
    init {
        require(before.closureProofState == "eligible:${proof.closureId}" &&
            after == before.copy(closureProofState = "started:${proof.requestId}"))
        proof.requireOriginal(after)
    }
}
internal class TypedNoSubmit03Entry internal constructor(val original: TypedSubmit03Record,
    val proof: TypedNoSubmit03Proof, val io: TypedNoSubmit03Io) {
    private val unused = AtomicBoolean(true)
    fun consume(): ByteArray { check(unused.compareAndSet(true, false)); return io.bytes() }
}
internal class TypedNoSubmit03SignEntry internal constructor(val original: TypedSubmit03Record, val proof: TypedNoSubmit03Proof) {
    private val unused = AtomicBoolean(true)
    fun consume(): TypedNoSubmit03Core { check(unused.compareAndSet(true, false)); return proof.challenge().core }
}

@Dao
internal abstract class TypedNoSubmit03Dao {
    @Query("SELECT * FROM typed_no_submit03_lineages WHERE closureId=:closure") abstract fun lineage(closure: String): TypedNoSubmit03Lineage?
    @Query("SELECT * FROM typed_no_submit03_proofs WHERE requestId=:id") abstract fun proof(id: String): TypedNoSubmit03Proof?
    @Query("SELECT * FROM typed_no_submit03_io WHERE requestId=:id") abstract fun io(id: String): TypedNoSubmit03Io?
    @Query("SELECT * FROM typed_no_submit03_io WHERE proofRequestId=:id AND requestId>:after ORDER BY requestId LIMIT 16")
    abstract fun history(id: String, after: String = ""): List<TypedNoSubmit03Io>
    @Query("SELECT s.* FROM typed_submit03 s WHERE s.accountId=:account AND s.deviceId=:device AND s.originalOriginSha256=:origin AND s.originalEnrolledPoint=:point AND s.phase='closed_no_submit' AND s.closureProofState IS NOT NULL AND s.conflict=0 AND s.lastCallbackOrdinal=0 AND s.attemptId>:after AND NOT EXISTS(SELECT 1 FROM typed_no_submit03_lineages l JOIN typed_no_submit03_proofs p ON p.requestId=l.currentRequestId WHERE l.attemptId=s.attemptId AND p.acceptedMs IS NOT NULL) ORDER BY s.attemptId LIMIT 16")
    abstract fun choices(account: String, device: String, origin: String, point: String, after: String): List<TypedSubmit03Record>
    @Query("SELECT * FROM typed_submit03 WHERE attemptId=:id") protected abstract fun submit(id: String): TypedSubmit03Record?
    @Query("SELECT EXISTS(SELECT 1 FROM typed_callback03 WHERE attemptId=:id)") protected abstract fun hasCallbacks(id: String): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM typed_no_submit03_io WHERE proofRequestId=:id AND kind='challenge')")
    protected abstract fun hasChallengeResult(id: String): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM typed_no_submit03_proofs WHERE closureId=:id)") protected abstract fun hasProofHistory(id: String): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM typed_no_submit03_io i LEFT JOIN typed_no_submit03_proofs p ON p.requestId=i.proofRequestId WHERE i.closureId=:id AND (p.requestId IS NULL OR p.closureId!=i.closureId))")
    protected abstract fun hasUncoveredIo(id: String): Boolean
    @Query("SELECT COUNT(*) FROM typed_no_submit03_proofs WHERE closureId=:id") protected abstract fun proofCount(id: String): Long
    @Query("SELECT COUNT(*) FROM typed_no_submit03_io WHERE closureId=:id") protected abstract fun ioCount(id: String): Long
    @Query("SELECT * FROM typed_history03_clocks WHERE requestId=:id") protected abstract fun clock(id: String): TypedHistory03Request?
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insert(row: TypedNoSubmit03Lineage)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insert(row: TypedNoSubmit03Proof)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insert(row: TypedNoSubmit03Io)
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedSubmit03Record): Int
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedNoSubmit03Lineage): Int
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedNoSubmit03Proof): Int
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedNoSubmit03Io): Int

    private fun closed(row: TypedSubmit03Record) = submit(row.attemptId) == row && row.phase == "closed_no_submit" &&
        !row.conflict && row.originalOriginSha256 != null && row.lastCallbackOrdinal == 0L && !hasCallbacks(row.attemptId)
    private fun held(row: TypedSubmit03Record, p: TypedNoSubmit03Proof, negative: Boolean = true): Boolean {
        p.requireOriginal(row)
        val l = lineage(p.closureId) ?: return false
        if (submit(row.attemptId) != row || negative && !closed(row) || proof(p.requestId) != p ||
            l.closureId != p.closureId || l.attemptId != p.attemptId || l.closureSha256 != p.closureSha256 ||
            l.originalCommandSha256 != p.commandSha256 || l.currentRequestId != p.requestId ||
            row.closureProofState != "started:${l.rootRequestId}" ||
            l.proofCount < 1 || l.ioCount < 0 || proofCount(p.closureId) != l.proofCount ||
            ioCount(p.closureId) != l.ioCount || hasUncoveredIo(p.closureId)) return false
        // Verify the WHOLE retained chain, including grandparents. Query pages stay <=16;
        // no history cap, MAX repair, provider/OS wait or unbounded I/O-list load exists.
        // Counts detect pruned rows; actual indexed links/core/packets provide coverage.
        var child: TypedNoSubmit03Proof? = null
        var at: TypedNoSubmit03Proof? = p
        var seen = 0L; var seenIo = 0L
        while (at != null) {
            val item = at
            seen = Math.addExact(seen, 1); if (seen > l.proofCount) return false // Also rejects cycles.
            item.requireOriginal(row)
            val successor = child
            if (successor != null) {
                val core = item.challenge().core
                if (item.acceptedMs != null || successor.previousRequestId != item.requestId ||
                    successor.previousChallengeId != core.challengeId || successor.previousCoreSha256 != TypedSubmit03Record.hex(core.sha256()) ||
                    successor.previousExpiresMs != core.expiresMs || successor.coreB64url != null && successor.challenge().core.issuedMs < core.expiresMs) return false
            }
            var after = ""; var challenges = 0L; var signatures = 0L
            while (true) {
                val page = history(item.requestId, after)
                for (entry in page) {
                    seenIo = Math.addExact(seenIo, 1)
                    if (seenIo > l.ioCount || entry.closureId != p.closureId || entry.connectionEpoch <= 0) return false
                    TypedNoSubmit03Wire.uuid(entry.requestId)
                    val expected = when (entry.kind) {
                        "challenge" -> { challenges++; TypedNoSubmit03Wire.challengeRequest(row, item, entry.connectionEpoch) }
                        "status" -> TypedNoSubmit03Wire.statusRequest(row, item, entry.requestId, entry.connectionEpoch)
                        "proof" -> { if (item.signatureState != "result") return false; TypedNoSubmit03Wire.proofRequest(item, entry.connectionEpoch) }
                        "signature" -> {
                            signatures++
                            if (entry.requestId != item.requestId || item.signatureState == "unused" ||
                                entry.connectionEpoch != item.challenge().core.number(2) || entry.replyB64url != item.signatureB64url) return false
                            item.challenge().core.transcript()
                        }
                        else -> return false
                    }
                    if (!entry.bytes().contentEquals(expected)) return false
                    entry.replyB64url?.let { encoded ->
                        val raw = TypedSubmit03Record.unbase(encoded)
                        when (entry.kind) {
                            "challenge" -> {
                                val checked = TypedNoSubmit03Wire.decodeChallenge(raw, row, item, entry.connectionEpoch)
                                if (item.coreB64url != null && (item.coreB64url != TypedSubmit03Record.base(checked.core.bytes()) ||
                                    item.nonceB64url != TypedSubmit03Record.base(checked.nonce()))) return false
                            }
                            "status" -> TypedNoSubmit03Wire.decodeStatus(raw, row, item, entry.requestId, entry.connectionEpoch)
                            "proof" -> TypedNoSubmit03Wire.decodeAck(raw, row, item, entry.connectionEpoch)
                            else -> Unit // Signature result is the exact raw64, never JSON.
                        }
                    }
                    after = entry.requestId
                }
                if (page.size < 16) break
            }
            val expectedSignatures = if (item.signatureState == "unused") 0L else 1L
            if (item.coreB64url != null && challenges == 0L || signatures != expectedSignatures) return false
            if (expectedSignatures == 1L && !signatureBasis(row, item)) return false
            child = item
            at = item.previousRequestId?.let { proof(it) ?: return false }
        }
        return child?.requestId == l.rootRequestId && seen == l.proofCount && seenIo == l.ioCount
    }
    /** Historical provenance ONLY: checking old bytes never constructs a live Sample. */
    private fun signatureBasis(row: TypedSubmit03Record, p: TypedNoSubmit03Proof): Boolean {
        val basis = clock(checkNotNull(p.signatureClockId)) ?: return false
        basis.requireOriginal(row)
        if (!basis.entered || basis.replyB64url == null || basis.subjectKind != "proof" || basis.subjectId != p.requestId) return false
        val core = p.challenge().core
        val reply = TypedHistory03Wire.decode(TypedSubmit03Record.unbase(basis.replyB64url), basis.query(), row.accountId,
            row.deviceId, basis.connectionEpoch, basis.lineVersion, TypedSubmit03Record.unbase(row.originalEnrolledPoint))
        if (basis.connectionEpoch != core.number(2) || reply.deploymentEpoch != core.number(3) ||
            reply.serverMs < core.issuedMs || core.expiresMs > reply.leaseExpiresMs ||
            !reply.sessionDigest().contentEquals(core.digest(3))) return false
        val status = io(checkNotNull(p.signatureStatusId)) ?: return false
        if (status.kind != "status" || status.proofRequestId != p.requestId || status.closureId != p.closureId ||
            status.connectionEpoch != basis.connectionEpoch || status.replyB64url == null) return false
        return TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(status.replyB64url), row, p,
            status.requestId, status.connectionEpoch).status == "challenged"
    }
    @Transaction open fun first(row: TypedSubmit03Record, id: String, current: () -> Unit): TypedNoSubmit03First? {
        current(); row.requireShape(); TypedNoSubmit03Wire.uuid(id)
        if (!closed(row)) return null
        val closure = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
        if (row.closureProofState != "eligible:${closure.closureId}" || lineage(closure.closureId) != null || hasProofHistory(closure.closureId) || hasUncoveredIo(closure.closureId) || proof(id) != null) return null
        val p = TypedNoSubmit03Proof(id, row.attemptId, closure.closureId, checkNotNull(row.closureSha256), row.commandSha256)
        p.requireOriginal(row)
        val next = row.copy(closureProofState = "started:${p.requestId}").also { it.requireShape() }
        insert(p); insert(TypedNoSubmit03Lineage(p.closureId, p.attemptId, p.closureSha256, p.commandSha256, p.requestId, p.requestId))
        check(update(next) == 1)
        current(); return TypedNoSubmit03First(row, next, p)
    }
    /** Replacement is a new explicit command over the SAME local negative row. Only a
     * new successor reply may certify the direct link; old status supplies no successor. */
    @Transaction open fun replace(row: TypedSubmit03Record, old: TypedNoSubmit03Proof, status: TypedNoSubmit03Io,
        observed: TypedHistory03Connections.Host.ClosureReply, actual: TypedHistory03Clock.Sample,
        request: TypedHistory03Request, id: String, current: () -> Unit): TypedNoSubmit03Proof? {
        current(); if (!held(row, old) || old.acceptedMs != null || io(status.requestId) != status || status.kind != "status") return null
        observed.requireLiveStatus()
        require(observed.io == status.copy(replyB64url = null) && status.replyB64url == TypedSubmit03Record.base(observed.bytes()) &&
            request.connectionEpoch == status.connectionEpoch)
        val checked = TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(checkNotNull(status.replyB64url)), row, old, status.requestId, status.connectionEpoch)
        if (checked.status != "challenged" || clock(request.requestId) != request || request.subjectKind != "proof" || request.subjectId != old.requestId) return null
        actual.requireExpiredProof(row, request, old.challenge().core)
        val next = TypedNoSubmit03Proof(id, old.attemptId, old.closureId, old.closureSha256, old.commandSha256,
            old.requestId, old.challenge().core.challengeId, TypedSubmit03Record.hex(old.challenge().core.sha256()), old.challenge().core.expiresMs)
        next.requireOriginal(row); if (proof(id) != null) return null
        val l = checkNotNull(lineage(old.closureId))
        insert(next); check(update(l.copy(currentRequestId = id, proofCount = Math.addExact(l.proofCount, 1))) == 1)
        current(); observed.requireLiveStatus(); actual.requireExpiredProof(row, request, old.challenge().core); return next
    }
    @Transaction open fun enter(row: TypedSubmit03Record, p: TypedNoSubmit03Proof, candidate: TypedNoSubmit03Io,
        current: () -> Unit, context: TypedNoSubmit03Context? = null): TypedNoSubmit03Entry? {
        current(); p.requireOriginal(row); TypedNoSubmit03Wire.uuid(candidate.requestId)
        require(candidate.proofRequestId == p.requestId && candidate.closureId == p.closureId && candidate.replyB64url == null && candidate.connectionEpoch > 0)
        if (!held(row, p, candidate.kind != "status" && p.acceptedMs == null) || io(candidate.requestId) != null) return null
        val expected = when (candidate.kind) {
            "challenge" -> { require(p.coreB64url == null && p.signatureState == "unused"); TypedNoSubmit03Wire.challengeRequest(row, p, candidate.connectionEpoch) }
            "status" -> TypedNoSubmit03Wire.statusRequest(row, p, candidate.requestId, candidate.connectionEpoch)
            "proof" -> {
                require(p.signatureState == "result")
                if (p.acceptedMs == null) checkNotNull(context).requireCurrent(row, p)
                TypedNoSubmit03Wire.proofRequest(p, candidate.connectionEpoch)
            }
            else -> error("Closure operation")
        }
        require(candidate.bytes().contentEquals(expected)); insert(candidate)
        val l = checkNotNull(lineage(p.closureId)); check(update(l.copy(ioCount = Math.addExact(l.ioCount, 1))) == 1); current()
        if (candidate.kind == "proof" && p.acceptedMs == null) checkNotNull(context).requireCurrent(row, p)
        return TypedNoSubmit03Entry(row, p, candidate)
    }
    /** Parse/crypto checks run outside Room. This exact returned append grants no clock or
     * permission, even if the user/host/callback changed during the provider or network. */
    @Transaction open fun retainReply(expected: TypedNoSubmit03Io, raw: ByteArray): Boolean {
        require(raw.size in 2..4096 && expected.replyB64url == null)
        if (io(expected.requestId) != expected) return false
        check(update(expected.copy(replyB64url = TypedSubmit03Record.base(raw))) == 1); return true
    }
    @Transaction open fun retainChallenge(row: TypedSubmit03Record, expected: TypedNoSubmit03Proof,
        result: TypedNoSubmit03Io, challenge: TypedNoSubmit03Wire.Challenge): TypedNoSubmit03Proof? {
        if (proof(expected.requestId) != expected || io(result.requestId) != result || result.replyB64url == null ||
            result.proofRequestId != expected.requestId || result.kind !in setOf("challenge", "status")) return null
        challenge.core.requireOriginal(row, challenge.nonce())
        // Caller supplies a parsed result, but the retained exact bytes must independently
        // select this SAME challenge before any state transition.
        val parsed = if (result.kind == "challenge") TypedNoSubmit03Wire.decodeChallenge(TypedSubmit03Record.unbase(result.replyB64url), row, expected, result.connectionEpoch)
            else TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(result.replyB64url), row, expected, result.requestId, result.connectionEpoch).challenge ?: return null
        require(parsed.core.bytes().contentEquals(challenge.core.bytes()) && parsed.nonce().contentEquals(challenge.nonce()))
        if (expected.coreB64url != null) { require(expected.coreB64url == TypedSubmit03Record.base(challenge.core.bytes()) && expected.nonceB64url == TypedSubmit03Record.base(challenge.nonce())); return expected }
        val next = expected.copy(coreB64url = TypedSubmit03Record.base(challenge.core.bytes()), nonceB64url = TypedSubmit03Record.base(challenge.nonce()))
        next.requireOriginal(row); check(update(next) == 1); return next
    }
    @Transaction open fun reserveSignature(row: TypedSubmit03Record, p: TypedNoSubmit03Proof,
        status: TypedNoSubmit03Io, context: TypedNoSubmit03Context): TypedNoSubmit03SignEntry? {
        context.requireCurrent(row, p)
        context.requireClock(clock(context.clockRequestId))
        if (!held(row, p) || p.signatureState != "unused" || p.acceptedMs != null || !hasChallengeResult(p.requestId) ||
            io(status.requestId) != status || status.kind != "status" || status.connectionEpoch != context.epoch) return null
        val checked = TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(checkNotNull(status.replyB64url)), row, p, status.requestId, status.connectionEpoch)
        if (checked.status != "challenged" || context.statusRequestId != status.requestId) return null
        val next = p.copy(signatureState = "reserved", signatureClockId = context.clockRequestId,
            signatureStatusId = context.statusRequestId); check(update(next) == 1)
        // The independent immutable burn cannot be turned back into UNUSED by a missing
        // result, a changed state field or a cold process. It is never a transport ticket.
        insert(TypedNoSubmit03Io(p.requestId, p.requestId, p.closureId, "signature", context.epoch,
            TypedSubmit03Record.base(p.challenge().core.transcript())))
        val l = checkNotNull(lineage(p.closureId)); check(update(l.copy(ioCount = Math.addExact(l.ioCount, 1))) == 1)
        context.requireCurrent(row, next); return TypedNoSubmit03SignEntry(row, next)
    }
    @Transaction open fun retainSignature(expected: TypedNoSubmit03Proof, signature: ByteArray): TypedNoSubmit03Proof? {
        require(expected.signatureState == "reserved" && expected.signatureB64url == null && signature.size == 64)
        if (proof(expected.requestId) != expected) return null
        val burned = io(expected.requestId) ?: return null
        require(burned.kind == "signature" && burned.proofRequestId == expected.requestId && burned.closureId == expected.closureId &&
            burned.replyB64url == null && burned.bytes().contentEquals(expected.challenge().core.transcript()))
        val next = expected.copy(signatureState = "result", signatureB64url = TypedSubmit03Record.base(signature))
        check(update(burned.copy(replyB64url = next.signatureB64url)) == 1)
        check(update(next) == 1); return next
    }
    @Transaction open fun retainAccepted(row: TypedSubmit03Record, p: TypedNoSubmit03Proof, result: TypedNoSubmit03Io): Boolean {
        if (proof(p.requestId) != p || io(result.requestId) != result || result.proofRequestId != p.requestId) return false
        val raw = TypedSubmit03Record.unbase(checkNotNull(result.replyB64url))
        val accepted = if (result.kind == "proof") TypedNoSubmit03Wire.decodeAck(raw, row, p, result.connectionEpoch)
            else if (result.kind == "status") TypedNoSubmit03Wire.decodeStatus(raw, row, p, result.requestId, result.connectionEpoch).acceptedMs ?: return false
            else return false
        require(p.acceptedMs == null || p.acceptedMs == accepted)
        check(update(p.copy(acceptedMs = accepted)) == 1); return true
    }
}
