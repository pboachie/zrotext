// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/** Negative-only callback epoch, captured at the affirmative action BEFORE queue/writer
 * waits. No epoch value proves absence of callbacks; the SAME Room writer checks facts. */
internal object TypedNoSubmit03Lifetimes {
    private val epoch = AtomicLong(0)
    class Ticket internal constructor(private val captured: Long) { fun requireCurrent() { check(epoch.get() == captured) } }
    fun capture() = Ticket(epoch.get())
    fun callbackArriving() { epoch.incrementAndGet() }
}
internal class TypedNoSubmit03Action private constructor(val row: TypedSubmit03Record,
    val host: TypedHistory03Connections.Host, val decision: ConversationInterval03Foreground.Decision,
    private val callbacks: TypedNoSubmit03Lifetimes.Ticket) {
    fun requireCurrent() { check(decision.isCurrent()); callbacks.requireCurrent(); host.requireOriginal(row); check(decision.isCurrent()) }
    /** Only the exact committed first-transition receipt may advance this decision. A
     * generic SELECT/new row can never be rebound to an old affirmative action. */
    fun afterFirst(receipt: TypedNoSubmit03First): TypedNoSubmit03Action {
        requireCurrent(); require(receipt.before == row)
        return TypedNoSubmit03Action(receipt.after, host, decision, callbacks).also { it.requireCurrent() }
    }
    companion object {
        fun capture(row: TypedSubmit03Record, host: TypedHistory03Connections.Host,
            decision: ConversationInterval03Foreground.Decision) = TypedNoSubmit03Action(row, host, decision,
                TypedNoSubmit03Lifetimes.capture()).also { it.requireCurrent() }
    }
}

/** Actual explicit producer. It reuses the single history worker; reconnect/scans never
 * invoke it. The two injected boundaries in tests are only the socket and existing signer. */
internal class TypedNoSubmit03Reporter(private val journal: SmsJournalDatabase,
    private val signer: (TypedNoSubmit03SignEntry, TypedNoSubmit03Context) -> ByteArray) {
    private val dao get() = journal.typedNoSubmits03()
    data class Result(val completed: Boolean, val text: String)

    fun status(action: TypedNoSubmit03Action): Result {
        action.requireCurrent()
        val row = action.row
        row.requireShape()
        require(row.phase == "closed_no_submit" && journal.typedSubmits03().get(row.attemptId) == row)
        val closure = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
        val p = dao.lineage(closure.closureId)?.let { dao.proof(it.currentRequestId) }
            ?: return Result(false, if (row.closureProofState == "eligible:${closure.closureId}")
                "No cancellation report has been requested. The saved cancellation is unchanged."
                else "Original cancellation reporting history is unavailable. The saved cancellation remains unconfirmed.")
        val (io, _) = exchange(action, p, "status")
        if (dao.retainAccepted(row, p, io)) return complete()
        val checked = TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(checkNotNull(io.replyB64url)), row, p, io.requestId, io.connectionEpoch)
        return Result(false, when (checked.status) {
            "superseded" -> "This saved proof was replaced. Its original history remains saved."
            "challenged" -> "The cancellation is not confirmed. Report the saved cancellation to continue explicitly."
            else -> "The cancellation is not confirmed. Its original request remains saved."
        })
    }
    fun report(captured: TypedNoSubmit03Action): Result {
        var action = captured
        action.requireCurrent()
        val closure = closed(action.row)
        var p = dao.lineage(closure.closureId)?.let { checkNotNull(dao.proof(it.currentRequestId)) } ?: run {
            val receipt = dao.first(action.row, id(), action::requireCurrent) ?: return pending()
            action = action.afterFirst(receipt)
            receipt.proof
        }
        val row = action.row
        if (p.coreB64url == null) {
            // Explicit SAME command reconciliation only, never a replacement on not_found.
            val (io, _) = exchange(action, p, "challenge")
            val challenge = TypedNoSubmit03Wire.decodeChallenge(TypedSubmit03Record.unbase(checkNotNull(io.replyB64url)), row, p, io.connectionEpoch)
            p = dao.retainChallenge(row, p, io, challenge) ?: return pending()
        }
        var checked = statusFor(action, p) ?: return complete()
        var sample = clock(action, p)
        // One explicit replacement at most. Conservative upper alone cannot prove expiry;
        // independently sampled actual primary must reach the old immutable end.
        if (!sample.first.proofExpired(row, sample.second, p.challenge().core)) {
            return signAndReport(action, p, checked, sample)
        }
        p = dao.replace(row, p, checked.first, checked.second, sample.first, sample.second, id(), action::requireCurrent) ?: return pending()
        val (newIo, _) = exchange(action, p, "challenge")
        val successor = TypedNoSubmit03Wire.decodeChallenge(TypedSubmit03Record.unbase(checkNotNull(newIo.replyB64url)), row, p, newIo.connectionEpoch)
        p = dao.retainChallenge(row, p, newIo, successor) ?: return pending()
        checked = statusFor(action, p) ?: return complete()
        sample = clock(action, p)
        return signAndReport(action, p, checked, sample)
    }
    private fun signAndReport(action: TypedNoSubmit03Action, initial: TypedNoSubmit03Proof,
        status: Pair<TypedNoSubmit03Io, TypedHistory03Connections.Host.ClosureReply>,
        sample: Pair<TypedHistory03Clock.Sample, TypedHistory03Request>): Result {
        var p = initial
        val context = TypedNoSubmit03Context.from(action.host, action.decision, action.row, p, status.first,
            status.second, sample.first, sample.second, action::requireCurrent)
        if (p.signatureState == "unused") {
            val entry = dao.reserveSignature(action.row, p, status.first, context) ?: return pending()
            context.requireCurrent(action.row, entry.proof); action.requireCurrent()
            val actual = signer(entry, context)
            // Actual result history precedes all post-provider decision/actor checks.
            require(ConversationContentCrypto.verifyRaw(actual, TypedSubmit03Record.unbase(action.row.originalEnrolledPoint), entry.proof.challenge().core.transcript()))
            p = dao.retainSignature(entry.proof, actual) ?: return pending()
        }
        if (p.signatureState != "result") return pending() // Lost provider result is never re-signed.
        context.requireCurrent(action.row, p); action.requireCurrent()
        val (io, _) = exchange(action, p, "proof", context) { context.requireCurrent(action.row, p) }
        return if (dao.retainAccepted(action.row, p, io)) complete() else pending()
    }
    private fun statusFor(action: TypedNoSubmit03Action, p: TypedNoSubmit03Proof): Pair<TypedNoSubmit03Io, TypedHistory03Connections.Host.ClosureReply>? {
        val result = exchange(action, p, "status")
        if (dao.retainAccepted(action.row, p, result.first)) return null
        val checked = TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(checkNotNull(result.first.replyB64url)), action.row, p,
            result.first.requestId, result.first.connectionEpoch)
        require(checked.status == "challenged") { "Unresolved or superseded proof cannot sign or select a new command" }
        result.second.requireLiveStatus(); action.requireCurrent()
        return result
    }
    private fun exchange(action: TypedNoSubmit03Action, p: TypedNoSubmit03Proof, kind: String,
        proofContext: TypedNoSubmit03Context? = null, additionalCurrent: () -> Unit = {}): Pair<TypedNoSubmit03Io, TypedHistory03Connections.Host.ClosureReply> {
        action.requireCurrent(); additionalCurrent()
        val id = id(); val raw = when (kind) {
            "challenge" -> TypedNoSubmit03Wire.challengeRequest(action.row, p, action.host.epoch)
            "status" -> TypedNoSubmit03Wire.statusRequest(action.row, p, id, action.host.epoch)
            "proof" -> TypedNoSubmit03Wire.proofRequest(p, action.host.epoch)
            else -> error("Closure operation")
        }
        val io = TypedNoSubmit03Io(id, p.requestId, p.closureId, kind, action.host.epoch, TypedSubmit03Record.base(raw))
        val current = { action.requireCurrent(); additionalCurrent() }
        val entry = dao.enter(action.row, p, io, current, proofContext) ?: error("Original closure changed")
        val returned = action.host.exchangeClosure(entry, current)
        check(dao.retainReply(io, returned.bytes()))
        return checkNotNull(dao.io(id)) to returned
    }
    private fun clock(action: TypedNoSubmit03Action, p: TypedNoSubmit03Proof): Pair<TypedHistory03Clock.Sample, TypedHistory03Request> {
        action.requireCurrent()
        val row = action.row; val host = action.host; val id = id()
        val query = TypedHistory03Wire.Query(id, row.messageId, row.attemptId)
        val candidate = TypedHistory03Request(id, row.attemptId, row.messageId, row.commandSha256, p.requestId, "proof",
            row.accountId, row.deviceId, checkNotNull(row.originalOriginSha256), row.originalEnrolledPoint, host.epoch, host.lineVersion,
            TypedSubmit03Record.base(TypedHistory03Wire.request(host.epoch, query)))
        val history = journal.typedHistory03()
        check(history.reserveClock(row, candidate, action::requireCurrent))
        val entry = history.enterClock(candidate, action::requireCurrent) ?: error("Proof clock changed")
        val entered = checkNotNull(history.clock(id))
        val sample = host.request(row, entry, action::requireCurrent)
        check(history.retainClockReply(entered, sample.bytes()))
        val retained = checkNotNull(history.clock(id)); sample.nowFor(row, retained); action.requireCurrent()
        return sample to retained
    }
    private fun closed(row: TypedSubmit03Record): TypedNoSubmit03Record {
        row.requireShape(); require(row.phase == "closed_no_submit" && !row.conflict && row.lastCallbackOrdinal == 0L)
        check(journal.typedSubmits03().get(row.attemptId) == row && journal.typedSubmits03().callbacks(row.attemptId).isEmpty())
        return TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
    }
    private fun complete() = Result(true, "Saved cancellation confirmed. This report does not retry or send a message.")
    private fun pending() = Result(false, "Cancellation remains saved and unconfirmed. No message is retried.")
    private fun id() = UUID.randomUUID().toString()
}
