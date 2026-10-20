// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/** Shipping consent is separate from Ready03. Only the same original live foreground ceremony,
 * existing role04 hardware, durable one-use phases and a matching actual install ACK issue a
 * RAM handle. Cold journals/status/signatures are retained recovery evidence, never handles.
 */
internal class ConversationInterval03Runtime(private val owner: Any, private val originDigest: ByteArray,
    private val store: ConversationInterval03Store, private val signer: ConversationInterval03ProofSigner,
    private val time: Profile03SessionTime,
    private val current: () -> Boolean, private val selection: (ByteArray, UUID) -> Profile03CurrentReader.Selection,
    private val send: (String) -> Boolean) : AutoCloseable {
    private class Work(val shown: ConversationInterval03Mount.Review, val permission: ConversationInterval03Permission,
        val projection: ByteArray, val selected: Profile03CurrentReader.Selection,
        val session: SealedDispatchExecutor.Session) {
        @Volatile var stopped = false
        var foreground: ConversationInterval03Foreground.Decision? = null
        @Volatile var dao: ConversationInterval03Dao? = null
        @Volatile var row: ConversationInterval03Record? = null
        @Volatile var proof: ConversationInterval03Proof? = null
        @Volatile var active = false
        var pendingStatus: Pair<UUID, Long>? = null
    }
    @Volatile private var closed = false
    private val lock = Any()
    private val works = java.util.concurrent.ConcurrentHashMap<UUID, Work>()
    private var lastStatus = -1L
    private var statusCount = 0
    private fun now() = checkNotNull(time.nowMs()).also { check(!closed && current()) }
    private fun ram(w: Work, setup: Boolean = true, foreground: Boolean = true,
        decision: ConversationInterval03Foreground.Decision? = w.foreground) {
        check(!closed && current() && !w.stopped && time.snapshot()?.first?.session === w.session && w.selected.physical.isCurrent())
        w.selected.authorityCurrent()
        val instant = now(); w.permission.statement.requireIntervalCurrent(instant)
        check(instant < w.selected.selected.permissionExpiresAtMs)
        if (setup) { check((!foreground || decision?.isCurrent() == true) && instant < w.permission.permissionExpiresMs)
            w.permission.statement.requireSetupCurrent(instant) }
    }
    /** Room/framework/Keystore access is outside the interval writer and hardware callbacks. */
    private fun verify(w: Work, setup: Boolean = true, foreground: Boolean = true,
        decision: ConversationInterval03Foreground.Decision? = w.foreground): Draft03ManifestAuthority.IntervalKeys {
        ram(w, setup, foreground, decision)
        val selected = selection(w.projection, w.permission.statement.line)
        val roles = w.permission.verifyCurrent(selected, signer.readerPoint(), originDigest, now())
        check(same(roles.phonePoint(), signer.phonePoint()))
        ram(w, setup, foreground, decision)
        return roles
    }
    fun challenge(raw: ByteArray) = synchronized(lock) {
        check(!closed && current())
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "interval_id", "statement", "owner_signature", "current", "interval_permission") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "conversation_interval_challenge03")
        val p = ConversationInterval03Permission.decode(Profile03Json.nested(f, "interval_permission"))
        p.requireRequest("interval_challenge", p.statement.receipt)
        require(p.phase == "requested" && f["interval_id"] == p.statement.interval.toString() &&
            same(Profile03Json.binary(f, "statement", 695, 1092), p.statement.bytes()) &&
            same(Profile03Json.binary(f, "owner_signature", 64, 64), checkNotNull(p.ownerSignature())))
        val bytes = Profile03Json.render(Profile03Json.nested(f, "current"))
        val selected = selection(bytes, p.statement.line)
        p.verifyCurrent(selected, signer.readerPoint(), originDigest, now())
        val existing = works[p.statement.interval]
        if (existing != null) {
            require(same(existing.permission.statement.bytes(), p.statement.bytes()) &&
                same(checkNotNull(existing.permission.ownerSignature()), checkNotNull(p.ownerSignature())))
            return@synchronized // No passive retry, new phone decision or signature on delivery replay.
        }
        val instant = now()
        // Bound the active/recovery RAM working set, not durable lifetime history. Removing a
        // terminal/actually interval-expired display never reconstructs or releases its row.
        works.entries.removeIf { (_, prior) ->
            if (prior.stopped || instant >= prior.permission.statement.intervalExpiresMs) {
                prior.stopped = true; prior.active = false; true
            } else false
        }
        check(works.size < 64)
        val s = p.statement
        val shown = ConversationInterval03Mount.Review.from(s)
        val w = Work(shown, p, bytes, selected, checkNotNull(time.snapshot()).first.session)
        works[s.interval] = w
        ConversationInterval03Mount.publish(owner, shown, "Review the conversation and encrypted-content disclosure before approving")
    }
    fun approve(shown: ConversationInterval03Mount.Review, foreground: ConversationInterval03Foreground.Decision) = synchronized(lock) {
        val w = checkNotNull(works[shown.interval]); check(w.shown === shown && (w.row == null || w.row?.state == "approved"))
        w.foreground = foreground
        if (w.row?.state == "approved") {
            // A genuinely new affirmative foreground action may continue an UNUSED install
            // phase after its already observed original approval ACK. A burned reservation
            // or an unknown signing result is never entered again.
            installOnce(w)
            return@synchronized
        }
        val roles = verify(w)
        val p = w.permission
        val proof = ConversationInterval03Proof(p.statement, checkNotNull(p.ownerSignature()), checkNotNull(p.requestedMs))
        val dao = store.openForDecision()
        val reserved = store.record(proof, "approval_reserved")
        verify(w)
        val persisted = dao.reserve(reserved, now()) { ram(w) }
        w.dao = dao; w.row = persisted; w.proof = proof // Burn before hardware; loss is UNKNOWN, never a reason to regenerate.
        val signature = signer.approval(proof.statement, proof.ownerSignature(), roles.phonePoint()) { ram(w) }
        verify(w)
        advance(w, proof.withPhone(signature), "approval_signed")
        sendProof(w, "conversation_interval_approve03", checkNotNull(w.proof?.phoneSignature()))
        ConversationInterval03Mount.update(owner, shown, "Phone approval saved. Waiting for the service acknowledgement")
    }
    private fun advance(w: Work, proof: ConversationInterval03Proof, state: String, foreground: Boolean = true) {
        val before = checkNotNull(w.row); val next = store.record(proof, state, before.reservedMs)
        checkNotNull(w.dao).advance(before, next) { ram(w, foreground = foreground) }
        w.row = next; w.proof = proof
    }
    private fun sendProof(w: Work, type: String, signature: ByteArray,
        decision: ConversationInterval03Foreground.Decision? = w.foreground) {
        ram(w, decision = decision)
        check(send(JSONObject().put("v", 1).put("type", type).put("interval_id", w.shown.interval)
            .put("statement_sha256", b64(w.permission.statement.sha256())).put("signature", b64(signature)).toString()))
    }
    fun approved(raw: ByteArray) = synchronized(lock) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "interval_id", "statement_sha256", "approved_ms"))
        val w = correlated(f, "conversation_interval_approved03")
        val at = Profile03Json.decimal(f, "approved_ms"); val proof = checkNotNull(w.proof)
        if (w.row?.state != "approval_signed") { require(proof.approvedMs == at); return@synchronized }
        verify(w, foreground = false); require(at >= proof.requestedMs && at <= now())
        advance(w, proof.approved(at), "approved", foreground = false)
        if (w.foreground?.isCurrent() == true) installOnce(w)
        else ConversationInterval03Mount.update(owner, w.shown, "Original approval acknowledged. Review and approve again in the foreground to continue the unused installation phase")
    }
    private fun installOnce(w: Work) {
        check(w.row?.state == "approved")
        verify(w)
        advance(w, checkNotNull(w.proof), "install_reserved")
        val roles = verify(w); val accepted = checkNotNull(w.proof)
        val signature = signer.installed(accepted.statement, accepted.ownerSignature(),
            checkNotNull(accepted.phoneSignature()), roles.phonePoint()) { ram(w) }
        verify(w)
        advance(w, accepted.withInstalled(signature), "install_signed")
        sendProof(w, "conversation_interval_install03", signature)
        ConversationInterval03Mount.update(owner, w.shown, "Installation saved. Waiting for the original matching acknowledgement")
    }
    fun installed(raw: ByteArray) = synchronized(lock) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "interval_id", "statement_sha256", "installed_ms", "device_session_digest"))
        val w = correlated(f, "conversation_interval_installed03")
        require(same(Profile03Json.binary(f, "device_session_digest", 32, 32), w.permission.statement.deviceSessionDigest))
        val at = Profile03Json.decimal(f, "installed_ms"); val proof = checkNotNull(w.proof)
        if (w.active) { require(proof.installedMs == at); ram(w, false); return@synchronized }
        check(w.row?.state == "install_signed"); verify(w, foreground = false)
        require(at >= checkNotNull(proof.approvedMs) && at <= now())
        advance(w, proof.installed(at), "active", foreground = false); w.active = true
        ConversationInterval03Mount.update(owner, w.shown, "Conversation approved. Every message still checks current service and phone permission")
    }
    private fun correlated(f: Map<String, Any>, type: String): Work {
        require(f["v"] == Profile03Json.Integer(1) && f["type"] == type)
        val id = UUID.fromString(Profile03ClosedUnaccepted.uuid(Profile03Json.text(f, "interval_id")))
        return checkNotNull(works[id]).also { w -> check(!closed && current() && !w.stopped &&
            time.snapshot()?.first?.session === w.session)
            require(same(Profile03Json.binary(f, "statement_sha256", 32, 32), w.permission.statement.sha256())) }
    }
    /** User initiated exact retained retry only; a reserved/lost hardware result cannot be retried. */
    fun retry(shown: ConversationInterval03Mount.Review, foreground: ConversationInterval03Foreground.Decision) = synchronized(lock) {
        val w = checkNotNull(works[shown.interval]); check(w.shown === shown)
        // Retransmission does not renew the affirmative decision for any unused hardware phase.
        verify(w, decision = foreground)
        val proof = checkNotNull(w.proof)
        check(checkNotNull(w.dao).find(shown.interval.toString())?.same(checkNotNull(w.row)) == true)
        when (w.row?.state) {
            "approval_signed" -> sendProof(w, "conversation_interval_approve03", checkNotNull(proof.phoneSignature()), foreground)
            "install_signed" -> sendProof(w, "conversation_interval_install03", checkNotNull(proof.installedSignature()), foreground)
            else -> error("Original signature outcome cannot be retried")
        }
    }
    fun requestStatus(shown: ConversationInterval03Mount.Review) = synchronized(lock) {
        val w = checkNotNull(works[shown.interval]); check(w.shown === shown && !closed && current() && !w.stopped &&
            time.snapshot()?.first?.session === w.session)
        val instant = now(); val elapsed = SystemClock.elapsedRealtime()
        w.permission.statement.requireIntervalCurrent(instant)
        if (!w.active) w.permission.statement.requireSetupCurrent(instant)
        check(w.pendingStatus == null && statusCount < 64 && (lastStatus < 0 || elapsed - lastStatus >= 25_000))
        val challenge = UUID.randomUUID(); w.pendingStatus = challenge to elapsed; lastStatus = elapsed; statusCount++
        check(send(JSONObject().put("v", 1).put("type", "conversation_interval_status03_request")
            .put("interval_id", shown.interval).put("challenge", challenge).toString()))
    }
    fun status(raw: ByteArray) = synchronized(lock) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "interval_id", "challenge", "statement_sha256", "phase",
            "approved_ms", "installed_ms", "device_session_digest", "interval_permission"))
        val w = correlated(f, "conversation_interval_status03")
        val waiting = checkNotNull(w.pendingStatus); w.pendingStatus = null
        require(f["challenge"] == waiting.first.toString() && SystemClock.elapsedRealtime() - waiting.second in 0..2_000)
        val p = ConversationInterval03Permission.decode(Profile03Json.nested(f, "interval_permission"))
        p.requireRequest("interval_status", waiting.first)
        fun nullableTime(name: String) = if (f[name] === Profile03Json.Null) null else Profile03Json.decimal(f, name)
        require(same(p.statement.bytes(), w.permission.statement.bytes()) && f["phase"] == p.phase &&
            nullableTime("approved_ms") == p.approvedMs && nullableTime("installed_ms") == p.installedMs &&
            same(Profile03Json.binary(f, "device_session_digest", 32, 32), p.statement.deviceSessionDigest))
        w.proof?.let { proof ->
            p.ownerSignature()?.let { require(same(it, proof.ownerSignature()) && p.requestedMs == proof.requestedMs) }
            p.phoneSignature()?.let { require(same(it, checkNotNull(proof.phoneSignature()))) }
            p.installedSignature()?.let { require(same(it, checkNotNull(proof.installedSignature()))) }
            proof.approvedMs?.let { require(it == p.approvedMs) }; proof.installedMs?.let { require(it == p.installedMs) }
            Unit
        } ?: require(p.phoneSignature() == null && p.installedSignature() == null &&
            same(checkNotNull(p.ownerSignature()), checkNotNull(w.permission.ownerSignature())))
        if (p.phase in setOf("stopped", "expired")) {
            w.stopped = true; w.active = false; w.dao?.stop(w.shown.interval.toString())
            ConversationInterval03Mount.update(owner, w.shown, "Conversation access stopped. Original records are retained")
        } else {
            p.verifyCurrent(selection(w.projection, p.statement.line), signer.readerPoint(), originDigest, now())
            // Even downloaded original active proofs cannot reconstruct a cold or pending handle.
            ConversationInterval03Mount.update(owner, w.shown, if (w.active) "Conversation remains approved; every message checks current permission"
                else "Original status checked. Use Retry to request the matching acknowledgement without creating a new signature")
        }
    }
    fun stopped(raw: ByteArray) = synchronized(lock) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "interval_id", "statement_sha256", "stopped_ms", "device_session_digest") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "conversation_interval_stopped03")
        val id = UUID.fromString(Profile03ClosedUnaccepted.uuid(Profile03Json.text(f, "interval_id")))
        val w = checkNotNull(works[id]); check(!closed && current() && w.stopped && time.snapshot()?.first?.session === w.session)
        require(same(Profile03Json.binary(f, "statement_sha256", 32, 32), w.permission.statement.sha256()) &&
            same(Profile03Json.binary(f, "device_session_digest", 32, 32), w.permission.statement.deviceSessionDigest) &&
            Profile03Json.decimal(f, "stopped_ms") in w.permission.statement.issuedMs..now())
        check(w.row == null || checkNotNull(w.dao).find(id.toString())?.state == "stopped")
        ConversationInterval03Mount.update(owner, w.shown, "The service acknowledged Stop. Retained encrypted content is deleted separately")
    }
    /** Withdrawal happens before acquiring the worker lock or waiting for Room/socket. */
    fun stop(shown: ConversationInterval03Mount.Review) {
        val w = checkNotNull(works[shown.interval]).also { check(it.shown === shown); it.stopped = true }
        JournalRuntime.io.execute { synchronized(lock) {
            w.dao?.stop(shown.interval.toString()); w.active = false
            ConversationInterval03Mount.update(owner, shown, "Stopped on this phone. Original encrypted content and approval history are retained")
            if (!closed && current()) check(send(JSONObject().put("v", 1).put("type", "conversation_interval_stop03")
                .put("interval_id", shown.interval).put("statement_sha256", b64(w.permission.statement.sha256())).toString()))
        } }
    }
    /** A manifest writer withdraws every old content lifetime at entry, before Room/key waits.
     * Original phase/proof history remains exact; this does not claim remote Stop or deletion. */
    fun withdrawAuthority() {
        works.values.forEach { it.stopped = true; it.active = false }
    }
    /** Actual device-signed fetch source invokes this for every full preparation/effect recheck. */
    fun requireFetch(packet: Profile03FetchPacket, grant: SealedDispatch03Frames.Grant,
        selected: Profile03CurrentReader.Selection): () -> Unit {
        val p = packet.intervalPermission(); p.requireRequest("fetch", grant.attemptId)
        val w = checkNotNull(works[p.statement.interval]); check(w.active && w.row?.state == "active")
        ram(w, false)
        val proof = checkNotNull(w.proof)
        require(same(p.statement.bytes(), proof.statement.bytes()) && same(checkNotNull(p.ownerSignature()), proof.ownerSignature()) &&
            same(checkNotNull(p.phoneSignature()), checkNotNull(proof.phoneSignature())) &&
            same(checkNotNull(p.installedSignature()), checkNotNull(proof.installedSignature())) &&
            p.requestedMs == proof.requestedMs && p.approvedMs == proof.approvedMs && p.installedMs == proof.installedMs)
        require(packet.acceptedMs in checkNotNull(proof.installedMs)..now())
        p.verifyCurrent(selected, signer.readerPoint(), originDigest, now())
        val intent = ReviewedIntent03.decode(packet.intent()); val s = proof.statement
        require(intent.intervalId == s.interval && intent.ownerUserId == s.ownerUser && intent.ownerSessionId == s.ownerSession &&
            intent.signerKeyId.contentEquals(s.browserSignerKeyId) && intent.peer().toString(Charsets.US_ASCII) == s.peer &&
            packet.intervalStartsMs == s.intervalStartsMs && packet.intervalExpiresMs == s.intervalExpiresMs &&
            grant.expiresAtMs <= p.permissionExpiresMs)
        val expected = (listOf(Draft03ManifestAuthority.Reader(1, s.readerKeyId), Draft03ManifestAuthority.Reader(2, s.archiveReaderKeyId)) +
            s.integrations().map { Draft03ManifestAuthority.Reader(3, it.keyId()) }).sortedBy { it.role.toString() + hex(it.keyId) }
        val actual = intent.request().readers()
        require(actual.size == expected.size && actual.zip(expected).all { (a, b) -> a.role == b.role && same(a.keyId, b.keyId) })
        val installedRow = checkNotNull(w.row)
        check(checkNotNull(w.dao).find(s.interval.toString())?.same(installedRow) == true)
        ram(w, false)
        // No mutation lock, Room, framework, key lookup or JSON work under hardware custody.
        // Interval end was independently bounded by every selected manifest/key lifetime.
        val deadline = minOf(grant.expiresAtMs, p.permissionExpiresMs, s.intervalExpiresMs,
            selected.selected.permissionExpiresAtMs)
        return { check(w.active && w.row === installedRow); ram(w, false); check(now() < deadline) }
    }
    override fun close() { closed = true; synchronized(lock) { works.values.forEach { it.stopped = true }; works.clear(); store.close() } }
    override fun toString() = "ConversationInterval03Runtime(redacted)"
    companion object {
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
