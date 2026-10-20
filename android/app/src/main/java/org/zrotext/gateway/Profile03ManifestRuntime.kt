// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject

/** Actual additive history/readback socket orchestration. Only nonce-matched reads on this
 * full leased connection enter the original verifier. Stored readback rows never recreate a
 * live handle, and reader availability remains separate from physical/content permission. */
internal class Profile03ManifestRuntime(private val db: SmsJournalDatabase, private val originals: Profile03ManifestOriginalReader,
    private val store: Profile03ManifestStore, private val time: Profile03SessionTime, private val current: () -> Boolean,
    private val enrollmentPoint: () -> ByteArray, private val send: (String) -> Boolean,
    private val withdrawEffects: () -> Unit, private val status: (String) -> Unit,
    private val selected: (ByteArray, UUID) -> Unit,
    private val elapsedRealtime: () -> Long = SystemClock::elapsedRealtime) : AutoCloseable {
    private enum class Kind { ORIGINAL, HISTORY, READBACK, CURRENT }
    private data class Tip(val version: Long, val digest: String, val ancestry: String)
    private class Pending(val kind: Kind, val challenge: UUID, val line: UUID, val started: Long,
        val session: SealedDispatchExecutor.Session, val after: Profile03ManifestChain.Saved?, val tip: Tip?)
    class Installed internal constructor(val saved: Profile03ManifestChain.Saved, val session: SealedDispatchExecutor.Session,
        private val epoch: AtomicLong, private val captured: Long, private val current: () -> Unit) {
        fun requireRamCurrent() { check(epoch.get() == captured); current(); check(epoch.get() == captured) }
        override fun toString() = "Manifest03Installed(actual-lease-readback)"
    }
    private val lock = Any()
    private val epoch = AtomicLong(0)
    private val chain = Profile03ManifestChain(store)
    @Volatile private var closed = false
    @Volatile private var installed: Installed? = null
    private var saved: Profile03ManifestChain.Saved? = null
    private var restore: Profile03ManifestChain.Restoration? = null
    private var evidence: Map<String, Any>? = null
    private var binding: UUID? = null
    private var fixedTip: Tip? = null
    private var historyChecked = false
    private var pending: Pending? = null
    private var lastRequest = -1L
    private var requests = 0
    @Volatile private var paused = false
    private fun session() = checkNotNull(time.snapshot()).first.session.also { check(!closed && current()) }
    private fun now(expected: SealedDispatchExecutor.Session) = checkNotNull(time.nowMs()).also {
        check(!closed && current() && time.snapshot()?.first?.session === expected && it > 0)
    }
    private fun withdraw() {
        epoch.incrementAndGet(); installed = null
        withdrawEffects() // RAM-only withdrawal BEFORE a worker, database or key can block.
    }
    /** Explicit snapshot restart; it preserves all originals, budgets, cursor/highwater and history. */
    fun checkSetup() {
        JournalRuntime.io.execute { synchronized(lock) {
            check(!closed && current()); paused = false; pending = null; fixedTip = null; evidence = null
            saved = null; restore = null; binding = null; historyChecked = false
            requestIfDue()
        } }
    }
    fun requestIfDue() = synchronized(lock) {
        if (closed || !current() || paused || restore != null || time.snapshot() == null) return@synchronized
        val elapsed = elapsedRealtime()
        pending?.let {
            if (elapsed - it.started !in 0..2_000) {
                pending = null; paused = true
                withdraw()
                status("Setup read interrupted. Check messaging setup to resume from saved history.")
            }
            return@synchronized
        }
        if (lastRequest >= 0 && elapsed - lastRequest < 25_000) return@synchronized
        if (requests >= 64) { paused = true; withdraw(); status("Setup read budget reached. Reconnect explicitly to continue saved history."); return@synchronized }
        val line = db.attempts().currentLineBinding() ?: return@synchronized
        if (line.protocolVersion != 2 || line.v2Purpose != "sealed") return@synchronized
        val retained = db.profile03Elections().installed(line.accountId, line.lineId)
            ?: db.profile03Elections().signedOpening(line.accountId, line.lineId) ?: return@synchronized
        val active = session(); now(active)
        check(line.accountId == active.accountId.toString() && line.deviceId == active.deviceId.toString() && retained.originHash == active.originHash)
        val local = saved
        val kind = when {
            local == null -> Kind.ORIGINAL
            !historyChecked || local.head == null || local.head.state == "progress" -> Kind.HISTORY
            installed == null -> Kind.READBACK
            else -> Kind.CURRENT
        }
        val challenge = UUID.randomUUID(); val lineId = UUID.fromString(line.lineId)
        val frame = JSONObject().put("v", 1).put("connection_epoch", active.connectionEpoch).put("challenge", challenge).put("line_id", lineId)
        when (kind) {
            Kind.ORIGINAL -> frame.put("type", "payload_profile_manifest_original03_request")
            Kind.HISTORY -> {
                val after = checkNotNull(local).checkpoint
                frame.put("type", "payload_profile_manifest03_request").put("after_version", after.authority.version.toString())
                    .put("after_digest", b64(after.authority.digest)).put("after_ancestry_sha256", b64(after.ancestry()))
                    .put("tip_version", fixedTip?.version?.toString() ?: JSONObject.NULL)
                    .put("tip_digest", fixedTip?.digest ?: JSONObject.NULL).put("tip_ancestry_sha256", fixedTip?.ancestry ?: JSONObject.NULL)
            }
            Kind.READBACK -> {
                val h = checkNotNull(local?.head)
                frame.put("type", "payload_profile_manifest03_installed").put("tip_version", h.version.toString())
                    .put("tip_digest", b64(unhex(h.digest))).put("tip_ancestry_sha256", b64(unhex(h.ancestry)))
                    .put("election_digest", b64(Profile03ElectionEncoding.decode(retained.coreB64url, 500).let {
                        sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/commitment/v1", it)) }))
            }
            Kind.CURRENT -> frame.put("type", "payload_profile_manifest_current03_request")
        }
        pending = Pending(kind, challenge, lineId, elapsed, active, local, fixedTip)
        lastRequest = elapsed; requests++
        check(send(frame.toString()))
    }
    /** Called synchronously at raw authenticated delivery entry, before queuing any key work. */
    fun accept(raw: ByteArray) {
        val f = Profile03ManifestJson.objectValue(raw)
        val type = Profile03Json.text(f, "type")
        if (type in setOf("payload_profile_manifest03", "payload_profile_manifest_current03")) {
            val h = Profile03Json.nested(f, if (type == "payload_profile_manifest03") "history" else "current")
            val active = installed
            val head = active?.saved?.head
            val versionField = if (type == "payload_profile_manifest03") "tip_version" else "manifest_version"
            val digestField = if (type == "payload_profile_manifest03") "tip_digest" else "manifest_digest"
            val prefixField = if (type == "payload_profile_manifest03") "tip_ancestry_sha256" else "manifest_ancestry_sha256"
            val sameTip = head != null && Profile03Json.decimal(h, versionField) == head.version &&
                same(Profile03Json.binary(h, digestField, 32, 32), unhex(head.digest)) &&
                same(Profile03Json.binary(h, prefixField, 32, 32), unhex(head.ancestry))
            if (!sameTip) withdraw()
        }
        JournalRuntime.io.execute { runCatching { synchronized(lock) { consume(f, type) } }.onFailure {
            withdraw(); paused = true; status("Messaging setup paused. Original proofs and progress remain saved.")
        } }
    }
    private fun consume(f: Map<String, Any>, type: String) {
        val p = checkNotNull(pending)
        val expected = when (p.kind) {
            Kind.ORIGINAL -> "payload_profile_manifest_original03"
            Kind.HISTORY -> "payload_profile_manifest03"
            Kind.READBACK -> "payload_profile_manifest03_installed_ack"
            Kind.CURRENT -> "payload_profile_manifest_current03"
        }
        require(type == expected && f["v"] == Profile03Json.Integer(1) && f["connection_epoch"] == Profile03Json.Integer(p.session.connectionEpoch) &&
            f["challenge"] == p.challenge.toString() && elapsedRealtime() - p.started in 0..2_000)
        now(p.session); pending = null
        when (p.kind) {
            Kind.ORIGINAL -> {
                require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "line_id", "binding_id", "evidence") && f["line_id"] == p.line.toString())
                val selectedBinding = UUID.fromString(Profile03ClosedUnaccepted.uuid(Profile03Json.text(f, "binding_id")))
                val originalEvidence = Profile03Json.nested(f, "evidence")
                val original = originals.read(originalEvidence, p.line, selectedBinding, p.session)
                evidence = originalEvidence; binding = selectedBinding
                restore = chain.begin(original) { now(p.session) }
                status("Checking saved manifest history. Pairing and original approvals are retained.")
                restoreChunk(p.session)
            }
            Kind.HISTORY -> {
                require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "history"))
                val page = Profile03ManifestHistory.decode(Profile03Json.nested(f, "history"))
                val prior = checkNotNull(p.after)
                val original = originals.read(page.evidence(), p.line, checkNotNull(binding), p.session)
                require(original.identity == prior.original.identity)
                val tip = Tip(page.tipVersion, b64(page.tipDigest), b64(page.tipAncestry))
                p.tip?.let { require(it == tip) }; fixedTip = tip
                val after = page.verify(prior.checkpoint, original.scope, now(p.session))
                val existing = installed
                if (existing?.saved?.head?.let { it.version == page.tipVersion && it.digest == hex(page.tipDigest) && it.ancestry == hex(page.tipAncestry) } == true) {
                    require(page.complete && page.entries().isEmpty() && same(after.authority.signedBytes, existing.saved.checkpoint.authority.signedBytes))
                    existing.requireRamCurrent(); saved = existing.saved
                } else {
                    withdraw()
                    val captured = epoch.get()
                    saved = chain.append(prior, page, { now(p.session) }) { check(epoch.get() == captured); now(p.session) }
                }
                historyChecked = page.complete
                status(if (page.complete) "Manifest history verified. Waiting for exact phone-session readback." else "Manifest progress saved. Continuing the same verified snapshot.")
            }
            Kind.READBACK -> {
                require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "line_id", "tip_version", "tip_digest", "tip_ancestry_sha256", "election_digest", "compared_ms") &&
                    f["line_id"] == p.line.toString())
                val prior = checkNotNull(p.after); val head = checkNotNull(prior.head)
                require(head.state != "progress" && Profile03Json.decimal(f, "tip_version") == head.version &&
                    hex(Profile03Json.binary(f, "tip_digest", 32, 32)) == head.digest &&
                    hex(Profile03Json.binary(f, "tip_ancestry_sha256", 32, 32)) == head.ancestry)
                val original = originals.read(checkNotNull(evidence), p.line, checkNotNull(binding), p.session)
                require(original.identity == prior.original.identity)
                val retained = checkNotNull(db.profile03Elections().find(original.electionId))
                require(same(Profile03Json.binary(f, "election_digest", 32, 32), sha(ReviewedIntent03.framed(
                    "ZTSE/line/payload-profile/commitment/v1", Profile03ElectionEncoding.decode(retained.coreB64url, 500)))))
                val compared = Profile03Json.decimal(f, "compared_ms"); require(compared in head.comparedMs..now(p.session))
                val point = enrollmentPoint(); now(p.session)
                val identity = checkNotNull(time.snapshot()).first
                val receipt = Profile03ManifestReadback(p.challenge.toString(), head.electionId, head.version, head.digest,
                    head.ancestry, hex(identity.deviceSessionDigest(point)), compared)
                val next = store.installed(head); val captured = epoch.get()
                fun ram() { check(epoch.get() == captured); now(p.session) }
                store.dao().readback(head, next, receipt, ::ram)
                ram()
                require(originals.read(checkNotNull(evidence), p.line, checkNotNull(binding), p.session).identity == original.identity)
                ram(); check(store.dao().head(head.electionId)?.same(next) == true); ram()
                val complete = Profile03ManifestChain.Saved(prior.original, next, prior.checkpoint)
                saved = complete
                installed = Installed(complete, p.session, epoch, captured) { now(p.session); check(checkNotNull(time.nowMs()) >= compared) }
                status("Current manifest acknowledged. Review this phone's SIM if its physical approval is paused.")
            }
            Kind.CURRENT -> {
                require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "current"))
                checkNotNull(installed).requireRamCurrent()
                selected(Profile03ManifestJson.render(Profile03Json.nested(f, "current")), p.line)
            }
        }
        requestIfDue()
    }
    private fun restoreChunk(active: SealedDispatchExecutor.Session) {
        val progress = checkNotNull(restore)
        val result = chain.advance(progress) { now(active) }
        if (result != null) { saved = result; restore = null; requestIfDue() }
        else JournalRuntime.io.execute { runCatching { synchronized(lock) {
            check(restore === progress); restoreChunk(active)
        } }.onFailure { withdraw(); paused = true; status("Saved manifest history could not be verified. No current permission was restored.") } }
    }
    fun currentInstalled(): Installed = checkNotNull(installed).also { it.requireRamCurrent() }
    /** A genuine physical installation only resumes bounded current reads; it is not Ready. */
    fun physicalReady() = synchronized(lock) {
        checkNotNull(installed).requireRamCurrent()
        paused = false
        if (pending?.kind == Kind.CURRENT) pending = null
        requestIfDue()
    }
    override fun close() { closed = true; withdraw(); synchronized(lock) { pending = null; restore = null; saved = null; evidence = null; store.close() } }
    override fun toString() = "Profile03ManifestRuntime(redacted)"
    companion object {
        private fun b64(b: ByteArray) = Profile03ElectionEncoding.encode(b)
        private fun hex(b: ByteArray) = Draft02OutboundPreparation.hex(b)
        private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    }
}
