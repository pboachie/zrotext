// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/** An installed refresh is an opaque RAM lease plus a separately verified immutable journal row.
 * Downloaded receipts and a cold journal cannot construct this handle.
 */
internal class InstalledSelectionRefresh03 private constructor(val record: SelectionRefresh03Record,
    val bundle: SelectionRefresh03.Bundle, private val lease: SelectedLineLeaseV2, private val current: () -> Boolean) {
    fun isCurrent() = lease.isCurrent() && runCatching(current).getOrDefault(false) && lease.isCurrent()
    internal fun requireProjection(f: Map<String, Any>, selectionEpoch: Long, deviceSession: ByteArray,
        database: SmsJournalDatabase) {
        require(f.keys == setOf("kind", "refresh_id", "bundle", "accepted_ms", "installed_ms") &&
            f["kind"] == "owner_refresh03" && f["refresh_id"] == record.refreshId &&
            MessageDigest.isEqual(Profile03Json.binary(f, "bundle", 745, 745), bundle.bytes()) &&
            Profile03Json.decimal(f, "accepted_ms") == record.acceptedMs &&
            Profile03Json.decimal(f, "installed_ms") == record.installedMs)
        requireContext(selectionEpoch, deviceSession, database)
    }
    internal fun requireContext(selectionEpoch: Long, deviceSession: ByteArray, database: SmsJournalDatabase) {
        check(isCurrent() && record.state == "installed" && bundle.core.selectionEpoch == selectionEpoch &&
            MessageDigest.isEqual(bundle.core.deviceSessionDigest, deviceSession) &&
            database.selectionRefreshes03().find(record.refreshId) == record && isCurrent())
    }
    override fun toString() = "InstalledSelectionRefresh03(opaque-current-issuer)"
    companion object {
        internal fun issue(record: SelectionRefresh03Record, bundle: SelectionRefresh03.Bundle, lease: SelectedLineLeaseV2,
            current: () -> Boolean): InstalledSelectionRefresh03 {
            record.requireShape(); require(record.state == "installed" && record.bundleSha256 == hex(bundle.sha256()) &&
                record.coreB64url == Profile03ElectionEncoding.encode(bundle.core.bytes()) &&
                record.observationB64url == Profile03ElectionEncoding.encode(bundle.observation()) &&
                record.deviceSignatureB64url == Profile03ElectionEncoding.encode(bundle.deviceSignature()) &&
                record.ownerSignatureB64url == Profile03ElectionEncoding.encode(bundle.ownerSignature()) &&
                MessageDigest.isEqual(bundle.observation(), lease.observation().bytes()) &&
                lease.selected.subscriptionId == record.selectedSubscription)
            check(current() && lease.isCurrent()); return InstalledSelectionRefresh03(record, bundle, lease, current)
        }
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    }
}

/** Actual03 socket consumer. Explicit phone consent, original full public proofs, current existing
 * hardware and a held complete-observation issuer are all required before a reserved signature.
 * Nothing here opens an owner challenge, supplies MFA, re-signs after a crash or resets history.
 */
internal class SelectionRefresh03Runtime(private val origins: Profile03Origins, private val database: SmsJournalDatabase,
    private val trust: Draft02TrustStore, private val readers: () -> DevicePayloadKeyStore,
    private val signer: DeviceSigningKeyStore, private val clock: Profile03SessionTime,
    private val socketCurrent: () -> Boolean, private val send: (String) -> Boolean,
    private val currentManifest: ((Map<String, Any>, Profile03RetainedElection.Verified, SelectionRefresh03.Core) -> Profile03ManifestResolver.Authority)? = null,
    private val installed: () -> Unit,
) : AutoCloseable {
    private val origin = origins.protocolOrigin
    private class Work(val decision: SamePhoneSelectionReview.Pending, val core: SelectionRefresh03.Core,
        val evidence: Map<String, Any>, val observation: ByteArray, var row: SelectionRefresh03Record,
        val identity: Profile03SessionTime.Identity) {
        var accepted: SelectionRefresh03.Bundle? = null
        var manifestCurrent: (() -> Unit)? = null
    }
    private class Publication(override val lease: SelectedLineLeaseV2, override val record: LineActivationV2Record,
        override val refresh03: InstalledSelectionRefresh03, private val publish: () -> Boolean,
    ) : LineActivationV2PublicationPermit {
        @Volatile private var published = false
        override fun publicationCurrent() = !published && runCatching(publish).getOrDefault(false)
        override fun installationCurrent() = refresh03.isCurrent()
        override fun publicationComplete() { published = true }
    }
    @Volatile private var closed = false
    private val lock = Any()
    private var decision: SamePhoneSelectionReview.Pending? = null
    private var challenge: ByteArray? = null
    private var work: Work? = null
    @Volatile private var activeHandle: InstalledSelectionRefresh03? = null
    private val dao get() = database.selectionRefreshes03()
    private fun session() = checkNotNull(clock.snapshot()).first.also { check(!closed && socketCurrent()); origins.requireSession(it.session) }
    private fun now(): Long = checkNotNull(clock.nowMs()).also { check(!closed && socketCurrent() && it > 0) }

    fun acceptDecision(input: SamePhoneSelectionReview.Pending) = synchronized(lock) {
        check(activeHandle == null)
        input.requireCurrent(); session()
        val previous = work
        if (previous == null) check(decision == null)
        else SelectionRefresh03Closure.requireFreshDecision(previous.row, input, now())
        decision = input
        process()
    }
    fun challenge(raw: ByteArray) = synchronized(lock) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "refresh_id", "core", "evidence", "closed_unaccepted") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "payload_profile_selection_challenge03")
        val core = SelectionRefresh03.Core.decode(Profile03Json.binary(f, "core", 496, 496))
        require(f["refresh_id"] == core.refresh.toString())
        val closures = SelectionRefresh03Closure.decode(f)
        SelectionRefresh03Closure.requireChain(core, closures, now())
        val previous = challenge
        if (previous != null && !MessageDigest.isEqual(previous, raw)) {
            check(activeHandle == null)
            val old = SelectionRefresh03.Core.decode(Profile03Json.binary(Profile03Json.objectValue(previous), "core", 496, 496))
            val closed = checkNotNull(closures.find { it.refreshId == old.refresh.toString() })
            check(closed.coreB64url == b64(old.bytes()))
            work?.let { prior ->
                check(prior.row.ownerSignatureB64url == null && prior.row.acceptedMs == null && prior.row.installedMs == null)
                check(closures.find { it.refreshId == prior.row.refreshId }?.coreB64url == prior.row.coreB64url)
            }
            // A new owner opening only queues a candidate. An expired phone decision never
            // becomes fresh consent; wait for another actual foreground complete-SIM review.
            if (decision?.confirmedMs?.let { it >= old.expiresMs } != true) decision = null
        }
        challenge = raw.copyOf()
        process()
    }
    /** Full validation outside Room. The closures handed to Room and hardware below are RAM only. */
    private fun verify(w: Work): Profile03RetainedElection.Verified {
        ram(w)
        w.decision.requireCurrent()
        val retained = w.decision.retained
        check(database.attempts().currentLineBinding() == retained.binding &&
            database.lineActivationsV2().find("sealed", retained.activation.challengeId) == retained.activation &&
            database.profile03Elections().find(retained.election.challengeId) == retained.election)
        val hardware = readers().existingPublic()
        val point = signer.existingConversationPublicPoint()
        require(same(point, retained.point()))
        val proofs = if (currentManifest == null) Profile03RetainedElection.verify(w.evidence, retained.election, retained.activation, trust,
            hardware, point, origin) { ram(w); now() }
        else Profile03RetainedElection.historical(w.evidence, retained.election, retained.activation, trust,
            hardware, point, origin) { ram(w); now() }
        val manifest = currentManifest?.invoke(w.evidence, proofs, w.core)
        if (manifest != null) {
            w.manifestCurrent?.invoke()
            if (w.manifestCurrent == null) w.manifestCurrent = manifest.ramCurrent
            manifest.ramCurrent()
        }
        val authority = manifest?.authority ?: proofs.authority
        val a = proofs.election.acceptedRecord()
        val c = w.core
        require(c.account.toString() == retained.binding.accountId && c.device.toString() == retained.binding.deviceId &&
            c.line.toString() == retained.binding.lineId && c.binding.toString() == retained.election.newBindingId &&
            c.bindingGeneration == a.newBindingGeneration && c.vaultGeneration == a.vaultGeneration &&
            c.manifestVersion == authority.version && same(c.manifestDigest, authority.digest) &&
            same(c.electionDigest, a.electionCommitment) && same(c.electionBundleSha256, a.electionBundleSha256) &&
            same(c.readerKeyId, hardware.keyId) && same(c.rootFingerprint, a.rootFingerprint) &&
            same(c.deviceSigningKeyId, Profile03RetainedElection.signingId(point)) &&
            same(c.approvalKeyId, Profile03RetainedElection.signingId(proofs.original.approvalPoint())) &&
            same(c.deviceSessionDigest, w.identity.deviceSessionDigest(point)) &&
            same(c.originDigest, sha(origin.toByteArray(Charsets.UTF_8))))
        authority.requireSelectedReader(a.deviceId, a.lineId, hardware.keyId, hardware.point, now(), c.expiresMs)
        w.decision.requireCurrent(); ram(w)
        return proofs
    }
    private fun ram(w: Work) {
        check(!closed && socketCurrent() && clock.snapshot()?.first?.session === w.identity.session)
        origins.requireSession(w.identity.session)
        w.manifestCurrent?.invoke()
        w.decision.requireRamCurrent()
        w.core.requireCurrent(now())
    }
    private fun process() {
        val pending = decision ?: return
        val fields = challenge?.let(Profile03Json::objectValue) ?: return
        pending.requireCurrent()
        val core = SelectionRefresh03.Core.decode(Profile03Json.binary(fields, "core", 496, 496))
        val previous = work
        if (previous != null) {
            if (core.refresh == previous.core.refresh) return // Exact original proof is never re-signed.
            SelectionRefresh03Closure.requireFreshDecision(previous.row, pending, now())
        }
        val closures = SelectionRefresh03Closure.decode(fields)
        val observation = pending.observation()
        val retained = pending.retained
        val identity = session()
        val row = SelectionRefresh03Record(core.refresh.toString(), core.account.toString(), core.device.toString(),
            core.line.toString(), core.binding.toString(), core.bindingGeneration, retained.activation.challengeId,
            retained.binding.generation, retained.election.challengeId, checkNotNull(retained.election.acceptedEvidenceSha256),
            hex(core.deviceSessionDigest), identity.session.connectionEpoch, identity.session.deploymentEpoch,
            origins.protocolHash, SelectionRefresh03.selectedSubscription(observation), pending.consentId.toString(),
            pending.confirmedMs, pending.expiresMs, b64(core.bytes()), b64(observation))
        val next = Work(pending, core, Profile03Json.nested(fields, "evidence"), observation, row, identity)
        verify(next)
        check(dao.reserveWithClosures(row, closures, now()) { actual -> check(actual == retained.binding); ram(next) })
        work = next // A failure after reservation is intentionally a burned, recoverable unknown.
        val signature = signer.signSelectionRefresh03(core, observation, retained.point()) { ram(next) }
        verify(next)
        val signed = row.copy(state = "signed", deviceSignatureB64url = b64(signature))
        check(dao.advance(signed, "reserved") { actual -> check(actual == retained.binding); ram(next) })
        next.row = signed
        ram(next)
        check(send(JSONObject().put("v", 1).put("type", "payload_profile_selection_proof03")
            .put("connection_epoch", identity.session.connectionEpoch).put("refresh_id", row.refreshId)
            .put("observation", row.observationB64url).put("device_signature", signed.deviceSignatureB64url).toString()))
    }
    fun approved(raw: ByteArray) = synchronized(lock) {
        val w = checkNotNull(work)
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "refresh_id", "bundle", "accepted_ms") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "payload_profile_selection_approved03" && f["refresh_id"] == w.row.refreshId)
        if (w.row.state == "installed") {
            check(activeHandle?.isCurrent() == true && dao.find(w.row.refreshId) == w.row &&
                same(Profile03Json.binary(f, "bundle", 745, 745), checkNotNull(w.accepted).bytes()) &&
                Profile03Json.decimal(f, "accepted_ms") == w.row.acceptedMs)
            session()
            sendInstalled(w, checkNotNull(w.accepted))
            return@synchronized // Exact stored ACK only, no signing or historical deadline renewal.
        }
        val original = verify(w)
        val bundle = SelectionRefresh03.Bundle.verify(Profile03Json.binary(f, "bundle", 745, 745),
            w.core.bytes(), w.observation, w.decision.retained.point(), original.original.approvalPoint())
        val acceptedMs = Profile03Json.decimal(f, "accepted_ms")
        require(acceptedMs in w.core.issuedMs..now() && acceptedMs < w.core.expiresMs &&
            b64(bundle.deviceSignature()) == w.row.deviceSignatureB64url)
        val accepted = w.row.copy(state = "accepted", ownerSignatureB64url = b64(bundle.ownerSignature()),
            bundleSha256 = hex(bundle.sha256()), acceptedMs = acceptedMs)
        if (w.row.state == "signed") {
            check(dao.advance(accepted, "signed") { ram(w) }); w.row = accepted; w.accepted = bundle
            val reserved = accepted.copy(state = "ack_reserved")
            check(dao.advance(reserved, "accepted") { ram(w) }); w.row = reserved
            val signature = signer.signSelectionRefreshInstalled03(bundle, w.identity.deviceSessionDigest(w.decision.retained.point()),
                w.decision.retained.point()) { ram(w) }
            verify(w)
            val signed = reserved.copy(state = "ack_signed", installedSignatureB64url = b64(signature))
            check(dao.advance(signed, "ack_reserved") { ram(w) }); w.row = signed
        } else {
            check(w.row.state == "ack_signed" && w.accepted?.bytes()?.let { same(it, bundle.bytes()) } == true &&
                w.row.acceptedMs == acceptedMs && dao.find(w.row.refreshId) == w.row)
        }
        ram(w)
        sendInstalled(w, bundle)
    }
    private fun sendInstalled(w: Work, bundle: SelectionRefresh03.Bundle) {
        check(send(JSONObject().put("v", 1).put("type", "payload_profile_selection_installed03")
            .put("connection_epoch", w.identity.session.connectionEpoch).put("refresh_id", w.row.refreshId)
            .put("bundle_sha256", b64(bundle.sha256())).put("device_signature", w.row.installedSignatureB64url).toString()))
    }
    fun installedAck(raw: ByteArray) = synchronized(lock) {
        val w = checkNotNull(work)
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "connection_epoch", "refresh_id", "bundle_sha256", "installed_ms") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "payload_profile_selection_install_ack03" &&
            f["connection_epoch"] == Profile03Json.Integer(w.identity.session.connectionEpoch) && f["refresh_id"] == w.row.refreshId &&
            same(Profile03Json.binary(f, "bundle_sha256", 32, 32), checkNotNull(w.accepted).sha256()))
        if (w.row.state == "installed") {
            check(activeHandle?.isCurrent() == true && dao.find(w.row.refreshId) == w.row &&
                Profile03Json.decimal(f, "installed_ms") == w.row.installedMs)
            return@synchronized // Exact acknowledged replay returns the original, without renewing its historical window.
        }
        verify(w)
        val instant = Profile03Json.decimal(f, "installed_ms")
        require(instant >= checkNotNull(w.row.acceptedMs) && instant <= now() && instant < w.core.expiresMs)
        val record = w.row.copy(state = "installed", installedMs = instant)
        check(dao.advance(record, "ack_signed") { ram(w) }); w.row = record
        val lease = w.decision.currentLease()
        val handle = InstalledSelectionRefresh03.issue(record, checkNotNull(w.accepted), lease) {
            !closed && socketCurrent() && clock.snapshot()?.first?.session === w.identity.session && lease.isCurrent()
        }
        val publication = Publication(lease, w.decision.retained.activation, handle) { runCatching { ram(w); true }.getOrDefault(false) }
        check(LineActivationV2SelectedLineMount.publishRefresh(publication)?.isCurrent() == true)
        activeHandle = handle
        installed() // Request a new current DEVICE selection. This ACK itself is never Ready/send.
    }
    override fun close() {
        closed = true // Withdraw before any blocked writer/provider/UI operation can complete.
        synchronized(lock) { decision = null; challenge = null; work = null; activeHandle = null }
    }
    override fun toString() = "SelectionRefresh03Runtime(redacted)"
    companion object {
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
