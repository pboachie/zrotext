// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.UUID
import okhttp3.OkHttpClient
import okhttp3.WebSocket
import org.json.JSONObject

internal object Profile03MessagingStatus {
    @Volatile private var owner: Any? = null
    var value by mutableStateOf("Messaging paused")
        private set
    @Synchronized fun open(candidate: Any) { owner = candidate; value = "Checking authenticated phone connection" }
    @Synchronized fun update(candidate: Any, text: String) { if (owner === candidate) value = text }
}

/** Ordinary shipping03 socket, same existing ACK/CAS/radio consumer and maintained recipient.
 * User intent to connect is separate from root/activation/election/current permission; this class
 * creates none of those prerequisites. Every absent or withdrawn authority refuses.
 */
internal class Profile03ExecutionConnection(context: Context, account: UUID, device: UUID, epoch: Long,
    streamUrl: String, client: OkHttpClient, private val socket: WebSocket,
    private val lineConsumerVersion: () -> Int?, private val socketCurrent: () -> Boolean,
) : AutoCloseable {
    private val application = checkNotNull(context.applicationContext)
    private val protectionEpoch = InboundProtectionHealth.snapshot()
    private val origins = Profile03Origins.fromStream(account, device, streamUrl)
    private val origin = origins.protocolOrigin
    private val db = SmsJournalDatabase.get(application)
    private val storage = Draft02AndroidTrustStorage(application)
    private val trust = Draft02TrustStore(storage)
    private val keys = DeviceSigningKeyStore(application)
    private val recipients by lazy {
        DevicePayloadKeyStore(application, ConversationAndroidEnrollment.readerAlias(checkNotNull(db.attempts().currentLineBinding())))
    }
    private val suppression = ConversationExistingSuppressionTokens(application)
    private val manifestStore by lazy { Profile03ManifestStore(application, ConversationExistingJournalProtection()) }
    @Volatile private var closed = false
    private val effects = Any()
    private val time = Profile03SessionTime(account, device, epoch,
        origins.routingHash, SystemClock::elapsedRealtime,
        ::current, lineConsumerVersion, socket::send)
    private val wire = ConversationSocketWire(socket, { time.snapshot()?.first?.session?.let(ConversationPhoneSession::from) })
    private val intervals: ConversationInterval03Runtime by lazy { ConversationInterval03Runtime(this,
        java.security.MessageDigest.getInstance("SHA-256").digest(origin.toByteArray(Charsets.UTF_8)),
        ConversationInterval03Store(application, ConversationExistingJournalProtection(), suppression),
        ConversationInterval03HardwareProofSigner(keys) { recipients }, time, ::current,
        { bytes, line -> reader.manifestDeviceSelection(bytes, line) }, socket::send) }
    private val manifestResolver: Profile03ManifestResolver by lazy { Profile03ManifestResolver({ manifests }, manifestStore, time) }
    private val reader: Profile03CurrentReader by lazy { Profile03CurrentReader(application, origins, db, trust, recipients, keys, time, ::current,
        { packet, grant, selected -> intervals.requireFetch(packet, grant, selected) }, manifestResolver) }
    private val manifests: Profile03ManifestRuntime by lazy { Profile03ManifestRuntime(origins, db,
        Profile03ManifestOriginal(origins, db, trust, { recipients }, keys, time, ::current), manifestStore, time, ::current,
        keys::existingConversationPublicPoint, socket::send,
        { intervals.withdrawAuthority(); projection = null },
        { text -> Profile03MessagingStatus.update(this, text) }, ::publishManifestCurrent) }
    private val setup by lazy { Profile03SetupRuntime(application, origins, db, trust, recipients, keys, time, ::current) }
    private val refresh = SelectionRefresh03Runtime(origins, db, trust, { recipients }, keys, time, ::current, socket::send,
        currentManifest = manifestResolver::refresh) {
        synchronized(effects) { check(current()); projection = null }
        Profile03MessagingStatus.update(this, "SIM approval acknowledged. Checking current messaging availability.")
        manifests.physicalReady()
    }
    private data class Pending(val challenge: UUID, val line: UUID, val started: Long)
    private var pending: Pending? = null
    private var requests = 0
    private var lastRequest = -1L
    @Volatile private var pollingStopped = false
    @Volatile private var projection: ByteArray? = null
    private val attempted = mutableSetOf<String>()
    private val fetch = SealedEnvelope03Client(streamUrl, client, { grant ->
        keys.signSealedEnvelopeFetch03(grant, keys.existingConversationPublicPoint()) { requireGrantCurrent(grant) }
    }, ::requireGrantCurrent)
    init {
        InboundProtection.restoreNegative(application)
        Profile03MessagingStatus.open(this)
        Profile03ManifestMount.attach(this, ::current) { manifests.checkSetup() }
        SelectionRefresh03Mount.attach(this, ::current) { decision ->
            synchronized(effects) { check(current()); projection = null }
            refresh.acceptDecision(decision)
            Profile03MessagingStatus.update(this, "Fresh SIM review saved. Approve this selection in your owner workspace.")
        }
        ConversationInterval03Mount.attach(this, ::current,
            { shown, foreground -> JournalRuntime.io.execute { runCatching { intervals.approve(shown, foreground) }
                .onFailure { ConversationInterval03Mount.update(this, shown, "Approval paused. Original records are retained; no new signature was requested") } } },
            { shown, foreground -> JournalRuntime.io.execute { runCatching { intervals.retry(shown, foreground) }
                .onFailure { ConversationInterval03Mount.update(this, shown, "Retry paused. Check the original setup and current connection; history is retained") } } },
            { shown -> JournalRuntime.io.execute { runCatching { intervals.requestStatus(shown) }
                .onFailure { ConversationInterval03Mount.update(this, shown, "Status unavailable. Original records remain unchanged") } } },
            { shown -> intervals.stop(shown) })
    }

    private fun current() = InboundProtectionHealth.current(protectionEpoch) && !closed && socketCurrent() &&
        lineConsumerVersion() == 2 && InboundProtectionHealth.current(protectionEpoch)
    fun start() = current() && time.request()
    fun tick(): Boolean = current() && time.request().also { available -> if (available) manifests.requestIfDue() }
    fun acceptMetadata(raw: ByteArray) {
        check(current()); time.accept(raw)
        JournalRuntime.timeouts.schedule({ JournalRuntime.io.execute { runCatching {
            synchronized(effects) {
                check(current())
                val session = checkNotNull(time.snapshot()).first.session
                Profile03BootstrapClock.publish(this, session, origins) { if (current()) time.nowMs() else null }
                if (projection == null) Profile03MessagingStatus.update(this, "Phone connected. Finish messaging setup in your owner workspace.")
            }
            manifests.requestIfDue()
        }.onFailure { close() } } }, 1, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    fun challenge(raw: ByteArray) {
        val owned = raw.copyOf()
        JournalRuntime.io.execute {
            runCatching {
                check(current())
                val proof = setup.challenge(owned)
                synchronized(effects) {
                    check(current() && socket.send(proof))
                    // Only a fully verified explicit opening can resume reads after expiry.
                    // Keep this socket's nonce, rate and total-request bounds unchanged.
                    pollingStopped = false
                }
                Profile03MessagingStatus.update(this, "Phone approval saved. Complete approval in your owner workspace.")
                manifests.requestIfDue()
            }.onFailure { close() }
        }
    }
    fun selectionRefresh(raw: ByteArray) {
        val owned = raw.copyOf()
        JournalRuntime.io.execute { runCatching {
            check(current())
            when (Profile03Json.objectValue(owned)["type"]) {
                "payload_profile_selection_challenge03" -> refresh.challenge(owned)
                "payload_profile_selection_approved03" -> refresh.approved(owned)
                "payload_profile_selection_install_ack03" -> refresh.installedAck(owned)
                else -> error("Refresh direction")
            }
        }.onFailure { close() } }
    }
    fun conversationInterval(raw: ByteArray) {
        val owned = raw.copyOf()
        JournalRuntime.io.execute { runCatching {
            check(current())
            when (Profile03Json.objectValue(owned)["type"]) {
                "conversation_interval_challenge03" -> intervals.challenge(owned)
                "conversation_interval_approved03" -> intervals.approved(owned)
                "conversation_interval_installed03" -> intervals.installed(owned)
                "conversation_interval_status03" -> intervals.status(owned)
                "conversation_interval_stopped03" -> intervals.stopped(owned)
                else -> error("Interval direction")
            }
        }.onFailure { close() } }
    }
    fun manifest(raw: ByteArray) = manifests.accept(raw)
    private fun publishManifestCurrent(bytes: ByteArray, line: UUID) {
        val value = reader.manifestDeviceSelection(bytes, line)
        val c = value.selected
        val session = checkNotNull(time.snapshot()).first.session
        val ready = SealedDispatch03Frames.ready(JSONObject().put("v", 1).put("type", "sealed_ready")
            .put("grant_version", 3).put("envelope_profile", 3).put("manifest_profile", 3)
            .put("line_id", line).put("connection_epoch", session.connectionEpoch).put("deployment_epoch", session.deploymentEpoch)
            .put("binding_generation", c.bindingGeneration).put("trust_generation", c.vaultGeneration)
            .put("manifest_version", c.manifestVersion).put("reader_key_id", b64(c.selectedReaderKeyId))
            .put("manifest_digest", b64(c.manifestDigest)).put("root_fingerprint", b64(c.rootFingerprint))
            .put("election_digest", b64(c.electionCommitment)).toString())
        value.authorityCurrent()
        synchronized(effects) { check(current()); value.authorityCurrent(); projection = bytes.copyOf(); check(socket.send(ready.json())) }
        Profile03MessagingStatus.update(this, "Messaging ready. Each message still needs current sending approval.")
    }
    /** Bounded reads only; it never opens/reserves/signs an election. */
    private fun requestCurrentIfDue() {
        if (!current() || pollingStopped || time.snapshot() == null) return
        val line = db.attempts().currentLineBinding() ?: return
        if (line.v2Purpose != "sealed" || line.installedSelectionV2()?.isCurrent() != true) return
        val installed = db.profile03Elections().installed(line.accountId, line.lineId)
        val signed = installed ?: db.profile03Elections().signedOpening(line.accountId, line.lineId) ?: return
        if (installed == null && checkNotNull(time.nowMs()) >= java.nio.ByteBuffer.wrap(
                Profile03ElectionEncoding.decode(signed.coreB64url, 500), 392, 8).long) {
            pollingStopped = true; return
        }
        synchronized(effects) {
            check(current())
            val elapsed = SystemClock.elapsedRealtime()
            val waiting = pending
            if (waiting != null) { check(elapsed - waiting.started in 0..2_000); return }
            if (lastRequest >= 0 && elapsed - lastRequest < 25_000) return
            check(requests < 64)
            val challenge = UUID.randomUUID()
            pending = Pending(challenge, UUID.fromString(line.lineId), elapsed)
            lastRequest = elapsed; requests++
            check(socket.send(JSONObject().put("v", 1).put("type", "payload_profile_current03_request")
                .put("connection_epoch", time.snapshot()!!.first.session.connectionEpoch)
                .put("challenge", challenge).put("line_id", line.lineId).toString()))
        }
    }
    fun acceptCurrent(raw: ByteArray) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "current") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "payload_profile_current03")
        val waiting = synchronized(effects) {
            check(current())
            val value = checkNotNull(pending)
            pending = null
            val session = checkNotNull(time.snapshot()).first.session
            require(f["connection_epoch"] == Profile03Json.Integer(session.connectionEpoch) &&
                f["challenge"] == value.challenge.toString() && SystemClock.elapsedRealtime() - value.started in 0..2_000)
            value
        }
        val bytes = Profile03Json.render(Profile03Json.nested(f, "current"))
        JournalRuntime.io.execute { runCatching {
            check(current())
            val value = reader.installAccepted(bytes, waiting.line)
            val session = checkNotNull(time.snapshot()).first.session
            val c = value.selected
            val ready = SealedDispatch03Frames.ready(JSONObject().put("v", 1).put("type", "sealed_ready")
                .put("grant_version", 3).put("envelope_profile", 3).put("manifest_profile", 3)
                .put("line_id", waiting.line).put("connection_epoch", session.connectionEpoch)
                .put("deployment_epoch", session.deploymentEpoch).put("binding_generation", c.bindingGeneration)
                .put("trust_generation", c.vaultGeneration).put("manifest_version", c.manifestVersion)
                .put("reader_key_id", b64(c.selectedReaderKeyId)).put("manifest_digest", b64(c.manifestDigest))
                .put("root_fingerprint", b64(c.rootFingerprint)).put("election_digest", b64(c.electionCommitment)).toString())
            synchronized(effects) { check(current()); projection = bytes; check(socket.send(ready.json())) }
            Profile03MessagingStatus.update(this, "Messaging ready. Each message still needs current sending approval.")
        }.onFailure { close() } }
    }
    fun acceptUnavailable(raw: ByteArray) {
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "connection_epoch", "challenge", "reason") &&
            f["v"] == Profile03Json.Integer(1) && f["type"] == "payload_profile_current03_unavailable" &&
            f["reason"] in setOf("not_accepted", "unsupported", "expired"))
        synchronized(effects) {
            check(current())
            val waiting = checkNotNull(pending); pending = null
            val session = checkNotNull(time.snapshot()).first.session
            require(f["connection_epoch"] == Profile03Json.Integer(session.connectionEpoch) &&
                f["challenge"] == waiting.challenge.toString() && SystemClock.elapsedRealtime() - waiting.started in 0..2_000)
            if (f["reason"] != "not_accepted") { pollingStopped = true; projection = null }
            Profile03MessagingStatus.update(this, if (f["reason"] == "not_accepted") "Waiting for owner approval. Your phone approval is saved."
                else "Messaging setup paused. Review the saved phone and line setup in your owner workspace.")
        }
    }
    private fun requireGrantCurrent(grant: SealedDispatch03Frames.Grant) {
        check(current())
        val session = checkNotNull(time.snapshot()).first.session
        check(grant.accountId == session.accountId && grant.deviceId == session.deviceId &&
            grant.connectionEpoch == session.connectionEpoch && grant.deploymentEpoch == session.deploymentEpoch)
        val instant = checkNotNull(time.nowMs())
        check(grant.expiresAtMs - instant in 1..35_000)
        val selected = reader.manifestDeviceSelection(checkNotNull(projection), grant.lineId).selected
        check(grant.bindingGeneration == selected.bindingGeneration && grant.trustGeneration == selected.vaultGeneration &&
            grant.manifestVersion == selected.manifestVersion && same(grant.readerKeyId, selected.selectedReaderKeyId) &&
            same(grant.rootFingerprint, selected.rootFingerprint) && same(grant.manifestDigest, selected.manifestDigest) &&
            same(grant.electionDigest, selected.electionCommitment) && grant.expiresAtMs <= selected.permissionExpiresAtMs)
        suppression.requireAvailable()
        check(current() && checkNotNull(time.nowMs()) < grant.expiresAtMs)
    }
    fun grant(raw: String) {
        val grant = SealedDispatch03Frames.grant(raw)
        synchronized(attempted) { check(attempted.size < 1024 && attempted.add("${grant.messageId}:${grant.attemptId}")) }
        JournalRuntime.io.execute { runCatching { execute(grant) }.onFailure { close() } }
    }
    private fun execute(grant: SealedDispatch03Frames.Grant) {
        requireGrantCurrent(grant)
        val packet = checkNotNull(fetch.fetch(grant))
        val session = checkNotNull(time.snapshot()).first.session
        fun live() = reader.readMessageManifest(packet, grant).also {
            requireGrantCurrent(grant)
            check(!db.attempts().isRecipientSuppressed(suppression.sender(it.intent.peer().toString(Charsets.US_ASCII))))
        }
        val initial = live()
        when (val result = Draft03OutboundPreparation.prepare(packet.envelope(), grant, session, db, recipients, time::nowMs, ::live)) {
            is Draft03OutboundPreparation.Ready -> result.prepared.use { prepared ->
                val context = Profile03RadioContext(grant, session, initial)
                fun fresh(): Long { live(); return checkNotNull(time.nowMs()).also { check(it < grant.expiresAtMs) } }
                synchronized(effects) {
                    check(current())
                    JournaledPreparedRadioSubmission(db.attempts(), wire,
                        { binding -> ConversationRadioPlatform(application, binding, suppression, enabled = true) }, true)
                        .submit(context, prepared, ::fresh)
                }
            }
            else -> Unit // Refusal never selects another profile/provider/plaintext path.
        }
    }
    fun radioAck(event: String, state: String, permitted: Boolean) =
        wire.acceptRadioAck(time.snapshot()?.first?.session?.let(ConversationPhoneSession::from), event, state, permitted)
    override fun close() {
        // Withdraw before acquiring a lock that a blocked preparation/radio operation may hold.
        closed = true
        SelectionRefresh03Mount.detach(this)
        ConversationInterval03Mount.detach(this)
        Profile03ManifestMount.detach(this)
        manifests.close()
        refresh.close()
        intervals.close()
        Profile03MessagingStatus.update(this, "Messaging paused. Your pairing and setup history are saved.")
        Profile03BootstrapClock.withdraw(this)
        time.close(); wire.invalidate()
        synchronized(effects) { pending = null; projection = null; Profile03BootstrapClock.withdraw(this) }
        storage.close()
    }
    override fun toString() = "Profile03ExecutionConnection(redacted)"
    companion object {
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun same(a: ByteArray, b: ByteArray) = java.security.MessageDigest.isEqual(a, b)
    }
}
