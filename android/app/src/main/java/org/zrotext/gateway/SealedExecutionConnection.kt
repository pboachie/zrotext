// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.util.Base64
import okhttp3.OkHttpClient
import okhttp3.WebSocket
import org.json.JSONObject

/** Ordinary socket composition of the existing executor and shared journaled radio path.
 * All authority is re-obtained locally; no dispatch negotiation occurs without an explicit lease.
 */
internal class SealedExecutionConnection(private val lease: SealedExecutionMount.Lease,
    account: java.util.UUID, device: java.util.UUID, epoch: Long, url: String,
    client: OkHttpClient, private val socket: WebSocket, keys: DeviceSigningKeyStore,
    private val socketCurrent: () -> Boolean,
) : AutoCloseable {
    private val inputs = lease.inputs
    @Volatile private var closed = false
    private val effects = Any()
    private val time = SealedSocketTime(account, device, epoch,
        EvidenceIdentity.fromStream(account, device, url).originHash, SystemClock::elapsedRealtime,
        ::current, { socket.send(it.toString()) })
    private val wire = ConversationSocketWire(socket, { time.currentSession()?.let(ConversationPhoneSession::from) })
    private val attempted = mutableSetOf<String>()
    private val started = SystemClock.elapsedRealtime()
    @Volatile private var ready = false
    private val fetch = SealedEnvelopeClient(url, client, keys::signSealedEnvelopeFetch) { fields ->
        val snapshot = checkNotNull(time.snapshot())
        check(current() && fields.accountId == snapshot.first.accountId && fields.deviceId == snapshot.first.deviceId &&
            fields.connectionEpoch == snapshot.first.connectionEpoch && fields.deploymentEpoch == snapshot.first.deploymentEpoch)
        val now = checkNotNull(time.trustedNow())
        check(fields.expiresAtMs > now && fields.expiresAtMs - now <= SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS)
        checkNotNull(inputs.observe(fields, snapshot.first, now) { checkNotNull(time.trustedNow()) })
    }
    private fun current() = !closed && lease.current() && socketCurrent() &&
        SystemClock.elapsedRealtime() - started in 0..300_000L
    fun start() = time.request()
    fun tick(): Boolean = current() && time.request()
    fun accept(frame: JSONObject) {
        check(current()); time.accept(frame)
        if (!ready) JournalRuntime.timeouts.schedule({ JournalRuntime.io.execute {
            runCatching {
                val session = checkNotNull(time.currentSession())
                checkNotNull(time.trustedNow())
                val (binding, key) = checkNotNull(inputs.readiness(session))
                synchronized(effects) {
                    check(current())
                    if (!ready) {
                        check(socket.send(JSONObject().put("v", 1).put("type", "sealed_ready").put("grant_version", 1)
                            .put("connection_epoch", session.connectionEpoch).put("line_id", binding.lineId)
                            .put("binding_generation", binding.generation).put("reader_key_id",
                                Base64.getUrlEncoder().withoutPadding().encodeToString(key.keyId)).toString()))
                        ready = true
                    }
                }
            }.onFailure { close() }
        } }, 1, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    fun grant(frame: JSONObject) {
        check(current() && ready)
        val fields = SealedExecutionGrantFrame.parse(frame)
        synchronized(attempted) {
            check(attempted.size < 1024 && attempted.add("${fields.messageId}:${fields.attemptId}"))
        }
        val owned = SealedEnvelopeFetch.frame(fields)
        JournalRuntime.io.execute { runCatching { execute(owned, fields) }.onFailure { close() } }
    }
    private fun execute(frame: JSONObject, fields: SealedExecutionGrantValidator.Fields) {
        val snapshot = time.snapshot() ?: return
        val session = snapshot.first
        fun observation() = time.trustedNow()?.let {
            inputs.observe(fields, session, it) { checkNotNull(time.trustedNow()) }
        }
        val initial = observation() ?: return
        fun fresh(): Long {
            check(current()); val now = checkNotNull(time.trustedNow())
            check(now < fields.expiresAtMs)
            val local = checkNotNull(observation()).first
            check(local.binding == initial.first.binding && local.manifestGeneration == initial.first.manifestGeneration &&
                local.manifestVersion == initial.first.manifestVersion && local.manifestDigest == initial.first.manifestDigest &&
                local.recipientDigest == initial.first.recipientDigest &&
                java.security.MessageDigest.isEqual(local.pinnedReaderKeyId, initial.first.pinnedReaderKeyId))
            val completed = checkNotNull(time.trustedNow())
            check(current() && completed >= now && completed < fields.expiresAtMs)
            return completed
        }
        val lane = SealedDispatchLane(session, snapshot.second, fetch::fetch, { observation()?.first },
            inputs.db, inputs.keyStore, SystemClock::elapsedRealtime,
            { grant -> inputs.preparation(grant, fields, session) { checkNotNull(time.trustedNow()) } },
            inputs::suppressed, inputs::cards, ::current) { _, segments, consume ->
            val peer = initial.second.request.peer().toString(Charsets.US_ASCII)
            val context = object : JournaledRadioContext {
                override val message = fields.messageId.toString()
                override val attempt = fields.attemptId.toString()
                override val accountId = session.accountId.toString()
                override val deviceId = session.deviceId.toString()
                override val peer = peer
                override val originalDeadlineMs = fields.expiresAtMs
                override val deadlineMs = fields.expiresAtMs
                override val grant get() = SealedEnvelopeFetch.snapshot(fields)
                override val session = session
                override val local = initial.first
            }
            val held = Draft02OutboundPreparation.relayPrepared(segments) { consumer ->
                synchronized(effects) { fresh(); consume(consumer) }
            }
            val result = JournaledPreparedRadioSubmission(inputs.db.attempts(), wire, inputs::platform, true)
                .submit(context, held, ::fresh)
            if (result == ConversationSubmission.SUBMITTED) SealedDispatchLane.Submission.SUBMITTED
            else SealedDispatchLane.Submission.UNKNOWN
        }
        val outcome = lane.onGrant(frame)
        if (outcome is SealedDispatchLane.Outcome.Refused && current())
            socket.send(SealedExecutionGrantFrame.refusal(fields.attemptId, session.connectionEpoch, outcome.reason).toString())
    }
    fun radioAck(event: String, state: String, permitted: Boolean) =
        wire.acceptRadioAck(time.currentSession()?.let(ConversationPhoneSession::from), event, state, permitted)
    override fun close() { synchronized(effects) { closed = true; time.close(); wire.invalidate() } }
    override fun toString() = "SealedExecutionConnection(redacted)"
}
