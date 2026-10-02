// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject

/** Only the authenticated socket listener may feed these metadata replies. No grant or wall-clock fallback. */
internal class SealedSocketTime(private val account: UUID, private val device: UUID,
    private val epoch: Long, private val originHash: String, private val elapsed: () -> Long,
    private val isCurrent: () -> Boolean, private val send: (JSONObject) -> Boolean) {
    private data class Pending(val challenge: UUID, val started: Long)
    private var waiting: Pending? = null
    private var session: SealedDispatchExecutor.Session? = null
    private var anchor: SealedSessionClock? = null
    private var closed = false
    private var lastElapsed = -1L
    private var lastUtc = 0L
    private var previousUpper = 0L
    private var previousReceived = 0L
    private var samples = 0
    private var lastRequest = -1L

    init {
        require(account != UUID(0, 0) && device != UUID(0, 0) && epoch > 0)
        require(originHash.matches(Regex("[0-9a-f]{64}")))
    }

    private fun monotonic(): Long {
        check(!closed && isCurrent())
        val now = elapsed()
        check(now >= 0 && now >= lastElapsed)
        lastElapsed = now
        return now
    }

    /** At most one pending sample. Time refresh never renews readiness, a grant or a journaled intent. */
    @Synchronized fun request(): Boolean = try {
        val now = monotonic()
        check(samples < MAX_SAMPLES)
        if (waiting != null) {
            check(now - checkNotNull(waiting).started <= MAX_RTT_MS)
            true
        } else if (lastRequest >= 0 && now - lastRequest < REQUEST_INTERVAL_MS) true
        else {
            val challenge = UUID.randomUUID()
            waiting = Pending(challenge, now)
            lastRequest = now
            check(send(JSONObject().put("v", 1).put("type", "sealed_session_request")
                .put("connection_epoch", epoch).put("challenge", challenge.toString())))
            true
        }
    } catch (_: Exception) { close(); false }

    /** Exact v2 reply binds a fresh nonce to the account/device/epoch proved by the ordinary handshake. */
    @Synchronized fun accept(frame: JSONObject) {
        try {
            val pending = checkNotNull(waiting)
            waiting = null // An invalid response consumes the nonce too.
            check(frame.keys().asSequence().toSet() == REPLY_KEYS)
            check(number(frame, "v") == 1L && frame.opt("type") == "sealed_session")
            check(uuid(frame, "challenge") == pending.challenge && uuid(frame, "account_id") == account &&
                uuid(frame, "device_id") == device && number(frame, "connection_epoch") == epoch)
            val deployment = number(frame, "deployment_epoch").also { check(it > 0) }
            val identity = uuid(frame, "session_id")
            val now = monotonic()
            val rtt = now - pending.started
            val sent = number(frame, "server_time_ms")
            check(rtt in 0..MAX_RTT_MS && sent > 0 && sent <= Long.MAX_VALUE - rtt - SealedSessionClock.MAX_ANCHOR_AGE_MS)
            val prior = session
            check(prior == null || prior.sessionId == identity && prior.deploymentEpoch == deployment)
            val upper = sent + rtt // Network uncertainty can only expire an operation early.
            val floor = if (prior == null) lastUtc else maxOf(lastUtc,
                Math.addExact(previousUpper, now - previousReceived))
            check(upper >= floor)
            val next = prior ?: SealedDispatchExecutor.Session(account, device, epoch, deployment, identity, originHash)
            anchor = checkNotNull(SealedSessionClock.establish(epoch, upper, now))
            session = next
            previousUpper = upper; previousReceived = now; lastUtc = upper
            samples++
        } catch (error: Exception) { close(); throw error }
    }

    @Synchronized fun trustedNow(): Long? = try {
        val now = checkNotNull(anchor).nowMs(monotonic())
        if (now != null) { check(now >= lastUtc); lastUtc = now }
        now
    } catch (_: Exception) { close(); null }

    @Synchronized fun currentSession(): SealedDispatchExecutor.Session? =
        if (!closed && runCatching { isCurrent() }.getOrDefault(false)) session else null

    @Synchronized fun snapshot(): Pair<SealedDispatchExecutor.Session, SealedSessionClock>? =
        if (trustedNow() == null) null else currentSession()?.let { it to checkNotNull(anchor) }

    @Synchronized fun close() { closed = true; waiting = null; anchor = null; session = null }
    override fun toString() = "SealedSocketTime(redacted)"

    companion object {
        const val PROTOCOL = "zrotext-device-status-v2+sealed-dispatch-v2"
        const val MAX_RTT_MS = 2_000L
        const val REQUEST_INTERVAL_MS = 25_000L
        const val MAX_SAMPLES = 64
        private val REPLY_KEYS = setOf("v", "type", "challenge", "account_id", "device_id",
            "connection_epoch", "deployment_epoch", "session_id", "server_time_ms")
        private fun number(frame: JSONObject, name: String): Long {
            val value = frame.opt(name)
            check(value is Int || value is Long)
            return (value as Number).toLong()
        }
        private fun uuid(frame: JSONObject, name: String): UUID {
            val value = frame.opt(name)
            check(value is String && value.length == 36)
            return UUID.fromString(value).also { check(it != UUID(0, 0) && it.toString() == value) }
        }
    }
}
