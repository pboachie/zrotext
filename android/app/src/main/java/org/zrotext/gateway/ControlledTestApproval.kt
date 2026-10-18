// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Callable

/** A new message needs its own deliberate approval; the first-use marker is never cleared. */
internal data class ControlledTestScope(val deviceId: String, val originHash: String,
    val subscriptionId: Int, val recipientDigest: String) {
    init {
        require(UUID.fromString(deviceId).toString() == deviceId && subscriptionId >= 0)
        require(listOf(originHash, recipientDigest).all { it.matches(Regex("[0-9a-f]{64}")) })
    }
    companion object {
        /** Approval reads may block; retirement during that read must still refuse the radio. */
        internal fun currentAfterApproval(current: () -> Boolean, approved: () -> Boolean): Boolean =
            current() && approved() && current()

        fun capture(endpoint: String, deviceId: String, subscriptionId: Int, recipient: String): ControlledTestScope {
            require(HeartbeatResumeStore.validUrl(endpoint) && recipient.matches(Regex("^\\+[1-9][0-9]{1,14}$")))
            val uri = URI(endpoint)
            val origin = "wss://${uri.host.lowercase(java.util.Locale.ROOT)}:${if (uri.port == -1) 443 else uri.port}"
            fun hash(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII))
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return ControlledTestScope(deviceId, hash(origin), subscriptionId, hash(recipient))
        }
    }
}

internal data class ControlledTestFailure(val attemptId: String, val identity: EvidenceIdentity, val scope: ControlledTestScope)

/** Owns only explicit controlled-test approvals. It cannot erase or reset an attempt. */
internal class ControlledTestApproval(private val db: SmsJournalDatabase, private val prefs: SharedPreferences) {
    private fun records(): JSONArray = runCatching {
        val raw = checkNotNull(prefs.getString(KEY, "[]"));require(raw.length <= 65536)
        JSONArray(raw).also { require(it.length() <= LIMIT) }
    }.getOrElse { throw IllegalStateException("Controlled-test approval history is unreadable", it) }
    private fun store(records: JSONArray) { check(prefs.edit().putString(KEY, records.toString()).commit()) }
    private fun scope(record: JSONObject) = ControlledTestScope(record.getString("device"), record.getString("origin"),
        record.getInt("sim"), record.getString("recipient"))
    private fun fresh(record: JSONObject, now: Long) = now >= record.getLong("created") &&
        now < record.getLong("expires") && record.getLong("expires") - record.getLong("created") == WINDOW_MS &&
        !record.has("used") && !record.has("replaced")

    private fun failure(wanted: ControlledTestScope, prior: String? = null, excluded: String = ""): ControlledTestFailure {
        val dao = db.attempts()
        val attempt = if (prior == null) dao.latestControlledTest(wanted.deviceId, wanted.originHash)
            else dao.getAttempt(prior)
        check(attempt != null && attempt.messageId != null && attempt.deviceId == wanted.deviceId &&
            attempt.originHash == wanted.originHash && attempt.state == AttemptState.FAILED && !attempt.evidenceConflict)
        val identity = EvidenceIdentity(checkNotNull(attempt.accountId), checkNotNull(attempt.deviceId), checkNotNull(attempt.originHash))
        check(dao.unresolvedControlledTestPeers(excluded) == 0)
        val segments = dao.getSegments(attempt.attemptId)
        check(segments.size == attempt.segmentCount && segments.indices.all { segments[it].segmentIndex == it } &&
            segments.all { it.sentResultCode != null && it.sentResultCode != Activity.RESULT_OK &&
                it.deliveryStatus != DeliveryStatus.RECEIVED })
        val evidence = dao.controlledTestEvents(attempt.attemptId)
        check(evidence.isNotEmpty() && evidence.all { it.acknowledgedAtMs != null && it.quarantinedAtMs == null &&
            it.accountId == identity.accountId && it.deviceId == identity.deviceId && it.originHash == identity.originHash })
        check(segments.all { segment -> evidence.any { it.evidence == "sent_callback_failed" &&
            it.segmentIndex == segment.segmentIndex && it.segmentCount == attempt.segmentCount } })
        check(evidence.none { it.evidence in setOf("sent_callback_ok", "delivery_callback_ok") })
        return ControlledTestFailure(attempt.attemptId, identity, wanted)
    }

    fun prepare(wanted: ControlledTestScope): ControlledTestFailure = db.runInTransaction(Callable {
        synchronized(lock) {
            check(prefs.getBoolean("attempt_used", false))
            val failed = failure(wanted)
            val all = records()
            check((0 until all.length()).none { all.getJSONObject(it).let { r ->
                r.getString("prior") == failed.attemptId && r.has("used") } })
            failed
        }
    })

    /** Called only by the affirmative review button, with the same immutable review snapshot. */
    fun approve(wanted: ControlledTestScope, reviewed: ControlledTestFailure, now: Long): String = db.runInTransaction(Callable {
        synchronized(lock) {
            check(now > 0 && prefs.getBoolean("attempt_used", false))
            check(failure(wanted) == reviewed)
            val all = records();check(all.length() < LIMIT)
            for (i in 0 until all.length()) {
                val r = all.getJSONObject(i)
                check(r.getString("prior") != reviewed.attemptId || !r.has("used"))
                if (!r.has("used") && !r.has("replaced")) r.put("replaced", now)
            }
            val nonce = UUID.randomUUID().toString()
            all.put(JSONObject().put("id", nonce).put("prior", reviewed.attemptId)
                .put("account", reviewed.identity.accountId).put("device", wanted.deviceId).put("origin", wanted.originHash)
                .put("sim", wanted.subscriptionId).put("recipient", wanted.recipientDigest)
                .put("created", now).put("expires", Math.addExact(now, WINDOW_MS)))
            store(all);nonce
        }
    })

    fun available(wanted: ControlledTestScope, now: Long): String? = synchronized(lock) {
        val all = records()
        (0 until all.length()).map { all.getJSONObject(it) }.singleOrNull {
            scope(it) == wanted && fresh(it, now)
        }?.getString("id")
    }

    /** Spending precedes Room reservation and every possible radio action, including uncertain failures. */
    fun consume(wanted: ControlledTestScope, nonce: String, identity: EvidenceIdentity, attemptId: String, now: Long) {
        db.runInTransaction {
            synchronized(lock) {
                check(prefs.getBoolean("attempt_used", false))
                require(UUID.fromString(attemptId).toString() == attemptId)
                val all = records()
                val record = (0 until all.length()).map { all.getJSONObject(it) }.single { it.getString("id") == nonce }
                check(scope(record) == wanted && fresh(record, now))
                val failed = failure(wanted, record.getString("prior"))
                check(failed.identity == identity && record.getString("account") == identity.accountId)
                check((0 until all.length()).none { all.getJSONObject(it).let { r ->
                    r.getString("prior") == failed.attemptId && r.has("used") } })
                record.put("used", now).put("attempt", attemptId);store(all)
            }
        }
    }

    /** A late contradictory callback also fences the new approval before its radio boundary. */
    fun radioStillApproved(nonce: String, identity: EvidenceIdentity, attemptId: String): Boolean = runCatching {
        db.runInTransaction(Callable {
            synchronized(lock) {
                val all = records()
                val record = (0 until all.length()).map { all.getJSONObject(it) }.single { it.getString("id") == nonce }
                check(record.has("used") && record.getString("attempt") == attemptId)
                val wanted = scope(record)
                check(record.getString("account") == identity.accountId && wanted.deviceId == identity.deviceId && wanted.originHash == identity.originHash)
                failure(wanted, record.getString("prior"), attemptId).identity == identity
            }
        })
    }.getOrDefault(false)

    companion object {
        private val lock = Any()
        private const val KEY = "controlled_test_approvals_v1"
        private const val LIMIT = 64
        private const val WINDOW_MS = 5L * 60 * 1000
    }
}
