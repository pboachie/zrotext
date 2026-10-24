// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/** Additive03 authenticated socket metadata. The nonce/time anchor never supplies a current
 * owner, accepted election or effect permission. Receiving a frame cannot install a SIM lease.
 */
internal class Profile03SessionTime(account: UUID, device: UUID, epoch: Long, originHash: String,
    elapsed: () -> Long, current: () -> Boolean, claimedLineVersion: () -> Int?, send: (String) -> Boolean,
) {
    class Identity internal constructor(val session: SealedDispatchExecutor.Session, val site: String, val instance: String) {
        fun deviceSessionDigest(existingEnrollmentPoint: ByteArray): ByteArray {
            DevicePayloadKeyStore.decodePoint(existingEnrollmentPoint)
            val id = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + existingEnrollmentPoint)
            fun text(value: String): ByteArray {
                val bytes = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(value))
                val owned = ByteArray(bytes.remaining()).also(bytes::get)
                require(owned.size in 1..256 && value.none { it.isISOControl() })
                return ByteBuffer.allocate(4).putInt(owned.size).array() + owned
            }
            val payload = ReviewedIntent03.uuid(session.accountId) + ReviewedIntent03.uuid(session.deviceId) +
                text(site) + text(instance) + ByteBuffer.allocate(18).putLong(session.connectionEpoch)
                .putLong(session.deploymentEpoch).putShort(2).array() + id
            return sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/device-session/v1", payload))
        }
        override fun toString() = "Profile03SocketIdentity(metadata-only)"
    }
    private val original = SealedSocketTime(account, device, epoch, originHash, elapsed,
        { current() && claimedLineVersion() == 2 }, { request ->
            send(JSONObject(request.toString()).put("type", "payload_profile_session03_request").toString())
        })
    private var identity: Identity? = null
    @Volatile private var closed = false
    fun request() = !closed && original.request()
    @Synchronized fun accept(raw: ByteArray) {
        try {
            check(!closed)
            require(raw.size <= 4096)
            val fields = Profile03Json.objectValue(raw)
            require(fields.keys == setOf("v", "type", "challenge", "account_id", "device_id", "connection_epoch",
                "deployment_epoch", "session_id", "server_time_ms", "site_id", "instance_id", "line_activation_version") &&
                fields["v"] == Profile03Json.Integer(1) && fields["type"] == "payload_profile_session03" &&
                fields["line_activation_version"] == Profile03Json.Integer(2))
            val site = Profile03Json.text(fields, "site_id")
            val instance = Profile03Json.text(fields, "instance_id")
            for (value in listOf(site, instance)) {
                require(value.toByteArray(Charsets.UTF_8).size in 1..256 && value.none { it.isISOControl() })
            }
            val prior = identity
            require(prior == null || prior.site == site && prior.instance == instance)
            // Reuse the private strict nonce/RTT/epoch/time engine. No03 wire/grant is parsed as02.
            val time = fields.filterKeys { it !in setOf("site_id", "instance_id", "line_activation_version") }
                .toMutableMap().apply { put("type", "sealed_session") }
            original.accept(JSONObject(Profile03Json.render(time).toString(Charsets.UTF_8)))
            identity = Identity(checkNotNull(original.currentSession()), site, instance)
        } catch (failure: Exception) { close(); throw failure }
    }
    @Synchronized fun snapshot(): Pair<Identity, SealedSessionClock>? {
        if (closed) return null
        val current = identity ?: return null
        val time = original.snapshot() ?: return null
        return if (time.first === current.session) current to time.second else null
    }
    fun nowMs(): Long? = if (closed) null else original.trustedNow()
    @Synchronized fun close() { closed = true; identity = null; original.close() }
    override fun toString() = "Profile03SessionTime(redacted)"
    companion object {
        const val PROTOCOL = "zrotext-device-status-v2+sealed-dispatch-v3"
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
