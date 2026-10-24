// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Synthetic authenticated-transport candidates, not actual enrollment or a clock brand. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedHistory03WireTest {
    private fun id(n: Long) = UUID(0, n).toString()
    private val query = TypedHistory03Wire.Query(id(3), id(4), id(5))
    private val point = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use {
        Base64.getUrlDecoder().decode(JSONObject(it.bufferedReader().readText()).getString("enrolled_point"))
    }
    private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun b64(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun text(value: String): ByteArray = value.toByteArray(Charsets.UTF_8).let {
        ByteBuffer.allocate(4).putInt(it.size).array() + it }
    private fun uuid(value: String) = UUID.fromString(value).let {
        ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array() }
    private fun frame(version: Int = 2, leaseEnd: Long = 4_000_000): JSONObject {
        val key = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
        val payload = uuid(id(1)) + uuid(id(2)) + text("synthetic-site") + text("synthetic-instance") +
            ByteBuffer.allocate(18).putLong(7).putLong(9).putShort(version.toShort()).array() + key
        val label = "ZTSE/line/payload-profile/device-session/v1\u0000".toByteArray(Charsets.US_ASCII)
        val digest = sha(label + ByteBuffer.allocate(4).putInt(payload.size).array() + payload)
        return JSONObject().put("v", 1).put("type", "payload_profile_history_clock03")
            .put("connection_epoch", 7).put("request_id", query.requestId).put("message_id", query.messageId)
            .put("attempt_id", query.attemptId).put("account_id", id(1)).put("device_id", id(2))
            .put("server_time_ms", "3000000").put("sample_expires_ms", minOf(3_030_000, leaseEnd).toString())
            .put("lease", JSONObject().put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
                .put("deployment_epoch", "9").put("line_activation_version", version)
                .put("enrolled_signing_key_id", b64(key)).put("device_session_digest", b64(digest))
                .put("expires_ms", leaseEnd.toString()))
    }
    private fun decode(frame: JSONObject, version: Int = 2) = TypedHistory03Wire.decode(
        frame.toString().toByteArray(), query, id(1), id(2), 7, version, point)

    @Test fun exactlyTheSixRequestFieldsAndBothActualLeaseVersionsRemainSeparateFromCurrent03() {
        val request = Profile03Json.objectValue(TypedHistory03Wire.request(7, query))
        assertEquals(setOf("v", "type", "connection_epoch", "request_id", "message_id", "attempt_id"), request.keys)
        assertEquals(Profile03Json.Integer(7), request["connection_epoch"])
        for (version in 1..2) {
            val actual = decode(frame(version), version)
            assertEquals(3_000_000L, actual.serverMs)
            assertEquals(3_030_000L, actual.sampleExpiresMs)
            assertEquals(9L, actual.deploymentEpoch)
        }
        assertThrows(IllegalArgumentException::class.java) { decode(frame(1), 2) }
        assertThrows(IllegalArgumentException::class.java) { decode(frame(2), 1) }
    }

    @Test fun exactNonceActorEpochLeasePointAndDigestAreAllRequired() {
        for (field in listOf("request_id", "message_id", "attempt_id", "account_id", "device_id"))
            assertThrows(IllegalArgumentException::class.java) { decode(frame().put(field, id(99))) }
        assertThrows(IllegalArgumentException::class.java) { decode(frame().put("connection_epoch", 8)) }
        for (field in listOf("enrolled_signing_key_id", "device_session_digest")) {
            val value = frame(); value.getJSONObject("lease").put(field, b64(ByteArray(32) { 1 }))
            assertThrows(IllegalArgumentException::class.java) { decode(value) }
        }
        for (field in listOf("site_id", "instance_id", "deployment_epoch")) {
            val value = frame(); value.getJSONObject("lease").put(field, if (field == "deployment_epoch") "10" else "different")
            assertThrows(IllegalArgumentException::class.java) { decode(value) }
        }
    }

    @Test fun duplicatesUnknownFieldsScalarCoercionAndUnboundedOrHistoricalWindowsRefuse() {
        val raw = frame().toString().replaceFirst("{", "{\"request_id\":\"${query.requestId}\",")
        assertThrows(IllegalArgumentException::class.java) {
            TypedHistory03Wire.decode(raw.toByteArray(), query, id(1), id(2), 7, 2, point) }
        assertThrows(IllegalArgumentException::class.java) { decode(frame().put("current", JSONObject())) }
        val extra = frame(); extra.getJSONObject("lease").put("permission", "yes")
        assertThrows(IllegalArgumentException::class.java) { decode(extra) }
        for (value in listOf<Any>(3_000_000, "03000000", "9223372036854775808", "0"))
            assertThrows(IllegalArgumentException::class.java) { decode(frame().put("server_time_ms", value)) }
        assertThrows(IllegalArgumentException::class.java) { decode(frame().put("connection_epoch", "7")) }
        for (end in listOf("3000000", "3030001", "3000001"))
            assertThrows(IllegalArgumentException::class.java) { decode(frame().put("sample_expires_ms", end)) }
        assertEquals(3_000_100L, decode(frame(leaseEnd = 3_000_100)).sampleExpiresMs)
        assertThrows(IllegalArgumentException::class.java) { decode(frame(leaseEnd = 3_000_000)) }
    }
}
