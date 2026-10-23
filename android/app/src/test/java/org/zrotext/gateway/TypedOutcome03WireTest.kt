// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedOutcome03WireTest {
    private val fixture = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun submit() = TypedSubmit03Command.decode(TypedHistory03Fixture.bytes(
        fixture.getJSONArray("cases").getJSONObject(0).getString("submit")))
    private fun outcome() = TypedOutcome03Command.decode(TypedHistory03Fixture.bytes(
        fixture.getJSONArray("cases").getJSONObject(0).getJSONArray("outcomes").getJSONObject(0).getString("command")))

    @Test fun everyIndependentOriginalFormKeepsIts211AndOnlyOuterEpochChanges() {
        val cases = fixture.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val command = TypedSubmit03Command.decode(TypedHistory03Fixture.bytes(c.getString("submit")))
            val forms = c.getJSONArray("outcomes")
            for (j in 0 until forms.length()) {
                val assertion = TypedOutcome03Command.decode(TypedHistory03Fixture.bytes(forms.getJSONObject(j).getString("command")))
                val before = assertion.bytes()
                val old = JSONObject(String(TypedOutcome03Wire.request(command, assertion, 12)))
                val next = JSONObject(String(TypedOutcome03Wire.request(command, assertion, 13)))
                assertEquals(14, old.length()); assertEquals(13L, next.getLong("connection_epoch"))
                old.remove("connection_epoch"); next.remove("connection_epoch")
                assertEquals(old.toString(), next.toString()); assertArrayEquals(before, assertion.bytes())
                assertEquals(assertion.segmentIndex == null, next.isNull("segment_index"))
            }
        }
    }

    @Test fun recordedAndHistoricalReceiptsKeepAllClosedStatesIncludingNullWithoutAuthority() {
        val command = submit(); val assertion = outcome()
        for (state in listOf(null, "submitting", "submitted", "delivered", "delivery_unknown", "unknown", "failed")) {
            for (disposition in listOf("recorded", "history_only")) {
                val raw = TypedOutcome03TestFixture.ack(command, assertion, 13, disposition, state).toString().toByteArray()
                val ack = TypedOutcome03Wire.Ack.decode(raw, command, assertion, 13)
                assertEquals(state, ack.resultingState); assertEquals(disposition == "history_only", ack.historyOnly)
                raw.fill(0); assertTrue(ack.bytes().size > 2)
            }
        }
    }

    @Test fun wrongActorCorrelationOriginalHashKindStateOrScalarCannotAcknowledgeAnOutcome() {
        val command = submit(); val assertion = outcome()
        for ((field, value) in listOf("event_id" to TypedHistory03Fixture.id(901),
            "submit_event_id" to TypedHistory03Fixture.id(902), "connection_epoch" to 12,
            "submit_command_sha256" to Profile03ElectionEncoding.encode(ByteArray(32) { 1 }),
            "event_sha256" to Profile03ElectionEncoding.encode(ByteArray(32) { 2 }),
            "type" to "payload_profile_submit_status03", "disposition" to "submit_once",
            "resulting_state" to "accepted", "recorded_ms" to 3000101)) {
            val raw = TypedOutcome03TestFixture.ack(command, assertion, 13).put(field, value).toString().toByteArray()
            assertThrows(Exception::class.java) { TypedOutcome03Wire.Ack.decode(raw, command, assertion, 13) }
        }
    }

    @Test fun duplicateExtraAndOversizedPacketsAndNullableKindCoercionRefuse() {
        val command = submit(); val assertion = outcome()
        val raw = TypedOutcome03TestFixture.ack(command, assertion, 13, state = null).toString()
        for (text in listOf(raw.dropLast(1) + ",\"event_id\":\"${assertion.eventId}\"}",
            raw.dropLast(1) + ",\"current\":{}}", raw + " ".repeat(4096))) {
            assertThrows(Exception::class.java) { TypedOutcome03Wire.Ack.decode(text.toByteArray(), command, assertion, 13) }
        }
        assertThrows(Exception::class.java) { Profile03Json.objectValue(raw.toByteArray()) }
        assertThrows(Exception::class.java) { Profile03Json.submitAckObject(raw.toByteArray()) }
        assertThrows(Exception::class.java) { TypedOutcome03Wire.request(command, assertion, 0) }
    }
}
