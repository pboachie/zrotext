// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedOutcome03CommandTest {
    private val fixture = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun bytes(value: String) = Base64.getUrlDecoder().decode(value)
    private fun original() = fixture.getJSONArray("cases").getJSONObject(0)

    @Test fun exactIndependentProducerFormsAreOwnedAndRetainTheirOriginalCommitments() {
        val cases = fixture.getJSONArray("cases")
        for (index in 0 until cases.length()) {
            val c = cases.getJSONObject(index)
            val submit = TypedSubmit03Command.decode(bytes(c.getString("submit")))
            val outcomes = c.getJSONArray("outcomes")
            for (i in 0 until outcomes.length()) {
                val row = outcomes.getJSONObject(i)
                val raw = bytes(row.getString("command"))
                val command = TypedOutcome03Command.decode(raw)
                val held = command.bytes(); raw.fill(0)
                command.requireCommand(submit)
                assertArrayEquals(held, command.bytes())
                assertArrayEquals(bytes(row.getString("commitment")), command.commitment())
                assertArrayEquals(held, TypedOutcome03Command.create(submit, row.getString("event_id"),
                    row.getInt("evidence"), if (row.isNull("segment_index")) null else row.getInt("segment_index"),
                    row.getString("observed_ms").toLong()).bytes())
            }
        }
    }

    @Test fun malformedIdentityDigestsTimeEvidenceAndSegmentGrammarRefuse() {
        val raw = bytes(original().getJSONArray("outcomes").getJSONObject(0).getString("command"))
        for (size in listOf(0, 210, 212)) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(ByteArray(size)) }
        for (at in 0 until 96 step 16) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it.fill(0, at, at + 16) }) }
        for (at in listOf(96, 128, 160)) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it.fill(0, at, at + 32) }) }
        for (count in listOf(0, 7, 255)) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it[200] = count.toByte() }) }
        for (kind in listOf(6, 255)) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it[201] = kind.toByte() }) }
        assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it[210] = 255.toByte() }) }
        assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { it[201] = 2 }) }
        val submit = ByteBuffer.wrap(raw, 192, 8).long
        for (time in listOf(0L, -1L, submit - 1)) assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.decode(raw.copyOf().also { ByteBuffer.wrap(it, 202, 8).putLong(time) }) }
    }

    @Test fun anAssertionCannotBecomeAnotherOriginalSubmitOrReplaceItsSourceIdentity() {
        val submit = TypedSubmit03Command.decode(bytes(original().getString("submit")))
        val source = UUID(0, 700).toString()
        val assertion = TypedOutcome03Command.create(submit, source, 0, 0, submit.observedMs)
        assertEquals(source, assertion.eventId)
        assertEquals(submit.observedMs, assertion.assertionMs)
        val other = TypedSubmit03Command.create(submit.accountId, submit.deviceId, UUID(0, 701).toString(),
            submit.messageId, submit.attemptId, submit.fetchSha256, submit.originalSessionSha256,
            submit.segmentCount, submit.observedMs)
        assertThrows(IllegalArgumentException::class.java) { assertion.requireCommand(other) }
        assertThrows(IllegalArgumentException::class.java) {
            TypedOutcome03Command.create(submit, source, 0, 0, submit.observedMs - 1) }
    }
}
