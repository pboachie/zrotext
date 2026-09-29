// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import java.util.UUID

/**
 * The PROPOSED `sealed_execution_grant` vectors in protocol/v1/vectors, shared with the
 * Python reference (test_sealed_execution_grant_vectors.py): the strict frame parser,
 * the envelope routing-claims bound and the validator must reach the pinned verdict
 * and exact refusal reason for every case.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedExecutionGrantVectorTest {
    private val vectors = resource("sealed-execution-grant-01.json")
    private val preparation = resource("candidate02-preparation.json")

    private fun resource(name: String) = JSONObject(
        checkNotNull(javaClass.classLoader?.getResourceAsStream(name)).use { it.readBytes() }.toString(Charsets.UTF_8)
    )

    private fun envelope(name: String?): ByteArray {
        val cases = preparation.getJSONObject("cases")
        val normal = PreparationFixture.hex(cases.getString(vectors.getJSONObject("envelopeSource").getString("case")))
        return when (name) {
            null -> normal
            "truncated" -> normal.copyOf(normal.size - 1)
            else -> PreparationFixture.hex(cases.getString(name))
        }
    }

    private fun patched(base: JSONObject, patch: JSONObject?, remove: List<String> = emptyList()) =
        JSONObject(base.toString()).also { copy ->
            patch?.keys()?.forEach { copy.put(it, patch.get(it)) }
            remove.forEach { copy.remove(it) }
        }

    private fun b64(text: String) = Base64.getUrlDecoder().decode(text)

    /** The executor's first two fences without the journal: envelope bound, then the validator. */
    private fun verdict(frame: JSONObject, context: JSONObject, bytes: ByteArray): Any {
        val fields = SealedExecutionGrantFrame.parse(frame)
        val routing = try {
            Draft02OutboundEnvelope.routingClaims(bytes)
        } catch (_: Exception) {
            return SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_MALFORMED
        }
        fun uuid(raw: ByteArray) = UUID.fromString(Draft02OutboundPreparation.uuid(raw))
        val claims = SealedExecutionGrantValidator.EnvelopeClaims(
            uuid(routing.accountId), uuid(routing.messageId), uuid(routing.deviceId), uuid(routing.lineId),
            routing.deviceReaderKeyId,
        )
        return SealedExecutionGrantValidator.validate(
            fields, bytes, claims,
            UUID.fromString(context.getString("authenticatedAccountId")),
            UUID.fromString(context.getString("authenticatedDeviceId")),
            UUID.fromString(context.getString("activeLineId")),
            context.getLong("connectionEpoch"), context.getLong("deploymentEpoch"),
            context.getLong("activeBindingGeneration"), b64(context.getString("pinnedReaderKeyId")),
            context.getLong("trustedNowMs"),
        )
    }

    @Test fun everyVectorReachesItsPinnedVerdictAndReason() {
        assertTrue(vectors.getString("status").startsWith("PROPOSED"))
        val cases = vectors.getJSONArray("cases")
        val seen = mutableSetOf<String>()
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val name = case.getString("name")
            val remove = case.optJSONArray("frameRemove")?.let { list -> List(list.length()) { list.getString(it) } }
            val frame = patched(vectors.getJSONObject("frame"), case.optJSONObject("framePatch"), remove.orEmpty())
            val context = patched(vectors.getJSONObject("context"), case.optJSONObject("contextPatch"))
            val bytes = envelope(if (case.has("envelope")) case.getString("envelope") else null)
            when (case.getString("verdict")) {
                "malformed" -> try {
                    SealedExecutionGrantFrame.parse(frame)
                    fail("$name parsed")
                } catch (_: IllegalStateException) {
                } catch (_: IllegalArgumentException) {
                }
                "accept" -> assertTrue(name, verdict(frame, context, bytes) is SealedExecutionGrantValidator.Verdict.Valid)
                "refuse" -> {
                    val refused = verdict(frame, context, bytes) as SealedExecutionGrantValidator.Verdict.Refused
                    assertEquals(name, case.getString("reason"), refused.name.lowercase())
                    seen += refused.name
                }
                else -> fail("$name verdict")
            }
        }
        // Every refusal except the post-decrypt segment fence has a shared vector.
        assertEquals(
            SealedExecutionGrantValidator.Verdict.Refused.entries.map { it.name }.toSet() -
                SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_EXCEEDS_GRANT.name,
            seen,
        )
    }

    @Test fun refusalReportMatchesTheVectorsAndCarriesNoContent() {
        val frames = vectors.getJSONArray("refusalFrames")
        val attempt = UUID.fromString(vectors.getJSONObject("frame").getString("attempt_id"))
        val expected = listOf(
            SealedExecutionGrantValidator.Verdict.Refused.EXPIRED,
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH,
        )
        expected.forEachIndexed { index, reason ->
            val actual = SealedExecutionGrantFrame.refusal(attempt, 1L, reason)
            assertEquals(frames.getJSONObject(index).toString(), actual.toString())
            assertEquals(setOf("v", "type", "grant_version", "attempt_id", "connection_epoch", "reason"),
                actual.keys().asSequence().toSet())
        }
    }

    @Test fun plaintextRulesMatchTheSharedBodyTextCorpus() {
        val corpus = resource("ztse-body-text-01.json").getJSONArray("textCases")
        for (index in 0 until corpus.length()) {
            val case = corpus.getJSONObject(index)
            val raw = PreparationFixture.hex(case.getString("hex"))
            val accepted = SealedPlaintextRules.acceptBody(raw)
            if (case.getString("verdict") == "accept") assertTrue(case.getString("name"), accepted)
            else assertFalse(case.getString("name"), accepted)
        }
    }
}
