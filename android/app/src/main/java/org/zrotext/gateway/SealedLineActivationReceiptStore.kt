// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import org.json.JSONObject

/** Public provenance only. This never restores a body-consent grant or a content/radio runtime. */
internal data class SealedLineActivationSnapshot(val proof: PreparedSealedLineActivation,
    val receipt: SealedLineActivationReceipt) {
    init { require(receipt.matches(proof)) }
    override fun toString() = "SealedLineActivationSnapshot(redacted)"
}

internal interface SealedLineReceiptPersistence {
    fun read(): SealedLineActivationSnapshot?
    fun write(snapshot: SealedLineActivationSnapshot): Boolean
}

internal object SealedLineActivationReceiptCodec {
    fun encode(snapshot: SealedLineActivationSnapshot): String {
        val proof = snapshot.proof
        return SealedLineActivationFrames.bounded(JSONObject().put("version", 1)
            .put("challenge", SealedLineActivationFrames.challengeFrame(proof.challenge))
            .put("api", proof.apiLevel).put("subscription", proof.sim.subscriptionId).put("card", proof.sim.cardId)
            .put("statement", SealedLineActivationFrames.encode(proof.statement()))
            .put("signature", SealedLineActivationFrames.encode(proof.signature()))
            .put("fingerprint", SealedLineActivationFrames.encode(proof.fingerprint()))
            .put("receipt", SealedLineActivationFrames.receiptFrame(snapshot.receipt)))
    }
    fun decode(text: String): SealedLineActivationSnapshot {
        require(text.length in 1..4096 && text.toByteArray(Charsets.UTF_8).size <= 4096)
        val frame = JSONObject(text)
        SealedLineActivationFrames.fields(frame, setOf("version", "challenge", "api", "subscription", "card",
            "statement", "signature", "fingerprint", "receipt"))
        require(SealedLineActivationFrames.integer(frame, "version") == 1L)
        val api = SealedLineActivationFrames.integer(frame, "api").also { require(it in 31..65535) }.toInt()
        val subscription = SealedLineActivationFrames.integer(frame, "subscription").also { require(it in 0..Int.MAX_VALUE.toLong()) }.toInt()
        val card = SealedLineActivationFrames.integer(frame, "card").also { require(it in 0..Int.MAX_VALUE.toLong()) }.toInt()
        val proof = PreparedSealedLineActivation(SealedLineActivationFrames.challenge(frame.getJSONObject("challenge")),
            api, ActivatedSimCard(subscription, card), SealedLineActivationFrames.variableBytes(frame, "statement", 130, 200),
            SealedLineActivationFrames.variableBytes(frame, "signature", 8, 72), SealedLineActivationFrames.bytes(frame, "fingerprint", 32))
        return SealedLineActivationSnapshot(proof, SealedLineActivationFrames.activated(frame.getJSONObject("receipt")))
    }
}

/** Manifest disables app backups. One MODE_PRIVATE entry, synchronous commit and exact readback. */
internal class SealedLineActivationReceiptStore(context: Context) : SealedLineReceiptPersistence {
    private val preferences = context.getSharedPreferences("sealed_line_activation_receipt", Context.MODE_PRIVATE)
    override fun read(): SealedLineActivationSnapshot? = try {
        preferences.getString("public_receipt_v1", null)?.let(SealedLineActivationReceiptCodec::decode)
    } catch (_: Exception) { null }
    override fun write(snapshot: SealedLineActivationSnapshot): Boolean = try {
        val encoded = SealedLineActivationReceiptCodec.encode(snapshot)
        preferences.edit().putString("public_receipt_v1", encoded).commit() &&
            preferences.getString("public_receipt_v1", null) == encoded
    } catch (_: Exception) { false }
}
