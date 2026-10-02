// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.ContextWrapper
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class SealedLineActivationReceiptStoreTest {
    @After fun disable() { SealedLineActivationMount.disable() }
    @Test fun defaultDisabledAndDeclinedLocalAcceptanceTouchNoPreferencesOrKeystore() {
        val f = SealedLineActivationFixture()
        SealedLineActivationMount.disable()
        val untouched = object : ContextWrapper(null) {
            override fun getSharedPreferences(name: String?, mode: Int): android.content.SharedPreferences = error("Disabled preference read")
            override fun getApplicationContext(): Context = error("Disabled application read")
        }
        assertFalse(SealedLineActivationMount.enable(f.selection))
        assertNull(SealedLineActivationMount.open(untouched, DeviceSigningKeyStore(untouched),
            f.challenge.accountId, f.challenge.deviceId, 42) { error("Disabled session lookup") })
    }
    @Test fun privatePublicSnapshotCommitsAndMalformedOrMissingSnapshotFailsClosed() {
        val context = RuntimeEnvironment.getApplication()
        val preferences = context.getSharedPreferences("sealed_line_activation_receipt", Context.MODE_PRIVATE)
        assertTrue(preferences.edit().clear().commit())
        val store = SealedLineActivationReceiptStore(context)
        assertNull(store.read())
        val f = SealedLineActivationFixture(); val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        val snapshot = SealedLineActivationSnapshot(proof, f.receipt(proof.signature()))
        assertTrue(store.write(snapshot))
        val recovered = checkNotNull(store.read())
        assertArrayEquals(proof.statement(), recovered.proof.statement())
        assertArrayEquals(proof.signature(), recovered.proof.signature())
        assertTrue(recovered.receipt.matches(proof))
        assertTrue(preferences.edit().putString("public_receipt_v1", "{}").commit()); assertNull(store.read())
        assertTrue(preferences.edit().remove("public_receipt_v1").commit()); assertNull(store.read())
    }
    @Test fun receiptCodecRejectsScopeStatementDigestDerTypeAndOversizeTampering() {
        val f = SealedLineActivationFixture(); val proof = checkNotNull(f.device.prepare(f.challenge, f.selection))
        val encoded = SealedLineActivationReceiptCodec.encode(SealedLineActivationSnapshot(proof, f.receipt(proof.signature())))
        // JSONObject's serializer turns 1.0 into 1. Preserve the received floating token itself.
        assertTrue(runCatching { SealedLineActivationReceiptCodec.decode(encoded.replace("\"version\":1", "\"version\":1.0")) }.isFailure)
        val changes: List<(JSONObject) -> Unit> = listOf(
            { it.put("api", 30) }, { it.put("subscription", 8) },
            { it.getJSONObject("challenge").put("generation", 8) },
            { it.getJSONObject("challenge").put("nonce", SealedLineActivationFrames.encode(ByteArray(32) { 8 })) },
            { it.put("signature", SealedLineActivationFrames.encode(byteArrayOf(0x30, 6, 2, 1, 0, 2, 1, 1))) },
            { it.getJSONObject("receipt").put("device_statement_sha256", SealedLineActivationFrames.encode(ByteArray(32))) },
            { it.put("extra", true) }
        )
        for (change in changes) {
            val mutated = JSONObject(encoded).also(change)
            assertTrue(runCatching { SealedLineActivationReceiptCodec.decode(mutated.toString()) }.isFailure)
        }
        assertTrue(runCatching { SealedLineActivationReceiptCodec.decode(" ".repeat(4097)) }.isFailure)
    }
    @Test fun wellFormedButForgedStoredSignatureIsNeverRecovered() {
        val f = SealedLineActivationFixture(); val p = f.provider(); val (_, ack) = f.start(p)
        assertNotNull(p.accept(f.activated(ack))); p.close()
        val original = checkNotNull(f.stored).proof
        val forgedDer = byteArrayOf(0x30, 6, 2, 1, 1, 2, 1, 1)
        val forged = PreparedSealedLineActivation(original.challenge, original.apiLevel, original.sim,
            original.statement(), forgedDer, original.fingerprint())
        val fakeAck = f.receipt(forgedDer)
        f.stored = SealedLineActivationSnapshot(forged, fakeAck)
        assertNull(f.provider(43).accept(f.activated(f.reepoch(fakeAck, 43))))
    }
}
