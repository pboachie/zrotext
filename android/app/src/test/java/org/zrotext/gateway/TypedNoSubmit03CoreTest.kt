// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03CoreTest {
    private val vector get() = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use { JSONObject(it.bufferedReader().readText()) }
    private fun case() = vector.getJSONArray("cases").getJSONObject(0)
    private fun core() = TypedNoSubmit03Core.decode(TypedSubmit03Record.unbase(case().getString("core")))

    @Test fun exactPublished441AndFixedDomainVerifyWithoutReinterpretingTheSyntheticLease() {
        val c = core(); val f = vector; val item = f.getJSONArray("cases").getJSONObject(0)
        assertEquals(441, c.bytes().size); assertEquals(1L, c.number(4))
        assertTrue(ConversationContentCrypto.verifyRaw(TypedSubmit03Record.unbase(item.getString("signature")),
            TypedSubmit03Record.unbase(f.getString("enrolled_point")), c.transcript()))
        assertFalse(ConversationContentCrypto.verifyRaw(TypedSubmit03Record.unbase(item.getString("signature")),
            TypedSubmit03Record.unbase(f.getString("enrolled_point")), ReviewedIntent03.framed("ZTSE/conversation/submit-command03/v1", c.bytes())))
        val owned = c.bytes(); owned[0] = 0; assertEquals(0x5a, c.bytes()[0].toInt())
    }
    @Test fun fixedGrammarRejectsUnsupportedHeaderSizeGenerationSegmentsAndTimeOrder() {
        val good = core().bytes()
        for (bad in listOf(good.copyOf(440), good + byteArrayOf(0), good.copyOf().apply { this[4] = 2 },
            good.copyOf().apply { ByteBuffer.wrap(this).putLong(168, 2) },
            good.copyOf().apply { ByteBuffer.wrap(this).putLong(176, 7) },
            good.copyOf().apply { ByteBuffer.wrap(this).putLong(192, 1) },
            good.copyOf().apply { ByteBuffer.wrap(this).putLong(208, core().issuedMs) })) {
            assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Core.decode(bad) }
        }
    }
    @Test fun nonceKeyAndOriginal210CommitmentsCannotBeSubstituted() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val p = ready.proof; val c = p.challenge().core
            c.requireOriginal(ready.action.row, p.challenge().nonce())
            assertThrows(IllegalArgumentException::class.java) { c.requireOriginal(ready.action.row, ByteArray(32) { 9 }) }
            val changed = c.bytes().apply { this[344] = (this[344].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Core.decode(changed).requireOriginal(ready.action.row, p.challenge().nonce()) }
            assertEquals(ready.action.row.command().originalSessionSha256.toList(), c.digest(2).toList())
        } }
    }
    @Test fun closedFramesRejectDuplicatesNullCoercionOverflowExtraFieldsAndOversize() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val receipt = db.typedNoSubmits03().first(f.closed(db), TypedNoSubmit03Fixture.id()) {}!!
            val row = receipt.after; val p = receipt.proof
            val raw = TypedNoSubmit03Wire.challengeRequest(row, p, f.epoch)
            assertEquals(16, Profile03Json.noSubmitObject(raw).size)
            val bad = listOf(String(raw).replace("\"v\":1", "\"v\":1,\"v\":1"), String(raw).replace("\"connection_epoch\":12", "\"connection_epoch\":\"12\""),
                String(raw).replace("\"v\":1", "\"v\":1,\"unknown\":0"), String(raw).replace("\"segment_count\":1", "\"segment_count\":null"),
                String(raw).replace("\"closed_ms\":\"${TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(row.closureB64url!!)).closedMs}\"", "\"closed_ms\":\"9223372036854775808\""))
            for (text in bad) assertThrows(Exception::class.java) {
                val fields = Profile03Json.noSubmitObject(text.toByteArray())
                require(fields.keys == Profile03Json.noSubmitObject(raw).keys && fields["connection_epoch"] == Profile03Json.Integer(f.epoch))
                Profile03Json.decimal(fields, "closed_ms")
            }
            assertThrows(IllegalArgumentException::class.java) { Profile03Json.noSubmitObject(ByteArray(4097) { 32 }) }
        } }
    }
    @Test fun originalAndProofLeasesRemainDistinctAndDoNotRelabelTheStoredCommand() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val c = ready.proof.challenge().core
            assertEquals(11L, c.number(0)); assertEquals(12L, c.number(2))
            assertFalse(c.digest(2).contentEquals(c.digest(3)))
            assertArrayEquals(f.command.bytes(), ready.action.row.command().bytes())
            assertArrayEquals(f.session(12), c.digest(3)); ready.context.requireCurrent(ready.action.row, ready.proof)
        } }
    }
}

internal fun <T> withDatabase(block: (SmsJournalDatabase) -> T): T {
    val db = androidx.room.Room.inMemoryDatabaseBuilder(org.robolectric.RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build()
    return try { block(db) } finally { db.close() }
}
