// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ClosedUnacceptedTest {
    @Test fun sharedStructuralVectorUsesTheShippingClosedParserAndExactCoreChain() {
        val vector = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-closed-unaccepted-01.json")!!.use {
            org.json.JSONObject(it.bufferedReader().readText())
        }
        val rows = Profile03ClosedUnaccepted.decode(Profile03Json.objectValue(
            ("{\"closed_unaccepted\":" + vector.getJSONArray("closed_unaccepted") + "}").toByteArray()))
        val coreText = vector.getString("target_core")
        val core = Profile03ElectionEncoding.decode(coreText, 500)
        fun id(at: Int) = ByteBuffer.wrap(core, at, 16).let { UUID(it.long, it.long).toString() }
        fun number(at: Int) = ByteBuffer.wrap(core, at, 8).long
        fun digest(at: Int) = Draft02OutboundPreparation.hex(core.copyOfRange(at, at + 32))
        val target = Profile03ElectionRecord(id(56), id(8), id(24), id(40), id(72),
            vector.getString("target_new_binding_id"), number(88), number(96), digest(136), digest(256), digest(400), 1, 1, coreText)
        assertEquals(vector.getString("target_challenge_id"), target.challengeId)
        Profile03ClosedUnaccepted.requireChain(target, rows, vector.getString("authenticated_now_ms").toLong())
        assertEquals(2, rows.size)
    }
    @Test fun completeLinkedChainAcceptsUnknownIntermediateAndDifferentFreshSessionWithoutInventingAcceptance() = Profile03RecoveryFixture().use { r ->
        val parsed = Profile03ClosedUnaccepted.decode(Profile03Json.objectValue(Profile03Json.render(r.wire())))
        assertEquals(r.closures, parsed)
        Profile03ClosedUnaccepted.requireChain(r.third, parsed, r.now)
        Profile03ClosedUnaccepted.requireChain(r.first, emptyList(), r.f.now)
        assertNull(r.dao.find(r.second.challengeId))
        assertEquals("Profile03UnacceptedClosureRecord(server-history-only)", parsed.first().toString())
    }
    @Test fun allOriginalScopeFieldsMustMatchDespiteStructurallyValidNewCores() = Profile03RecoveryFixture().use { r ->
        // Account/device/line, original binding/generation, proof/root/vault/02 manifest,
        // next version, reader/enrollment/original approval key and canonical origin.
        for (at in listOf(8, 24, 40, 72, 88, 104, 136, 168, 176, 184, 216, 256, 288, 320, 400)) {
            val original = r.closures.first()
            val changed = Profile03ElectionEncoding.decode(original.coreB64url, 500)
            changed[at] = (changed[at].toInt() xor 1).toByte()
            assertThrows(IllegalArgumentException::class.java) {
                Profile03ClosedUnaccepted.requireChain(r.third, listOf(original.copy(coreB64url =
                    Profile03ElectionEncoding.encode(changed)), r.closures.last()), r.now)
            }
        }
        // A freshly signed candidate manifest digest is allowed to change; its real signature
        // is independently checked by Profile03SetupRuntime, never by this structural helper.
        val fresh = r.mutateCore(r.third) { it[224] = (it[224].toInt() xor 1).toByte() }
        Profile03ClosedUnaccepted.requireChain(fresh, r.closures, r.now)
    }
    @Test fun closureMustBeExactSuccessorIssuedTimeAfterOriginalExpiryAndTargetMustBeLive() = Profile03RecoveryFixture().use { r ->
        val first = r.closures.first()
        for (bad in listOf(first.copy(closedUnacceptedMs = first.closedUnacceptedMs - 1),
            first.copy(closedUnacceptedMs = first.closedUnacceptedMs + 1),
            first.copy(supersededByChallengeId = r.third.challengeId))) {
            assertThrows(IllegalArgumentException::class.java) { Profile03ClosedUnaccepted.requireChain(r.third, listOf(bad, r.closures.last()), r.now) }
        }
        val tooEarly = r.mutateCore(r.second) {
            ByteBuffer.wrap(it, 384, 8).putLong(100_500)
            ByteBuffer.wrap(it, 392, 8).putLong(100_900)
        }
        val chain = listOf(Profile03RecoveryFixture.close(r.first, tooEarly, 30), Profile03RecoveryFixture.close(tooEarly, r.third, 31))
        assertThrows(IllegalArgumentException::class.java) { Profile03ClosedUnaccepted.requireChain(r.third, chain, r.now) }
        for (now in listOf(102_999L, 104_000L, 104_001L))
            assertThrows(IllegalArgumentException::class.java) { Profile03ClosedUnaccepted.requireChain(r.third, r.closures, now) }
    }
    @Test fun duplicateReorderedDecreasingOrForeignChainsRefuse() = Profile03RecoveryFixture().use { r ->
        val a = r.closures.first(); val b = r.closures.last()
        for (rows in listOf(listOf(b, a), listOf(a, a), List(17) { a },
            listOf(a, b.copy(openingId = a.openingId)), listOf(a, b.copy(newBindingId = a.newBindingId)),
            listOf(a.copy(supersededByChallengeId = UUID(0, 98).toString()), b),
            listOf(a.copy(challengeId = r.third.challengeId), b))) {
            assertThrows(IllegalArgumentException::class.java) { Profile03ClosedUnaccepted.requireChain(r.third, rows, r.now) }
        }
        val decreasing = r.mutateCore(r.second) { ByteBuffer.wrap(it, 96, 8).putLong(r.third.newGeneration) }
        assertThrows(IllegalArgumentException::class.java) { Profile03ClosedUnaccepted.requireChain(r.third,
            listOf(Profile03RecoveryFixture.close(r.first, decreasing, 30), Profile03RecoveryFixture.close(decreasing, r.third, 31)), r.now) }
    }
    @Test fun wireRequiresClosedCanonicalSixFieldsAndNoCoercedCountersOrUuid() = Profile03RecoveryFixture().use { r ->
        val item = Profile03Json.closedUnaccepted(r.wire()).first()
        val invalid = listOf(item - "opening_id", item + ("accepted" to "yes"),
            item + ("opening_id" to UUID(0, 0).toString()), item + ("new_binding_id" to "1-1-1-1-1"),
            item + ("closed_unaccepted_ms" to "0102000"), item + ("closed_unaccepted_ms" to "0"),
            item + ("closed_unaccepted_ms" to Profile03Json.Integer(102_000)), item + ("core" to (r.first.coreB64url + "=")))
        for (bad in invalid) assertThrows(Exception::class.java) {
            Profile03ClosedUnaccepted.decode(mapOf("closed_unaccepted" to listOf(bad)))
        }
        for (input in listOf(emptyMap(), mapOf("closed_unaccepted" to "[]"), mapOf("closed_unaccepted" to listOf("bad"))))
            assertThrows(Exception::class.java) { Profile03ClosedUnaccepted.decode(input) }
    }
    @Test fun strictJsonAllowsOnlyRootClosureObjectArrayWithSixteenMembers() {
        fun decode(s: String) = Profile03Json.objectValue(s.toByteArray())
        assertEquals(emptyList<Map<String, Any>>(), Profile03Json.closedUnaccepted(decode("""{"closed_unaccepted":[]}""")))
        assertEquals(16, Profile03Json.closedUnaccepted(decode("{\"closed_unaccepted\":[${List(16) { "{}" }.joinToString(",")}]}")).size)
        for (bad in listOf("""{"other":[]}""", """{"x":{"closed_unaccepted":[]}}""",
            """{"closed_unaccepted":[[]]}""", """{"closed_unaccepted":[1]}""", """{"closed_unaccepted":[null]}""",
            """{"closed_unaccepted":[{},]}""", """{"closed_unaccepted":[{"x":"a","x":"b"}]}""",
            """{"closed_unaccepted":[],"closed_unaccepted":[]}""",
            "{\"closed_unaccepted\":[${List(17) { "{}" }.joinToString(",")}]}",
            """{"closed_unaccepted":[{"closed_unaccepted":[]}]}"""))
            assertThrows(IllegalArgumentException::class.java) { decode(bad) }
        assertThrows(IllegalArgumentException::class.java) { Profile03Json.render(mapOf("x" to mapOf("closed_unaccepted" to emptyList<Any>()))) }
        assertThrows(IllegalArgumentException::class.java) { Profile03Json.render(mapOf("other" to emptyList<Any>())) }
    }
}
