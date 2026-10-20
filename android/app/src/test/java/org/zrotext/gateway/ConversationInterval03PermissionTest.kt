// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ConversationInterval03PermissionTest {
    @Test fun activeOriginalProofsRequireExactPendingFetchAndIndependentlySelectedContext(): Unit = ConversationInterval03TestFixture().use { v ->
        val p = v.decode(v.permission()); p.requireRequest("fetch", v.f.attempt)
        val roles = p.verifyCurrent(v.selected(), Profile03ExecutionFixture.point(v.f.reader),
            Profile03ExecutionFixture.unhex(v.f.session.originHash), v.f.now)
        assertArrayEquals(Profile03ExecutionFixture.point(v.f.eventSigning), roles.phonePoint())
        assertThrows(Exception::class.java) { p.requireRequest("fetch", UUID(0, 888)) }
        assertThrows(Exception::class.java) { p.requireRequest("interval_status", v.f.attempt) }
        assertThrows(Exception::class.java) { p.verifyCurrent(v.selected(), Profile03ExecutionFixture.point(v.f.reader), ByteArray(32), v.f.now) }
        v.f.line.callback()
        assertThrows(Exception::class.java) { p.verifyCurrent(v.selected(), Profile03ExecutionFixture.point(v.f.reader),
            Profile03ExecutionFixture.unhex(v.f.session.originHash), v.f.now) }
    }
    @Test fun exactNullSequencesDescribePendingOriginalsAndCanNeverSatisfyFetch(): Unit = ConversationInterval03TestFixture().use { v ->
        for (phase in listOf("reserved", "requested", "install_pending", "active")) {
            val proof = v.proof(); val kind = "interval_challenge"
            assertEquals(phase, v.decode(v.permission(proof, phase, kind, proof.statement.receipt)).phase)
            if (phase != "active") assertThrows(Exception::class.java) { v.decode(v.permission(proof, phase)) }
        }
        val active = v.permission()
        for (name in listOf("owner_signature", "phone_signature", "installed_signature", "requested_ms", "approved_ms", "installed_ms"))
            assertThrows(Exception::class.java) { v.decode(JSONObject(active.toString()).put(name, JSONObject.NULL)) }
        assertThrows(Exception::class.java) { v.decode(JSONObject(active.toString()).put("requested_ms", 100001)) }
        assertThrows(Exception::class.java) { v.decode(JSONObject(active.toString()).put("approved_ms", "100000")) }
    }
    @Test fun closedMappingSetAndStrictScalarsCannotBeFilledFromCiphertextOrUnsignedExtraFields(): Unit = ConversationInterval03TestFixture().use { v ->
        val original = v.permission()
        for (changed in listOf(JSONObject(original.toString()).put("extra", "unsupported"),
            JSONObject(original.toString()).put("v", "1"), JSONObject(original.toString()).put("permission_expires_ms", "0100600"),
            JSONObject(original.toString()).put("owner_signature", ConversationInterval03TestFixture.b64(ByteArray(64))),
            JSONObject(original.toString()).put("device_session_digest", ConversationInterval03TestFixture.b64(ByteArray(32) { 1 })),
            JSONObject(original.toString()).put("readers", JSONArray().put(JSONObject()))))
            assertThrows(Exception::class.java) { v.decode(changed) }
        assertThrows(Exception::class.java) { v.decode(JSONObject(original.toString()).apply { remove("readers") }) }
    }
    @Test fun permissionDeadlineClockAndSamePrimaryComparisonAreIndependentOfSignatureValidity(): Unit = ConversationInterval03TestFixture().use { v ->
        val p = v.decode(v.permission())
        fun verify(p: ConversationInterval03Permission, now: Long = v.f.now) = p.verifyCurrent(v.selected(),
            Profile03ExecutionFixture.point(v.f.reader), Profile03ExecutionFixture.unhex(v.f.session.originHash), now)
        assertThrows(Exception::class.java) { verify(p, v.f.now - 1) }
        assertThrows(Exception::class.java) { verify(p, p.permissionExpiresMs) }
        assertThrows(Exception::class.java) { verify(v.decode(v.permission().put("compared_ms", (v.f.now - 1).toString()))) }
        assertThrows(Exception::class.java) { verify(v.decode(v.permission().put("permission_expires_ms", "100801"))) }
    }
    @Test fun jsonArrayAndNullSupportIsRestrictedToExactNewPathsWithDuplicateChecksBeforeCoercion() {
        fun parse(text: String) = Profile03Json.objectValue(text.toByteArray())
        assertNotNull(parse("""{"interval_permission":{"readers":[],"owner_signature":null}}"""))
        assertNotNull(parse("""{"approved_ms":null,"installed_ms":null}"""))
        for (text in listOf("""{"owner_signature":null}""", """{"v":null}""", """{"readers":[]}""",
            """{"x":{"readers":[]}}""", """{"interval_permission":{"readers":[null]}}""",
            """{"interval_permission":{"readers":[],"readers":[]}}""", """{"interval_permission":{"requested_ms":false}}""",
            """{"interval_permission":{"x":null}}""", """{"interval_permission":{"x":{"requested_ms":null}}}"""))
            assertThrows(Exception::class.java) { parse(text) }
    }
}
