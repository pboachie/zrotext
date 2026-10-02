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

internal class ConversationEnrollmentFixture {
    val json = JSONObject(javaClass.classLoader!!.getResourceAsStream("draft02-genesis.json")!!.bufferedReader().use { it.readText() })
    val pin: ByteArray = Base64.getDecoder().decode(json.getString("root_pin_b64"))
    val manifest: ByteArray = Base64.getDecoder().decode(json.getString("manifest_b64"))
    val now = json.getLong("now_ms")
    val account = id(pin.copyOfRange(5, 21))
    val storage = Memory()
    var live = true
    var readers = 0
    var protection = 0
    var security = PayloadKeySecurity.TRUSTED_ENVIRONMENT
    var creating: () -> Unit = {}
    fun session() = ConversationEnrollmentSession(account, { check(live) }, {
        readers++; creating(); DevicePayloadPublic(pin.copyOfRange(29, 94), ByteArray(32) { 1 }, security)
    }, storage, { protection++ })
    fun compared(session: ConversationEnrollmentSession) = session.reviewRoot(pin).fingerprintHex
    fun trust(): Draft02TrustStore = Draft02TrustStore(storage)
    fun enrolled(): Draft02TrustStore {
        val session = session(); val fp = compared(session)
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, session.enrollComparedRoot(fp, true).status)
        return trust()
    }
    fun id(bytes: ByteArray): String = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long).toString() }
    class Memory : Draft02TrustStore.Storage, Draft02TrustStore.Session {
        var key = Draft02TrustStore.KeyState.ABSENT
        var data: ByteArray? = null
        var creations = 0
        var commits = 0
        var beforeCommit: () -> Unit = {}
        override fun <T> locked(action: Draft02TrustStore.Session.() -> T) = action(this)
        override fun keyState() = key
        override fun read() = data?.copyOf()
        override fun createKey() { check(key == Draft02TrustStore.KeyState.ABSENT); creations++; key = Draft02TrustStore.KeyState.READY }
        override fun seal(plaintext: ByteArray) = plaintext.copyOf()
        override fun open(ciphertext: ByteArray) = ciphertext.copyOf()
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) {
            beforeCommit(); preCommit(); data = ciphertext.copyOf(); commits++
        }
    }
}

@RunWith(RobolectricTestRunner::class) @Config(sdk = [34])
class ConversationEnrollmentSessionTest {
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected refusal") } catch (_: IllegalArgumentException) {} catch (_: IllegalStateException) {}
    }
    @Test fun constructionAndCloseNeverProvisionAReaderRootOrProtection() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); session.close()
        denied { session.enrollReader() }
        assertEquals(0, f.readers); assertEquals(0, f.protection); assertEquals(0, f.storage.creations)
    }
    @Test fun explicitEligibleReaderEnrollmentPreparesProtectionWithoutGrantingTrustOrContentConsent() {
        val f = ConversationEnrollmentFixture(); f.session().enrollReader()
        assertEquals(1, f.readers); assertEquals(1, f.protection)
        assertEquals(Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON, f.trust().inspect().status)
    }
    @Test fun softwareOrUnknownReaderNeverPreparesProtection() {
        for (security in listOf(PayloadKeySecurity.SOFTWARE, PayloadKeySecurity.UNKNOWN, PayloadKeySecurity.UNKNOWN_SECURE)) {
            val f = ConversationEnrollmentFixture(); f.security = security
            denied { f.session().enrollReader() }; assertEquals(0, f.protection)
        }
    }
    @Test fun cancellationWhileCreatingReaderNeverPublishesOrPreparesProtection() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); f.creating = { session.close() }
        denied { session.enrollReader() }; assertEquals(0, f.protection)
    }
    @Test fun independentComparisonIsSeparateAndDoesNotAutoFillOrPersist() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); f.compared(session)
        denied { session.enrollComparedRoot("00".repeat(32), true) }
        assertEquals(0, f.storage.creations); assertNull(f.storage.data)
    }
    @Test fun decliningIndependentComparisonNeverCreatesRootProtection() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); val fp = f.compared(session)
        denied { session.enrollComparedRoot(fp, false) }; assertEquals(0, f.storage.creations)
    }
    @Test fun rootEnrollmentPersistsOnlyAnUnfreshGenesisPinAndNeverCreatesReader() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); val fp = f.compared(session)
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, session.enrollComparedRoot(fp, true).status)
        assertEquals(0L, f.trust().inspect().snapshot!!.version); assertEquals(0, f.readers)
        denied { f.compared(session) }; assertEquals(1, f.storage.creations)
    }
    @Test fun foregroundCancellationAtRootPrecommitCannotPersistAnEnrollment() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); val fp = f.compared(session)
        f.storage.beforeCommit = { session.close() }
        denied { session.enrollComparedRoot(fp, true) }; assertNull(f.storage.data)
        assertEquals(Draft02TrustStore.Status.RECOVERY_REQUIRED, f.trust().inspect().status)
    }
    @Test fun authenticatedHostLossAtRootPrecommitCannotPersistAnEnrollment() {
        val f = ConversationEnrollmentFixture(); val session = f.session(); val fp = f.compared(session)
        f.storage.beforeCommit = { f.live = false }
        denied { session.enrollComparedRoot(fp, true) }; assertNull(f.storage.data)
    }
    @Test fun importedRootCannotSelectAnotherAccount() {
        val f = ConversationEnrollmentFixture(); val pin = f.pin.copyOf(); pin[5] = (pin[5].toInt() xor 1).toByte()
        denied { f.session().reviewRoot(pin) }; assertEquals(0, f.storage.creations)
    }
    @Test fun publicChainImportIsCanonicalAndBoundedBeforeSetup() {
        val f = ConversationEnrollmentFixture(); val encoded = Base64.getEncoder().encodeToString(f.manifest)
        assertArrayEquals(f.manifest, ConversationEnrollmentSession.decodeChain(encoded).single())
        assertTrue(ConversationEnrollmentSession.decodeChain("").isEmpty())
        denied { ConversationEnrollmentSession.decodeChain((1..65).joinToString("\n") { encoded }) }
        denied { ConversationEnrollmentSession.decodeChain("AA==") }
    }
}
