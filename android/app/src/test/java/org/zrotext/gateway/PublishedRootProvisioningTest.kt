// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import javax.crypto.KeyGenerator
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Same-instance CI consumer only. Synthetic AES custody is not Android hardware proof. */
@RunWith(RobolectricTestRunner::class) @Config(sdk = [34])
class PublishedRootProvisioningTest {
    private class EncryptedMemory : Draft02TrustStore.Storage, Draft02TrustStore.Session {
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val aad = "synthetic provisioning root state".toByteArray()
        private var state = Draft02TrustStore.KeyState.ABSENT
        var ciphertext: ByteArray? = null
        var creations = 0
        override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = action(this)
        override fun keyState() = state
        override fun read() = ciphertext?.copyOf()
        override fun createKey() { check(state == Draft02TrustStore.KeyState.ABSENT); creations++; state = Draft02TrustStore.KeyState.READY }
        override fun seal(plaintext: ByteArray) = Draft02RootStateCipher.seal(key, aad, plaintext)
        override fun open(ciphertext: ByteArray) = Draft02RootStateCipher.open(key, aad, ciphertext)
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) { preCommit(); this.ciphertext = ciphertext.copyOf() }
    }
    private fun session(account: String, store: EncryptedMemory, current: () -> Unit) =
        ConversationEnrollmentSession(account, current, { error("Reader creation forbidden") }, store, { error("Content protection forbidden") })
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected provisioning refusal") }
        catch (_: IllegalArgumentException) {} catch (_: IllegalStateException) {}
    }
    @Test fun encryptedSyntheticRootStoreRejectsRecordSubstitution() {
        val f = ConversationEnrollmentFixture()
        val store = EncryptedMemory()
        session(f.account, store) {}.use { s ->
            val compared = s.reviewRoot(f.pin).fingerprintHex
            assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, s.enrollComparedRoot(compared, true).status)
        }
        store.ciphertext!![store.ciphertext!!.lastIndex] = (store.ciphertext!!.last().toInt() xor 1).toByte()
        assertEquals(Draft02TrustStore.Status.CORRUPT, Draft02TrustStore(store).inspect().status)
    }
    @Test fun creatorWithdrawalAtComparisonCannotCreateRootCustody() {
        val f = ConversationEnrollmentFixture(); val store = EncryptedMemory(); var live = true
        session(f.account, store) { check(live) }.use { s ->
            val compared = s.reviewRoot(f.pin).fingerprintHex
            live = false
            denied { s.enrollComparedRoot(compared, true) }
        }
        assertEquals(0, store.creations); assertNull(store.ciphertext)
    }
    @Test fun actualPublishedCustodyPinRequiresIndependentComparisonAndCurrentCreator() {
        val raw = System.getenv("ZT_COMPOSED_ROOT_FIXTURE")
        // Ordinary JVM runs have no live server. The managed CI driver supplies
        // this bounded input and separately requires this exact test to pass.
        if (System.getProperty("zrotext.composedRootRequired") == "true") checkNotNull(raw)
        assumeNotNull(raw)
        check(raw!!.toByteArray().size <= 2048)
        val f = JSONObject(raw)
        check(f.keys().asSequence().toSet() == setOf("accountId", "rootPin", "comparedFingerprint", "port", "controlToken"))
        val pin = Base64.getDecoder().decode(f.getString("rootPin"))
        check(pin.size == 94 && Base64.getEncoder().encodeToString(pin) == f.getString("rootPin"))
        val account = f.getString("accountId")
        check(ByteBuffer.wrap(pin, 5, 16).let { UUID(it.long, it.long).toString() } == account)
        check(ByteBuffer.wrap(pin, 21, 8).long == 1L)
        val compared = f.getString("comparedFingerprint")
        check(compared.matches(Regex("[0-9a-f]{64}")))
        val port = f.getInt("port"); check(port in 1..65535)
        val token = f.getString("controlToken"); check(token.matches(Regex("[0-9a-f]{64}")))
        fun control(operation: String): JSONObject {
            check(operation in setOf("root_current", "revoke_creator"))
            val connection = URI("http", null, "127.0.0.1", port, "/__fixture/owner-setup", null, null).toURL().openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = 5000; connection.readTimeout = 5000
                connection.instanceFollowRedirects = false; connection.requestMethod = "POST"; connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("x-zrotext-fixture-token", token)
                val body = JSONObject().put("version", 1).put("operation", operation).toString().toByteArray()
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
                check(connection.responseCode == 200)
                val bytes = connection.inputStream.use { it.readNBytes(2049) }; check(bytes.size <= 2048)
                val result = JSONObject(String(bytes, Charsets.UTF_8))
                check(result.getInt("version") == 1 && result.getBoolean("synthetic") && result.getString("operation") == operation)
                check(result.keys().asSequence().toSet() == setOf("version", "synthetic", "operation", if (operation == "root_current") "current" else "ok"))
                return result
            } finally { connection.disconnect() }
        }
        val current = { check(control("root_current").getBoolean("current")) }
        val missing = EncryptedMemory()
        session(account, missing, current).use { s -> s.reviewRoot(pin); denied { s.enrollComparedRoot(compared, false) } }
        assertEquals(0, missing.creations)
        val substituted = pin.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        session(account, EncryptedMemory(), current).use { denied { it.reviewRoot(substituted) } }
        val store = EncryptedMemory()
        session(account, store, current).use { s ->
            assertEquals(compared, s.reviewRoot(pin).fingerprintHex)
            assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, s.enrollComparedRoot(compared, true).status)
        }
        val saved = Draft02TrustStore(store).inspect()
        assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, saved.status)
        assertArrayEquals(pin, saved.snapshot!!.pin)
        assertEquals(0L, saved.snapshot!!.version)
        assertFalse(store.ciphertext!!.contentEquals(saved.snapshot!!.bytes()))
        val revokedStore = EncryptedMemory()
        session(account, revokedStore, current).use { s ->
            s.reviewRoot(pin)
            assertTrue(control("revoke_creator").getBoolean("ok"))
            assertFalse(control("root_current").getBoolean("current"))
            denied { s.enrollComparedRoot(compared, true) }
        }
        assertEquals(0, revokedStore.creations); assertNull(revokedStore.ciphertext)
        // This marker contains neither the public fixture nor its private control capability.
        println("COMPOSED_PHONE_ROOT_ADMISSION_PASS")
    }
}
