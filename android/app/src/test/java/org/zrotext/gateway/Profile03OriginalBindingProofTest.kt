// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03OriginalBindingProofTest {
    private val vector = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-activation-evidence-01.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun value(name: String) = vector.getString(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val registration get() = value("registration_evidence")
    private val activation get() = value("activation_evidence")
    private val registrationPrefix = "ZTSE/line/payload-profile/registration-evidence/v1\u0000".toByteArray(Charsets.US_ASCII).size + 4
    private val activationPrefix = "ZTSE/line/payload-profile/activation-evidence/v1\u0000".toByteArray(Charsets.US_ASCII).size + 4
    private val pin get() = registration.copyOfRange(registrationPrefix + 4 +
        "ZTSE/line/owner-key/register/v1\u0000".length + 5 * 16 + 8 + 16 + 32 + 16,
        registrationPrefix + 4 + "ZTSE/line/owner-key/register/v1\u0000".length + 5 * 16 + 8 + 16 + 32 + 16 + 94)
    private val enrollment get() = activation.copyOfRange(activationPrefix + 32, activationPrefix + 97)
    private val reader get() = value("selected_reader_key_id")
    private fun core() = ByteArray(500).apply {
        byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3).copyInto(this)
        value("account_id").copyInto(this, 8); value("device_id").copyInto(this, 24); value("line_id").copyInto(this, 40)
        value("old_binding_id").copyInto(this, 72); ByteBuffer.wrap(this).putLong(88, 1)
        value("old_binding_proof_digest").copyInto(this, 104); value("root_fingerprint").copyInto(this, 136)
        reader.copyInto(this, 256); value("paired_signing_key_id").copyInto(this, 288)
        MessageDigest.getInstance("SHA-256").digest(vector.getString("origin").toByteArray(Charsets.UTF_8)).copyInto(this, 400)
    }
    private fun verify(r: ByteArray = registration, a: ByteArray = activation, c: ByteArray = core(),
        p: ByteArray = pin, e: ByteArray = enrollment, selected: ByteArray = reader, origin: String = vector.getString("origin")) =
        Profile03OriginalBindingProof.verify(r, a, c, p, e, selected, origin)

    @Test fun independentOriginalProofVectorPreservesValidHighSAndExactOldBindingDigest() {
        assertTrue(vector.getBoolean("device_signature_is_high_s"))
        val proof = verify()
        assertArrayEquals(value("old_binding_proof_digest"), proof.oldBindingProofDigest())
        assertArrayEquals(enrollment, proof.devicePoint())
        assertEquals(3000L, proof.acceptedMs)
        assertEquals("Profile03OriginalBindingProof(historical-public-evidence)", proof.toString())
        val copy = proof.oldBindingProofDigest(); copy.fill(0)
        assertArrayEquals(value("old_binding_proof_digest"), proof.oldBindingProofDigest())
    }
    @Test fun changedOriginalStatementsOrSignaturesCannotBeReplacedByTheirDigests() {
        val deviceAt = activationPrefix + 32 + 65 + 65
        val deviceDerAt = deviceAt + 255 + 2
        val deviceDerSize = (ByteBuffer.wrap(activation, deviceAt + 255, 2).short.toInt() and 65535)
        val ownerAt = deviceDerAt + deviceDerSize
        for (at in listOf(deviceAt, deviceAt + 30, deviceAt + 100, deviceAt + 254,
            deviceDerAt + deviceDerSize - 1, ownerAt, ownerAt + 313, activation.size - 9)) {
            val changed = activation.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() }
            assertTrue("original offset $at", runCatching { verify(a = changed) }.isFailure)
        }
    }
    @Test fun changedOriginalRootAccountReaderEnrollmentOriginOrBindingRefuses() {
        for (at in listOf(8, 24, 40, 72, 88, 104, 136, 256, 288, 400)) {
            assertTrue(runCatching { verify(c = core().apply { this[at] = (this[at].toInt() xor 1).toByte() }) }.isFailure)
        }
        assertTrue(runCatching { verify(origin = "https://different.example.test") }.isFailure)
        assertTrue(runCatching { verify(selected = reader.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() }) }.isFailure)
        assertTrue(runCatching { verify(e = pin.copyOfRange(29, 94)) }.isFailure)
        assertTrue(runCatching { verify(p = pin.copyOf().apply { this[5] = 99 }) }.isFailure)
    }
    @Test fun noncanonicalFramingMalformedOriginalRegistrationAndTrailingBytesRefuse() {
        for (changed in listOf(registration + byteArrayOf(0), registration.copyOf(registration.size - 1),
            registration.copyOf().apply { this[0] = 0 }, registration.copyOf().apply { this[registrationPrefix] = 127 },
            registration.copyOf().apply { this[registrationPrefix + 4 + 50] = 99 },
            registration.copyOf().apply { ByteBuffer.wrap(this).putLong(this.size - 8, Long.MAX_VALUE) })) {
            assertTrue(runCatching { verify(r = changed) }.isFailure)
        }
        for (changed in listOf(activation + byteArrayOf(0), activation.copyOf(activation.size - 1),
            activation.copyOf().apply { this[0] = 0 }, activation.copyOf().apply { this[activationPrefix] = 0 })) {
            assertTrue(runCatching { verify(a = changed) }.isFailure)
        }
    }
}
