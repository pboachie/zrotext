// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Reader leg of the sealed downgrade/leakage acceptance harness (issue #632).
 * The database-persisted envelopes handed over by the Rust boundary lane carry
 * a synthetic marker as their client-side plaintext. Only the authorized
 * device reader may recover that marker; the raw persisted bytes, every other
 * reader and every wrong trust input must fail closed. Synthetic software keys
 * and pinned time only; no radio, hardware or carrier involvement. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedBoundaryCanaryTest {
    private class Fixture {
        val persisted = readFixture("ZT_INTEROP_CANARY_FIXTURE").also {
            require(it.get("fixtureVersion") == 1) { "Unsupported boundary fixture version" }
        }
        // Caller-selected expected values supplied separately; never inferred from envelope bytes.
        val expected = readFixture("ZT_INTEROP_CANARY_CONTEXT")
        val now = expected.getLong("now")
        val canaryText = expected.getString("canaryText")
        fun bytes(name: String) = hex(expected.getString(name))
        fun authority() = Draft02ManifestAuthority.verify(
            bytes("rootPin"), hex(persisted.getString("manifest")), Draft02ManifestAuthority.Trust(
                bytes("accountId"), bytes("rootFingerprint"), expected.getLong("generation"),
                Draft02ManifestAuthority.Position.after(expected.getLong("previousVersion"), bytes("previousDigest"))), now)
        fun request(message: ByteArray = bytes("messageId")) = Draft02ManifestAuthority.Request(
            Draft02ManifestAuthority.Direction.OUTBOUND, bytes("accountId"), message,
            bytes("deviceId"), bytes("lineId"), "+12".toByteArray(Charsets.US_ASCII),
            bytes("signerKeyId"), listOf(
                Draft02ManifestAuthority.Reader(1, bytes("deviceKeyId")),
                Draft02ManifestAuthority.Reader(2, bytes("archiveKeyId"))))
        fun proof(message: ByteArray = bytes("messageId"), envelopeField: String = "persistedOutboundEnvelope"): Draft02OutboundEnvelope {
            val source = hex(persisted.getString(envelopeField))
            return Draft02OutboundEnvelope.verify(source, authority(), request(message)) { now }
        }
        fun cek(proof: Draft02OutboundEnvelope, scalar: ByteArray = bytes("devicePrivateScalar")): ByteArray {
            val parts = proof.parts()
            val params = AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec("secp256r1")); getParameterSpec(ECParameterSpec::class.java)
            }
            val privateKey = try {
                require(scalar.size == 32) { "Synthetic recipient scalar width" }
                KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), params))
            } finally { scalar.fill(0) }
            val dh = KeyAgreement.getInstance("ECDH").run {
                init(privateKey); doPhase(DevicePayloadKeyStore.decodePoint(parts.enc), true); generateSecret()
            }
            try {
                val secret = Draft02PublicJcaKeystoreHpke.deriveSharedSecret(dh, parts.enc, bytes("devicePoint"))
                try {
                    val info = Draft02PublicJcaKeystoreHpke.buildDeviceInfo(parts.header, parts.protected, 1, parts.keyId)
                    try {
                        val material = Draft02PublicJcaKeystoreHpke.deriveKeyMaterial(secret, info)
                        try {
                            return Cipher.getInstance("AES/GCM/NoPadding").run {
                                init(Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "AES"), GCMParameterSpec(128, material.nonce))
                                updateAAD(byteArrayOf()); doFinal(parts.wrap)
                            }
                        } finally { material.clear() }
                    } finally { info.fill(0) }
                } finally { secret.fill(0) }
            } finally { dh.fill(0) }
        }
        fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
            if (needle.isEmpty() || haystack.size < needle.size) return false
            return (0..haystack.size - needle.size).any { start ->
                (needle.indices).all { haystack[start + it] == needle[it] }
            }
        }
    }

    @Test fun authorizedDeviceReaderRecoversTheMarkerFromPersistedCiphertext() {
        val fixture = Fixture()
        val clear = Draft02Body.open(fixture.proof(), fixture.cek(fixture.proof()))
        try {
            assertEquals("The authorized reader must obtain exactly the marker plaintext", fixture.canaryText, String(clear))
        } finally { clear.fill('\u0000') }
    }

    @Test fun authorizedDeviceReaderRecoversTheMarkerFromTheProductionComposerEnvelope() {
        val fixture = Fixture()
        val proof = fixture.proof(fixture.bytes("productionMessageId"), "persistedProductionEnvelope")
        val clear = Draft02Body.open(proof, fixture.cek(proof))
        try {
            assertEquals(fixture.canaryText, String(clear))
        } finally { clear.fill('\u0000') }
    }

    @Test fun persistedEnvelopeBytesCarryNoMarkerPlaintext() {
        val fixture = Fixture()
        val marker = fixture.canaryText.toByteArray(Charsets.UTF_8)
        for (field in listOf("persistedInboundEnvelope", "persistedOutboundEnvelope", "persistedProductionEnvelope")) {
            val raw = hex(fixture.persisted.getString(field))
            assertFalse("Database-persisted $field exposes marker plaintext", fixture.contains(raw, marker))
        }
    }

    @Test fun wrongReaderScalarCannotUnwrapTheCanaryEnvelope() {
        val fixture = Fixture()
        val scalar = ByteArray(32).apply { this[31] = 1 }
        assertFalse(MessageDigest.isEqual(scalar, fixture.bytes("devicePrivateScalar")))
        assertThrows(Exception::class.java) { fixture.cek(fixture.proof(), scalar) }
        assertTrue(scalar.all { it == 0.toByte() })
    }

    @Test fun canaryEnvelopeFailsClosedOutsideItsMessageContext() {
        val fixture = Fixture()
        val message = fixture.bytes("messageId").apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { fixture.proof(message) }
    }

    companion object {
        private const val MAX_FIXTURE_BYTES = 1_048_576

        private fun readFixture(variable: String): JSONObject {
            val path = requireNotNull(System.getenv(variable)?.takeIf { it.isNotBlank() }) {
                "Required boundary fixture path is missing"
            }
            val file = File(path)
            require(file.isFile) { "Boundary fixture file is missing" }
            val bytes = file.inputStream().use { it.readNBytes(MAX_FIXTURE_BYTES + 1) }
            require(bytes.size in 1..MAX_FIXTURE_BYTES) { "Boundary fixture size" }
            return JSONObject(bytes.toString(Charsets.UTF_8))
        }

        private fun hex(text: String): ByteArray {
            require(text.length % 2 == 0 && text.all { it in "0123456789abcdefABCDEF" })
            return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}
