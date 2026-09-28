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

/** SDK/PostgreSQL ciphertext interoperability with synthetic software keys and time.
 * This is not the hardware preparation entry, a trusted-time provider or radio authorization. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedSdkPostgresInteropTest {
    private class Fixture {
        val input = readFixture("ZT_INTEROP_TEST_FIXTURE").also {
            require(it.get("fixtureVersion") == 1) { "Unsupported interoperability fixture version" }
        }
        // Caller-selected expected values supplied separately; never inferred from envelope bytes.
        val expected = readFixture("ZT_INTEROP_TEST_CONTEXT")
        val now = expected.getLong("now")
        fun bytes(name: String) = hex(expected.getString(name))
        fun authority(fingerprint: ByteArray = bytes("rootFingerprint"), manifestField: String = "manifest") =
            Draft02ManifestAuthority.verify(
                bytes("rootPin"), hex(input.getString(manifestField)), Draft02ManifestAuthority.Trust(
                    bytes("accountId"), fingerprint, expected.getLong("generation"),
                    Draft02ManifestAuthority.Position.after(expected.getLong("previousVersion"), bytes("previousDigest"))), now)
        fun authorityWithManifest(manifest: ByteArray) = Draft02ManifestAuthority.verify(
            bytes("rootPin"), manifest, Draft02ManifestAuthority.Trust(
                bytes("accountId"), bytes("rootFingerprint"), expected.getLong("generation"),
                Draft02ManifestAuthority.Position.after(expected.getLong("previousVersion"), bytes("previousDigest"))), now)
        fun request(message: ByteArray = bytes("messageId")) = Draft02ManifestAuthority.Request(
            Draft02ManifestAuthority.Direction.OUTBOUND, bytes("accountId"), message,
            bytes("deviceId"), bytes("lineId"), expected.getString("peer").toByteArray(Charsets.US_ASCII),
            bytes("signerKeyId"), listOf(Draft02ManifestAuthority.Reader(1, bytes("deviceKeyId")),
                Draft02ManifestAuthority.Reader(2, bytes("archiveKeyId"))))
        fun proof(message: ByteArray = bytes("messageId")): Draft02OutboundEnvelope {
            val source = hex(input.getString("outboundEnvelope"))
            val persisted = hex(input.getString("persistedOutboundEnvelope"))
            assertArrayEquals("Database must preserve the exact SDK envelope", source, persisted)
            return Draft02OutboundEnvelope.verify(persisted, authority(), request(message)) { now }
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
    }

    @Test fun persistedSdkCiphertextVerifiesAndDecryptsWithShippingDerivationAndBody() {
        val fixture = Fixture()
        val proof = fixture.proof()
        assertArrayEquals(fixture.bytes("unsignedDigest"), proof.unsignedDigest)
        val cek = fixture.cek(proof)
        val clear = Draft02Body.open(proof, cek)
        try {
            assertEquals(fixture.expected.getString("expectedText"), String(clear))
            assertTrue(cek.all { it == 0.toByte() })
        } finally { clear.fill('\u0000') }
    }

    @Test fun independentFingerprintMismatchFailsClosed() {
        val fixture = Fixture()
        val fingerprint = fixture.bytes("rootFingerprint").apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { fixture.authority(fingerprint) }
    }

    @Test fun independentMessageContextMismatchFailsClosed() {
        val fixture = Fixture()
        val message = fixture.bytes("messageId").apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { fixture.proof(message) }
    }

    @Test fun wrongSoftwareRecipientCannotUnwrapTheVerifiedEnvelope() {
        val fixture = Fixture()
        val scalar = ByteArray(32).apply { this[31] = 1 }
        assertFalse(MessageDigest.isEqual(scalar, fixture.bytes("devicePrivateScalar")))
        assertThrows(Exception::class.java) { fixture.cek(fixture.proof(), scalar) }
        assertTrue(scalar.all { it == 0.toByte() })
    }

    @Test fun independentlySignedWrongNoncePassesAuthorityButFailsBodyAuthentication() {
        val fixture = Fixture()
        val proof = Draft02OutboundEnvelope.verify(hex(fixture.input.getString("outboundWrongNonce")),
            fixture.authority(), fixture.request()) { fixture.now }
        val cek = fixture.cek(proof)
        assertThrows(Exception::class.java) { Draft02Body.open(proof, cek) }
        assertTrue(cek.all { it == 0.toByte() })
    }

    @Test fun wrongSignatureIsRejectedBeforeRecipientUnwrap() {
        val fixture = Fixture()
        assertThrows(Exception::class.java) {
            Draft02OutboundEnvelope.verify(hex(fixture.input.getString("outboundWrongSignature")),
                fixture.authority(), fixture.request()) { fixture.now }
        }
    }

    // Adversarial cross-client vectors: every tampered, truncated, oversized,
    // downgraded, misaddressed or clock-skewed input must fail closed here too.
    private fun rejectEnvelope(bytes: ByteArray) {
        val fixture = Fixture()
        assertThrows(Exception::class.java) {
            Draft02OutboundEnvelope.verify(bytes, fixture.authority(), fixture.request()) { fixture.now }
        }
    }

    private fun rejectManifest(field: String) {
        val fixture = Fixture()
        assertThrows(Exception::class.java) { fixture.authority(manifestField = field) }
    }

    @Test fun truncatedEnvelopeTailIsRejected() {
        val fixture = Fixture()
        val envelope = hex(fixture.input.getString("outboundEnvelope"))
        rejectEnvelope(envelope.copyOf(envelope.size - 1))
    }

    @Test fun truncatedEnvelopeHeaderIsRejected() {
        val fixture = Fixture()
        val envelope = hex(fixture.input.getString("outboundEnvelope"))
        rejectEnvelope(envelope.copyOf(300))
    }

    @Test fun truncatedEnvelopeSignatureIsRejected() {
        val fixture = Fixture()
        val envelope = hex(fixture.input.getString("outboundEnvelope"))
        rejectEnvelope(envelope.copyOf(envelope.size - 64))
    }

    @Test fun oversizedEnvelopeIsRejected() {
        val fixture = Fixture()
        val envelope = hex(fixture.input.getString("outboundEnvelope"))
        rejectEnvelope(envelope + ByteArray(36_865))
    }

    @Test fun downgradedProfileByteIsRejected() {
        val fixture = Fixture()
        rejectEnvelope(hex(fixture.input.getString("outboundDowngradeV1")))
    }

    @Test fun unknownRecipientKeyIsRejected() {
        val fixture = Fixture()
        rejectEnvelope(hex(fixture.input.getString("outboundWrongRecipient")))
    }

    @Test fun ungrantedWrapRoleIsRejected() {
        val fixture = Fixture()
        rejectEnvelope(hex(fixture.input.getString("outboundWrongRole")))
    }

    @Test fun expiredEnvelopeIntentIsRejected() {
        val fixture = Fixture()
        rejectEnvelope(hex(fixture.input.getString("outboundExpired")))
    }

    @Test fun tamperedManifestSignatureIsRejected() {
        val fixture = Fixture()
        val manifest = hex(fixture.input.getString("manifest"))
        manifest[manifest.size - 1] = (manifest[manifest.size - 1].toInt() xor 1).toByte()
        assertThrows(Exception::class.java) { fixture.authorityWithManifest(manifest) }
    }

    @Test fun expiredManifestIsRejected() = rejectManifest("manifestExpired")

    @Test fun futureManifestIsRejected() = rejectManifest("manifestFuture")

    @Test fun wrongPreviousDigestManifestIsRejected() = rejectManifest("manifestWrongPreviousDigest")

    companion object {
        private const val MAX_FIXTURE_BYTES = 1_048_576

        private fun readFixture(variable: String): JSONObject {
            val path = requireNotNull(System.getenv(variable)?.takeIf { it.isNotBlank() }) {
                "Required interoperability fixture path is missing"
            }
            val file = File(path)
            require(file.isFile) { "Interoperability fixture file is missing" }
            val bytes = file.inputStream().use { it.readNBytes(MAX_FIXTURE_BYTES + 1) }
            require(bytes.size in 1..MAX_FIXTURE_BYTES) { "Interoperability fixture size" }
            return JSONObject(bytes.toString(Charsets.UTF_8))
        }

        private fun hex(text: String): ByteArray {
            require(text.length % 2 == 0 && text.all { it in "0123456789abcdefABCDEF" })
            return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}
