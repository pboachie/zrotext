// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

enum class SigningKeySecurity { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN_SECURE, UNKNOWN }

class DeviceSigningPublic internal constructor(
    val spkiDer: ByteArray,
    val fingerprint: ByteArray,
    val security: SigningKeySecurity,
    /** Null for a pre-existing key: creation-time fallback history is unknown. */
    val strongBoxFallbackOnCreation: Boolean?
) {
    val fingerprintHex: String get() = EnrollmentProof.hexUpper(fingerprint)
}

/** A versioned, non-exportable P-256 signing identity for enrollment and socket challenges. */
class DeviceSigningKeyStore(
    private val context: Context,
    private val alias: String = DEFAULT_ALIAS
) {
    @Synchronized
    fun getOrCreate(): DeviceSigningPublic {
        val store = openStore()
        var fallbackOnCreation: Boolean? = null
        if (!store.containsAlias(alias)) {
            fallbackOnCreation = false
            val preferStrongBox = Build.VERSION.SDK_INT >= 28 &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            if (preferStrongBox) {
                try {
                    generate(strongBox = true)
                } catch (_: StrongBoxUnavailableException) {
                    // A failed StrongBox request must not replace a partially created identity.
                    check(!openStore().containsAlias(alias)) { "Signing identity requires repair" }
                    generate(strongBox = false)
                    fallbackOnCreation = true
                }
            } else {
                generate(strongBox = false)
            }
        }
        val certificate = openStore().getCertificate(alias) ?: error("Signing identity missing certificate")
        val publicKey = certificate.publicKey as? ECPublicKey ?: error("Signing identity is not EC")
        val privateKey = privateKey()
        check(privateKey.encoded == null) { "Signing identity is exportable" }
        return DeviceSigningPublic(
            spkiDer = publicKey.encoded.copyOf(),
            fingerprint = EnrollmentProof.fingerprint(publicKey),
            security = securityLevel(privateKey),
            strongBoxFallbackOnCreation = fallbackOnCreation
        )
    }

    fun signEnrollmentChallenge(accountId: UUID, pairingId: UUID, nonce: ByteArray): ByteArray {
        val fingerprint = getOrCreate().fingerprint
        return sign(EnrollmentProof.enrollmentBytes(accountId, pairingId, fingerprint, nonce))
    }

    fun signDeviceChallenge(accountId: UUID, deviceId: UUID, challengeId: UUID, nonce: ByteArray): ByteArray =
        sign(EnrollmentProof.deviceAuthBytes(accountId, deviceId, challengeId, nonce))

    internal fun signInboundMetadata(accountId: UUID, deviceId: UUID, upload: InboundUpload,
                                     event: InboundEvent): ByteArray =
        sign(InboundUploadFrame.signedBytes(accountId, deviceId, upload, event))

    internal fun signLineOptOut(accountId: UUID, deviceId: UUID,
                                entry: LocalInboundWithdrawal, recipientE164: String): ByteArray =
        sign(LineOptOutUploadFrame.signedBytes(accountId, deviceId, entry, recipientE164))

    private fun sign(payload: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(privateKey())
        update(payload)
        sign() // DER encoded ECDSA signature, accepted by the server's p256 verifier.
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .apply { if (Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(strongBox) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun privateKey(): PrivateKey =
        (openStore().getKey(alias, null) as? PrivateKey) ?: error("Signing identity missing private key")

    private fun openStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    private fun securityLevel(privateKey: PrivateKey): SigningKeySecurity {
        val info = KeyFactory.getInstance("EC", "AndroidKeyStore")
            .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT < 31) {
            @Suppress("DEPRECATION")
            return if (info.isInsideSecureHardware) SigningKeySecurity.UNKNOWN_SECURE else SigningKeySecurity.SOFTWARE
        }
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> SigningKeySecurity.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SigningKeySecurity.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> SigningKeySecurity.SOFTWARE
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> SigningKeySecurity.UNKNOWN_SECURE
            else -> SigningKeySecurity.UNKNOWN
        }
    }

    companion object { const val DEFAULT_ALIAS = "zrotext.device.signing.v1" }
}
