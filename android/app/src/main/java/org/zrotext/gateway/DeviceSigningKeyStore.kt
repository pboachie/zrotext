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

    /** Read the existing hardware identity only; never replace a missing or unsupported signer. */
    internal fun existingConversationPublicPoint(): ByteArray {
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(
            SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        val public = openStore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: error("Existing conversation signer unavailable")
        return DevicePayloadKeyStore.encodePoint(public)
    }

    fun signEnrollmentChallenge(accountId: UUID, pairingId: UUID, nonce: ByteArray): ByteArray {
        val fingerprint = getOrCreate().fingerprint
        return sign(EnrollmentProof.enrollmentBytes(accountId, pairingId, fingerprint, nonce))
    }

    fun signDeviceChallenge(accountId: UUID, deviceId: UUID, challengeId: UUID, nonce: ByteArray): ByteArray =
          sign(EnrollmentProof.deviceAuthBytes(accountId, deviceId, challengeId, nonce))

    /** Explicit approved conversation only; missing/unsupported existing keys are never created. */
    internal fun signConversationStatement(domain:ByteArray,statement:ByteArray,expectedPoint:ByteArray):ByteArray {
        ConversationActivationCodec.decode(statement)
        val key=privateKey()
        check(securityLevel(key) in setOf(SigningKeySecurity.STRONGBOX,SigningKeySecurity.TRUSTED_ENVIRONMENT))
        val public=openStore().getCertificate(alias)?.publicKey as? ECPublicKey ?: error("Existing conversation signer unavailable")
        check(DevicePayloadKeyStore.encodePoint(public).contentEquals(expectedPoint))
        val der=Signature.getInstance("SHA256withECDSA").run {initSign(key);update(ConversationActivationCodec.transcript(domain,statement));sign()}
        return Draft01SignaturePrimitive.canonicalRawFromDer(der)
    }

    /** Existing hardware identity only; restricted to the canonical inbound conversation envelope. */
    internal fun signConversationEnvelope(unsigned: ByteArray, expectedPoint: ByteArray): ByteArray {
        val owned = unsigned.copyOf()
        val point = expectedPoint.copyOf()
        ConversationContentCrypto.checkInboundUnsigned(owned, point)
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(
            SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        val public = openStore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: error("Existing conversation signer unavailable")
        check(java.security.MessageDigest.isEqual(DevicePayloadKeyStore.encodePoint(public), point))
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update("ZTSE/sign/v2\u0000".toByteArray(Charsets.US_ASCII))
            update(java.nio.ByteBuffer.allocate(4).putInt(owned.size).array())
            update(owned)
            sign()
        }
        return Draft01SignaturePrimitive.canonicalRawFromDer(der)
    }

    internal fun signInboundMetadata(accountId: UUID, deviceId: UUID, upload: InboundUpload,
                                     event: InboundEvent): ByteArray =
        sign(InboundUploadFrame.signedBytes(accountId, deviceId, upload, event))

    internal fun signLineOptOut(accountId: UUID, deviceId: UUID,
                                entry: LocalInboundWithdrawal, recipientE164: String): ByteArray =
        sign(LineOptOutUploadFrame.signedBytes(accountId, deviceId, entry, recipientE164))

    internal fun signSmsLineActivation(challenge: SmsLineChallenge, apiLevel: Int,
                                       selectedSubscriptionId: Int): ByteArray =
        sign(SmsLineActivationTranscript.deviceStatement(challenge, apiLevel,
            selectedSubscriptionId))

    /** Dedicated SEALED confirmation with the existing non-exportable hardware identity only. */
    internal fun signSealedLineActivation(challenge: SealedLineChallenge, apiLevel: Int,
                                         selectedSubscriptionId: Int, expectedFingerprint: ByteArray): ByteArray {
        check(Build.VERSION.SDK_INT >= 31 && apiLevel == Build.VERSION.SDK_INT)
        val expected = expectedFingerprint.copyOf()
        val frozen = challenge.copy(nonce = challenge.nonce.copyOf())
        val statement = SealedLineActivationTranscript.deviceStatement(frozen, apiLevel, selectedSubscriptionId)
        val point = existingConversationPublicPoint()
        check(expected.size == 32 && java.security.MessageDigest.isEqual(expected,
            SealedLineActivationTranscript.digest(point)))
        val sim = checkNotNull(SimCardContinuity.activationCandidate(SimCardContinuity.observe(context)))
        fun selected() = context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .getInt("subscription_id", android.telephony.SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        check(sim.subscriptionId == selectedSubscriptionId && selected() == selectedSubscriptionId)
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(
            SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(statement); sign()
        }
        SealedLineActivationTranscript.requireCanonicalDer(signature)
        check(selected() == selectedSubscriptionId &&
            SimCardContinuity.matches(sim, SimCardContinuity.observe(context)) &&
            java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()) &&
            SealedLineActivationTranscript.verify(point, statement, signature))
        return signature
    }

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
