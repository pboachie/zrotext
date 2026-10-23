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

/** An unreadable provider is not evidence that an enrolled identity was lost. */
internal sealed interface ExistingSigningIdentity {
    data class Present(val fingerprint: String) : ExistingSigningIdentity
    data object Missing : ExistingSigningIdentity
    data object Unavailable : ExistingSigningIdentity

    companion object {
        fun observe(aliasPresent: () -> Boolean, fingerprint: () -> String): ExistingSigningIdentity = try {
            if (aliasPresent()) Present(fingerprint()) else Missing
        } catch (_: Exception) { Unavailable }
    }
}

class DeviceSigningPublic internal constructor(
    val spkiDer: ByteArray,
    val fingerprint: ByteArray,
    val security: SigningKeySecurity,
    /** Null for a pre-existing key: creation-time fallback history is unknown. */
    val strongBoxFallbackOnCreation: Boolean?
) {
    val fingerprintHex: String get() = EnrollmentProof.hexUpper(fingerprint)
}

/** Checks the explicitly selected physical card on both sides of a blocking key operation. */
internal object SelectedSimSigning {
    fun sign(selectedSubscriptionId: Int, selected: () -> Int,
             observe: () -> List<ActiveSimCard>?, operation: () -> ByteArray): ByteArray {
        check(selected() == selectedSubscriptionId)
        val sim = checkNotNull(SimCardContinuity.activationCandidate(observe(), selectedSubscriptionId))
        check(selected() == selectedSubscriptionId)
        val signature = operation()
        check(selected() == selectedSubscriptionId && SimCardContinuity.matches(sim, observe()) &&
            selected() == selectedSubscriptionId)
        return signature
    }
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
        return existing(fallbackOnCreation)
    }

    /** Read a previously enrolled identity. Recovery must never silently create a new key. */
    @Synchronized
    fun existing(): DeviceSigningPublic = existing(null)

    @Synchronized
    internal fun observeExistingIdentity(): ExistingSigningIdentity = ExistingSigningIdentity.observe(
        { openStore().containsAlias(alias) }, { existing().fingerprintHex })

    private fun existing(fallbackOnCreation: Boolean?): DeviceSigningPublic {
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

    /** Ordinary first-origin metadata, without a conversation/API31 hardware claim. This
     * reads the already enrolled nonexportable key only and never enrolls/replaces it. */
    internal fun existingProtectionPublicPoint(): ByteArray {
        check(privateKey().encoded == null)
        val public = openStore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: error("Original enrolled protection signer unavailable")
        return DevicePayloadKeyStore.encodePoint(public)
    }

    /** Fixed441 existing enrolled hardware signer, after an irreversible writer burn. */
    internal fun signNoSubmit03(entry: TypedNoSubmit03SignEntry, context: TypedNoSubmit03Context): ByteArray {
        Capture03IngressGate.requireOutside()
        val core = entry.consume() // Actual reservation returned after Room COMMIT, once only.
        val expected = TypedSubmit03Record.unbase(entry.original.originalEnrolledPoint)
        context.requireCurrent(entry.original, entry.proof)
        check(java.security.MessageDigest.isEqual(expected, existingConversationPublicPoint()))
        val key = privateKey(); check(key.encoded == null)
        val signer = Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
        context.requireCurrent(entry.original, entry.proof) // Includes waits for provider/key entry.
        signer.update(core.transcript())
        context.requireCurrent(entry.original, entry.proof) // Last RAM check at provider entry.
        val returned = signer.sign()
        // Retain the actual burned call's result even after a pause. No post-call RAM guard
        // may discard it and accidentally suggest that this operation can be re-signed.
        return Draft01SignaturePrimitive.canonicalRawFromDer(returned).also {
            check(ConversationContentCrypto.verifyRaw(it, expected, core.transcript()))
        }
    }

    /** Only the first-origin metadata domain; caller owns the durable one-use reservation. */
    internal fun signProtectionOrigin(core: ProtectionOriginProof.Core, expectedPoint: ByteArray): ByteArray {
        val point = expectedPoint.copyOf()
        check(java.security.MessageDigest.isEqual(point, existingProtectionPublicPoint()))
        val key = privateKey(); check(key.encoded == null)
        val transcript = ProtectionOriginProof.deviceTranscript(core)
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(transcript); sign() }
        return Draft01SignaturePrimitive.canonicalRawFromDer(der).also {
            check(ConversationContentCrypto.verifyRaw(it, point, transcript))
        }
    }

    fun signEnrollmentChallenge(accountId: UUID, pairingId: UUID, nonce: ByteArray): ByteArray {
        val fingerprint = getOrCreate().fingerprint
        return sign(EnrollmentProof.enrollmentBytes(accountId, pairingId, fingerprint, nonce))
    }

    fun signDeviceChallenge(accountId: UUID, deviceId: UUID, challengeId: UUID, nonce: ByteArray): ByteArray =
          sign(EnrollmentProof.deviceAuthBytes(accountId, deviceId, challengeId, nonce))

    /** Read-only pairing reconciliation with the original existing identity only. */
    internal fun signPairingBinding(accountId: UUID, pairingId: UUID, challengeId: UUID,
                                    fingerprint: ByteArray, nonce: ByteArray): ByteArray {
        check(java.security.MessageDigest.isEqual(existing().fingerprint, fingerprint))
        return sign(PairingBindingProof.bytes(accountId, pairingId, challengeId, fingerprint, nonce))
    }

    /** Exact scoped fetch only. Missing identities are never enrolled or replaced by a receive path. */
    internal fun signSealedEnvelopeFetch(grant: SealedExecutionGrantValidator.Fields): ByteArray {
        val transcript = SealedEnvelopeFetch.transcript(grant)
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(
            SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(transcript)
            sign()
        }
    }

    /** Additive03 transcript only. Canonicalize our own randomized signing output; received
     * signatures are never normalized. This neither authenticates a grant nor selects a key.
     */
    internal fun signSealedEnvelopeFetch03(grant: SealedDispatch03Frames.Grant,
        expectedPoint: ByteArray, current: () -> Unit): ByteArray {
        val transcript = SealedEnvelopeFetch03.transcript(SealedDispatch03Frames.grant(grant.json()))
        val point = expectedPoint.copyOf()
        current()
        check(java.security.MessageDigest.isEqual(existingConversationPublicPoint(), point))
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(
            SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        current()
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(transcript); sign()
        }
        current()
        check(java.security.MessageDigest.isEqual(existingConversationPublicPoint(), point))
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
        fun integer(at: Int) = java.math.BigInteger(1, raw.copyOfRange(at, at + 32)).toByteArray()
            .let { byteArrayOf(2, it.size.toByte()) + it }
        val fields = integer(0) + integer(32)
        val canonical = byteArrayOf(0x30, fields.size.toByte()) + fields
        SealedEnvelopeFetch03.requireCanonicalDer(canonical)
        current()
        return canonical
    }

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

    /** Additive03 role04 only, called AFTER the future actual capture journal's one-use
     * reservation. A public proof never substitutes for that caller's current113/physical
     * provenance. Missing/nonmatching/exportable keys refuse; no key is created or aliased. */
    internal fun signPreparedInbound03(prepared: Draft03InboundEnvelope.Unsigned,
        now: () -> Long, current: () -> Unit): ByteArray {
        var latest = 0L
        fun checked() {
            current(); val value = now(); check(value >= latest)
            prepared.requirePublicCurrent(value); current(); latest = value
        }
        checked()
        val point = prepared.signerPoint()
        check(java.security.MessageDigest.isEqual(existingConversationPublicPoint(), point))
        checked()
        val key = privateKey()
        check(key.encoded == null && securityLevel(key) in setOf(SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
        checked()
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(prepared.transcript()); sign() }
        checked()
        check(java.security.MessageDigest.isEqual(existingConversationPublicPoint(), point))
        checked()
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
        prepared.signed(raw) // Independently verify our new signature over the exact03 transcript.
        checked()
        return raw
    }

    internal fun signInboundMetadata(accountId: UUID, deviceId: UUID, upload: InboundUpload,
                                     event: InboundEvent): ByteArray =
        sign(InboundUploadFrame.signedBytes(accountId, deviceId, upload, event))

    internal fun signLineOptOut(accountId: UUID, deviceId: UUID,
                                entry: LocalInboundWithdrawal, recipientE164: String): ByteArray =
        sign(LineOptOutUploadFrame.signedBytes(accountId, deviceId, entry, recipientE164))

    internal fun signSmsLineActivation(challenge: SmsLineChallenge, apiLevel: Int,
                                       selectedSubscriptionId: Int): ByteArray {
        check(Build.VERSION.SDK_INT >= 29 && apiLevel == Build.VERSION.SDK_INT)
        val frozen = challenge.copy(nonce = challenge.nonce.copyOf())
        val statement = SmsLineActivationTranscript.deviceStatement(frozen, apiLevel, selectedSubscriptionId)
        return SelectedSimSigning.sign(selectedSubscriptionId, ::selectedSubscription,
            { SimCardContinuity.observe(context) }) { sign(statement) }
    }

    /** Dedicated SEALED confirmation with the existing non-exportable hardware identity only. */
    internal fun signSealedLineActivation(challenge: SealedLineChallenge, apiLevel: Int,
                                         selectedSubscriptionId: Int, expectedFingerprint: ByteArray): ByteArray {
        check(Build.VERSION.SDK_INT >= 31 && apiLevel == Build.VERSION.SDK_INT)
        val expected = expectedFingerprint.copyOf()
        val frozen = challenge.copy(nonce = challenge.nonce.copyOf())
        val statement = SealedLineActivationTranscript.deviceStatement(frozen, apiLevel, selectedSubscriptionId)
        return SelectedSimSigning.sign(selectedSubscriptionId, ::selectedSubscription,
            { SimCardContinuity.observe(context) }) {
            val point = existingConversationPublicPoint()
            check(expected.size == 32 && java.security.MessageDigest.isEqual(expected,
                SealedLineActivationTranscript.digest(point)))
            val key = privateKey()
            check(key.encoded == null && securityLevel(key) in setOf(
                SigningKeySecurity.STRONGBOX, SigningKeySecurity.TRUSTED_ENVIRONMENT))
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(key); update(statement); sign()
            }
            SealedLineActivationTranscript.requireCanonicalDer(signature)
            check(java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()) &&
                SealedLineActivationTranscript.verify(point, statement, signature))
            signature
        }
    }

    private fun selectedSubscription(): Int = context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
        .getInt("subscription_id", android.telephony.SubscriptionManager.INVALID_SUBSCRIPTION_ID)

    /** Same enrolled nonexportable signer, only after the caller's durable one-use reservation.
     * Canonicalizes this newly generated outgoing signature; received originalv2 DER is untouched.
     */
    internal fun signPayloadElection03(core: ByteArray, expectedPoint: ByteArray, current: () -> Unit): ByteArray {
        require(core.size == 500 && expectedPoint.size == 65)
        val owned = core.copyOf()
        val point = expectedPoint.copyOf()
        current()
        check(java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()))
        current()
        val transcript = ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", owned)
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(sign(transcript))
        current()
        check(java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()) &&
            ConversationContentCrypto.verifyRaw(raw, point, transcript))
        current()
        return raw
    }

    /** Caller commits the distinct refresh reservation before this dedicated signing operation. */
    internal fun signSelectionRefresh03(core: SelectionRefresh03.Core, observation: ByteArray,
        expectedPoint: ByteArray, current: () -> Unit): ByteArray = signExistingRefreshTranscript(
        SelectionRefresh03.deviceTranscript(core, observation), expectedPoint, current)

    /** Caller atomically installs the original exact accepted refresh row before this ACK. */
    internal fun signSelectionRefreshInstalled03(bundle: SelectionRefresh03.Bundle, actualDeviceSessionDigest: ByteArray,
        expectedPoint: ByteArray, current: () -> Unit): ByteArray = signExistingRefreshTranscript(
        SelectionRefresh03.installedTranscript(bundle, actualDeviceSessionDigest), expectedPoint, current)

    /** Actual selected manifest role04, independently compared to this existing hardware key.
     * Reader availability and the separately enrolled socket key never supply that selection.
     * The caller must commit the distinct one-use phase before either operation.
     */
    internal fun signConversationApproval03(statement: ConversationInterval03.Statement, ownerSignature: ByteArray,
        expectedRole04: ByteArray, current: () -> Unit): ByteArray = signExistingRefreshTranscript(
        ConversationInterval03.approvalTranscript(statement, ownerSignature), expectedRole04, current)

    internal fun signConversationInstalled03(statement: ConversationInterval03.Statement, ownerSignature: ByteArray,
        phoneSignature: ByteArray, expectedRole04: ByteArray, current: () -> Unit): ByteArray = signExistingRefreshTranscript(
        ConversationInterval03.installedTranscript(statement, ownerSignature, phoneSignature), expectedRole04, current)

    private fun signExistingRefreshTranscript(transcript: ByteArray, expectedPoint: ByteArray, current: () -> Unit): ByteArray {
        val point = expectedPoint.copyOf()
        current()
        check(java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()))
        current()
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(sign(transcript))
        current()
        check(java.security.MessageDigest.isEqual(point, existingConversationPublicPoint()) &&
            ConversationContentCrypto.verifyRaw(raw, point, transcript))
        current()
        return raw
    }

    /** Existing enrolled identity only. A received line challenge cannot create a replacement key. */
    internal fun existingLineActivationV2Point(purpose: LineActivationV2Purpose): ByteArray {
        if (purpose == LineActivationV2Purpose.SEALED) return existingConversationPublicPoint()
        val key = privateKey()
        check(key.encoded == null)
        val public = openStore().getCertificate(alias)?.publicKey as? ECPublicKey
            ?: error("Existing line signer unavailable")
        return DevicePayloadKeyStore.encodePoint(public)
    }

    /** Genuine held complete observation on both sides of the existing-key operation. */
    internal fun signLineActivationV2(purpose: LineActivationV2Purpose,
        fields: LineActivationV2StatementFields, lease: SelectedLineLeaseV2,
        expectedFingerprint: ByteArray, expiresAtMs: Long, nowMs: () -> Long,
        sessionCurrent: () -> Boolean): SignedLineActivationV2 {
        val fingerprint = expectedFingerprint.copyOf()
        var lastNow = 0L
        fun fresh() {
            check(sessionCurrent() && Build.VERSION.SDK_INT >= 33 && Build.VERSION.SDK_INT == lease.projection.apiLevel &&
                selectedSubscription() == lease.selected.subscriptionId && lease.recheck() &&
                selectedSubscription() == lease.selected.subscriptionId)
            val completed = nowMs()
            check(completed > 0 && completed >= lastNow && expiresAtMs - completed in 1..300_000L &&
                sessionCurrent() && lease.isCurrent())
            lastNow = completed
        }
        fresh()
        val point = existingLineActivationV2Point(purpose)
        check(fingerprint.size == 32 && java.security.MessageDigest.isEqual(fingerprint,
            SealedLineActivationTranscript.digest(point)))
        fresh()
        val statement = LineActivationV2Statements.device(purpose, fields, lease.observation())
        val signature = sign(statement)
        SealedLineActivationTranscript.requireCanonicalDer(signature)
        check(SealedLineActivationTranscript.verify(point, statement, signature) &&
            java.security.MessageDigest.isEqual(point, existingLineActivationV2Point(purpose)))
        fresh()
        return SignedLineActivationV2(statement, signature, point)
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
