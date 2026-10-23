// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/** Actual Android provider adapter. The flow, not this adapter, commits each original burn
 * and verifies its authenticated opening before invoking generation/signing. No implicit
 * getter creates an alias; there is no deletion, replacement, scalar export or reset API. */
internal class ProtectionOriginKeys(private val context: Context) : ProtectionOriginProviderPort {
    private val enrolled = DeviceSigningKeyStore(context)
    fun enrolledPoint() = enrolled.existingProtectionPublicPoint()
    override fun aliasesMatchRetained(rows: List<ProtectionSetupProvider>) {
        val store = store()
        for (kind in ProtectionSetupProvider.KINDS) {
            val retained = rows.singleOrNull { it.kind == kind }
            if (retained == null) check(!store.containsAlias(alias(kind))) { "Existing protection needs its original setup history" }
            // A retained unknown operation is NOT permission to generate or adopt its alias.
            else { retained.requireShape(); check(retained.evidenceB64url != null) { "Original provider result is unknown" } }
        }
    }
    /** Called only for a newly committed original operation. The gate serializes every
     * production creator of these FOUR aliases, and is released before any Room append. */
    override fun generate(kind: String, probeContext: ByteArray): ByteArray = synchronized(providerGate) {
        Capture03IngressGate.requireOutside(); require(probeContext.size == 192)
        val ownedContext = probeContext.copyOf(); val name = alias(kind)
        check(!store().containsAlias(name)) { "Original protection alias already exists" }
        if (kind == "canary") {
            val known = signingPoints()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                initialize(KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256).build())
                generateKeyPair()
            }
            canaryPoint().also { point -> check(known.none { ProtectionOriginProof.same(it, point) }) }
        } else {
            val isHmac = kind == "suppression_hmac"
            val algorithm = if (isHmac) KeyProperties.KEY_ALGORITHM_HMAC_SHA256 else KeyProperties.KEY_ALGORITHM_AES
            val purposes = if (isHmac) KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                else KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            val spec = KeyGenParameterSpec.Builder(name, purposes).setKeySize(256).apply {
                if (isHmac) setDigests(KeyProperties.DIGEST_SHA256)
                else setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            }.build()
            KeyGenerator.getInstance(algorithm, "AndroidKeyStore").run { init(spec); generateKey() }
            if (isHmac) hmac(ownedContext) else aesProbe(kind, ownedContext)
        }
    }
    override fun requireResult(kind: String, expected: ByteArray, probeContext: ByteArray) {
        Capture03IngressGate.requireOutside()
        when (kind) {
            "canary" -> check(expected.size == 65 && ProtectionOriginProof.same(expected, canaryPoint()))
            "suppression_hmac" -> check(expected.size == 32 && ProtectionOriginProof.same(expected, hmac(probeContext)))
            "journal_aes", "withdrawal_aes" -> verifyAes(kind, expected, probeContext)
            else -> error("Unknown protection purpose")
        }
    }
    fun requirePrepared(prepared: ProtectionOriginPrepared, opening: ProtectionOriginWire.Opening) {
        val c = prepared.association.probeContext(opening.nonce)
        check(ProtectionOriginProof.same(enrolledPoint(), opening.enrolledPoint))
        prepared.association.requireOriginal(prepared.command)
        prepared.association.requireProviderClaims(opening.nonce, prepared.aesProbe())
        requireResult("canary", prepared.association.canaryPoint, c)
        requireResult("suppression_hmac", prepared.association.hmacProbe, c)
        requireResult("journal_aes", prepared.aesProbe().copyOfRange(0, 60), c)
        requireResult("withdrawal_aes", prepared.aesProbe().copyOfRange(60, 120), c)
        check(ProtectionOriginProof.same(enrolledPoint(), opening.enrolledPoint))
    }
    /** Exact first-origin domain only, AFTER the caller's separate durable signature burn.
     * Returned bytes are first retained as history; foreground/current/time is rechecked
     * before any next signature, upload or pin. This adapter does not bypass those checks. */
    fun signDevice(core: ProtectionOriginProof.Core): ByteArray {
        val point = enrolledPoint()
        check(ProtectionOriginProof.same(ProtectionOriginProof.signingKeyId(point), core.association.enrolledKeyId))
        return enrolled.signProtectionOrigin(core, point)
    }
    fun signCanary(core: ProtectionOriginProof.Core, originalDeviceSignature: ByteArray): ByteArray {
        val point = canaryPoint()
        check(ProtectionOriginProof.same(point, core.association.canaryPoint))
        check(ConversationContentCrypto.verifyRaw(originalDeviceSignature, enrolledPoint(), ProtectionOriginProof.deviceTranscript(core)))
        val transcript = ProtectionOriginProof.canaryTranscript(core, originalDeviceSignature.copyOf())
        val result = Signature.getInstance("SHA256withECDSA").run { initSign(canaryPrivate()); update(transcript); sign() }
        return Draft01SignaturePrimitive.canonicalRawFromDer(result).also {
            check(ConversationContentCrypto.verifyRaw(it, point, transcript))
        }
    }
    fun continuityTag(): String = Draft02OutboundPreparation.hex(Mac.getInstance("HmacSHA256").run {
        init(secret("suppression_hmac"))
        doFinal("zrotext-inbound-protection-continuity-v1\u0000".toByteArray(Charsets.US_ASCII))
    })
    fun suppressionKey(): SecretKey = secret("suppression_hmac")
    private fun hmac(probeContext: ByteArray) = Mac.getInstance("HmacSHA256").run {
        init(secret("suppression_hmac")); doFinal(ProtectionOriginProof.hmacTranscript(probeContext))
    }
    private fun aesProbe(kind: String, probeContext: ByteArray): ByteArray {
        val purpose = purpose(kind); val plaintext = ProtectionOriginProof.aesPlaintext(purpose, probeContext)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secret(kind)); cipher.updateAAD(ProtectionOriginProof.aesAad(purpose, probeContext))
            (cipher.iv + cipher.doFinal(plaintext)).also { require(it.size == 60); verifyAes(kind, it, probeContext) }
        } finally { plaintext.fill(0) }
    }
    private fun verifyAes(kind: String, expected: ByteArray, probeContext: ByteArray) {
        val probe = expected.copyOf(); require(probe.size == 60)
        val purpose = purpose(kind); val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret(kind), GCMParameterSpec(128, probe.copyOfRange(0, 12)))
        cipher.updateAAD(ProtectionOriginProof.aesAad(purpose, probeContext))
        val clear = cipher.doFinal(probe.copyOfRange(12, 60)); val original = ProtectionOriginProof.aesPlaintext(purpose, probeContext)
        try { check(ProtectionOriginProof.same(clear, original)) } finally { clear.fill(0); original.fill(0) }
    }
    private fun secret(kind: String): SecretKey {
        val key = checkNotNull(store().getKey(alias(kind), null) as? SecretKey)
        check(key.encoded == null)
        val hmac = kind == "suppression_hmac"
        check(key.algorithm.equals(if (hmac) "HmacSHA256" else "AES", true))
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        check(info.keySize == 256)
        return key
    }
    private fun canaryPrivate(): PrivateKey = checkNotNull(store().getKey(CANARY_ALIAS, null) as? PrivateKey).also {
        check(it.encoded == null)
        val info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(it, KeyInfo::class.java) as KeyInfo
        check(info.keySize == 256 && info.purposes == KeyProperties.PURPOSE_SIGN)
    }
    private fun canaryPoint(): ByteArray {
        canaryPrivate()
        val point = DevicePayloadKeyStore.encodePoint(checkNotNull(store().getCertificate(CANARY_ALIAS)?.publicKey as? ECPublicKey))
        DevicePayloadKeyStore.decodePoint(point)
        check(!ProtectionOriginProof.same(point, enrolledPoint()))
        return point
    }
    private fun signingPoints(): List<ByteArray> {
        val store = store()
        return store.aliases().toList().filter { it != CANARY_ALIAS }.mapNotNull {
            (store.getCertificate(it)?.publicKey as? ECPublicKey)?.takeIf { p -> p.params.curve.field.fieldSize == 256 }
                ?.let { key -> DevicePayloadKeyStore.encodePoint(key) }
        } + listOf(enrolledPoint())
    }
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun purpose(kind: String) = when (kind) { "journal_aes" -> "journal"; "withdrawal_aes" -> "withdrawal"; else -> error("AES purpose") }
    private fun alias(kind: String) = when (kind) {
        "canary" -> CANARY_ALIAS
        "suppression_hmac" -> ConversationExistingSuppressionTokens.ALIAS
        "journal_aes" -> ConversationExistingJournalProtection.ALIAS
        "withdrawal_aes" -> InboundVault.WITHDRAWAL_ALIAS
        else -> error("Protection purpose")
    }
    companion object {
        internal const val CANARY_ALIAS = "zrotext.protection.canary.v1"
        private val providerGate = Any()
    }
}
