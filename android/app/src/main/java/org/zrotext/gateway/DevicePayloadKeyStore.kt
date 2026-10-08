// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

enum class PayloadKeySecurity { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN_SECURE, UNKNOWN }

class DevicePayloadPublic internal constructor(
    point: ByteArray,
    keyId: ByteArray,
    val security: PayloadKeySecurity
) {
    private val pointBytes = point.copyOf()
    private val keyIdBytes = keyId.copyOf()
    val point: ByteArray get() = pointBytes.copyOf()
    val keyId: ByteArray get() = keyIdBytes.copyOf()
}

/**
 * Recipient key boundary for the candidate ZTSE P-256 KEM on API 31+.
 *
 * This class exposes a validated public point and a single ECDH result, never the private scalar.
 * It does not implement or authorize HPKE, parse an envelope, or enable sealed radio operations.
 */
class DevicePayloadKeyStore(context: Context, private val alias: String) {
    private val lifecycle = PayloadKeyLifecycle(PayloadKeyLifecycleFileStore(context, alias))
    /** Creation is allowed only during explicit enrollment. A missing receive key is never replaced here. */
    fun getOrCreateForEnrollment(): DevicePayloadPublic = PayloadKeyCustodyEntry.withDeviceMonitor(this) {
        requireSupportedSdk(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
        lifecycle.enroll(exists = { openStore().containsAlias(alias) }, create = {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(false)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                initialize(spec)
                generateKeyPair()
            }
        }, load = { loadExisting() }, keyId = { it.second.keyId }).second
    }

    /** Looks up the pinned recipient identity without creating a replacement key. */
    fun existingPublic(): DevicePayloadPublic = PayloadKeyCustodyEntry.withDeviceMonitor(this) {
        requireSupportedSdk(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
        lifecycle.existing(null, { loadExisting() }, { it.second.keyId }) { it.second }
    }

    /** Local denial only, not a server/root revocation grant. The durable tombstone
     * survives alias deletion and prevents reuse of this enrolled identity. */
    fun revokeExisting(pinnedKeyId: ByteArray): Unit = PayloadKeyCustodyEntry.withDeviceMonitor(this) {
        requireSupportedSdk(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
        lifecycle.revoke(pinnedKeyId)
    }

    /**
     * One validated ECDH operation for a future reviewed RFC 9180 receiver provider.
     * The caller must zero the returned secret. A wrong pinned key ID or lost key fails closed.
     */
    internal fun agreeExisting(enc: ByteArray, pinnedKeyId: ByteArray): ByteArray = PayloadKeyCustodyEntry.withDeviceMonitor(this) {
        requireSupportedSdk(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
        require(pinnedKeyId.size == 32) { "Invalid payload key ID" }
        val peer = decodePoint(enc)
        lifecycle.existing(pinnedKeyId, { loadExisting() }, { it.second.keyId }) { (privateKey, _) ->
            KeyAgreement.getInstance("ECDH", "AndroidKeyStore").run {
                init(privateKey)
                doPhase(peer, true)
                generateSecret().also {
                    if (it.size != 32) {
                        it.fill(0)
                        error("Unexpected P-256 secret width")
                    }
                }
            }
        }
    }

    /** Local-only custody observation. No profile, decryption or application authority. */
    internal fun <R> withExistingCustody(pinnedKeyId: ByteArray,
                                       operation: (ScopedPayloadRecipient) -> R): R =
        PayloadKeyCustodyEntry.withDeviceMonitor(this) {
            requireSupportedSdk(Build.VERSION.SDK_INT)
            if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
            val source = object : PayloadKeyCustodySource<Pair<PrivateKey, DevicePayloadPublic>> {
                override fun load() = loadExisting()
                override fun keyId(material: Pair<PrivateKey, DevicePayloadPublic>) = material.second.keyId
                override fun requireSameIdentity(initial: Pair<PrivateKey, DevicePayloadPublic>,
                                                 current: Pair<PrivateKey, DevicePayloadPublic>) {
                    requireSamePublicIdentity(initial.second, current.second)
                }
            }
            lifecycle.scopedExisting(pinnedKeyId, source) { material, scope ->
                operation(ScopedPayloadRecipient(scope, material.second))
            }
        }

    /** Trusted-adapter variant of [withExistingCustody] for the native HPKE
     * receiver ([WolfHpkeKeystoreReceiver]): the validated AndroidKeyStore
     * handle is supplied to [operation] next to its public facade under the
     * same record lock and identity-revalidation scope. The handle never
     * outlives this call and only ever reaches the in-process native bridge. */
    internal fun <R> withRecipientKey(pinnedKeyId: ByteArray,
                                      operation: (PrivateKey, DevicePayloadPublic) -> R): R =
        PayloadKeyCustodyEntry.withDeviceMonitor(this) {
            requireSupportedSdk(Build.VERSION.SDK_INT)
            if (Build.VERSION.SDK_INT < 31) error("Sealed payload keys require Android API 31+")
            val source = object : PayloadKeyCustodySource<Pair<PrivateKey, DevicePayloadPublic>> {
                override fun load() = loadExisting()
                override fun keyId(material: Pair<PrivateKey, DevicePayloadPublic>) = material.second.keyId
                override fun requireSameIdentity(initial: Pair<PrivateKey, DevicePayloadPublic>,
                                                 current: Pair<PrivateKey, DevicePayloadPublic>) {
                    requireSamePublicIdentity(initial.second, current.second)
                }
            }
            lifecycle.scopedExisting(pinnedKeyId, source) { material, _ ->
                operation(material.first, material.second)
            }
        }

    @RequiresApi(31)
    private fun loadExisting(): Pair<PrivateKey, DevicePayloadPublic> {
        val store = openStore()
        val publicKey = store.getCertificate(alias)?.publicKey as? ECPublicKey
            ?: error("Payload recipient key missing or not EC")
        val privateKey = store.getKey(alias, null) as? PrivateKey
            ?: error("Payload recipient private key missing")
        privateKey.encoded?.let {
            it.fill(0)
            error("Payload recipient key is exportable")
        }
        val info = KeyFactory.getInstance("EC", "AndroidKeyStore")
            .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
        check(info.origin == KeyProperties.ORIGIN_GENERATED &&
            info.purposes == KeyProperties.PURPOSE_AGREE_KEY && info.keySize == 256 &&
            !info.isUserAuthenticationRequired) { "Payload recipient key properties changed" }
        val point = encodePoint(publicKey)
        val security = when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> PayloadKeySecurity.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> PayloadKeySecurity.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> PayloadKeySecurity.SOFTWARE
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> PayloadKeySecurity.UNKNOWN_SECURE
            else -> PayloadKeySecurity.UNKNOWN
        }
        return privateKey to DevicePayloadPublic(point, keyId(point), security)
    }

    private fun openStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    companion object {
        private val params: ECParameterSpec by lazy {
            AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec("secp256r1"))
                getParameterSpec(ECParameterSpec::class.java)
            }
        }

        internal fun requireSupportedSdk(sdk: Int) {
            require(sdk >= 31) { "Sealed payload keys require Android API 31+" }
        }

        internal fun requireSamePublicIdentity(initial: DevicePayloadPublic, current: DevicePayloadPublic) {
            check(MessageDigest.isEqual(initial.keyId, current.keyId) &&
                MessageDigest.isEqual(initial.point, current.point) && initial.security == current.security) {
                "Payload recipient identity changed"
            }
        }

        internal fun keyId(point: ByteArray): ByteArray {
            decodePoint(point)
            return MessageDigest.getInstance("SHA-256").digest(
                "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 16) + point)
        }

        internal fun encodePoint(publicKey: ECPublicKey): ByteArray {
            val spec = publicKey.params
            require(spec.curve == params.curve && spec.generator == params.generator &&
                spec.order == params.order && spec.cofactor == params.cofactor) { "Not P-256" }
            fun coordinate(value: BigInteger): ByteArray {
                require(value.signum() >= 0)
                val signed = value.toByteArray()
                val magnitude = if (signed.size == 33 && signed[0] == 0.toByte()) signed.copyOfRange(1, 33) else signed
                require(magnitude.size <= 32)
                return ByteArray(32).also { magnitude.copyInto(it, 32 - magnitude.size) }
            }
            val point = byteArrayOf(4) + coordinate(publicKey.w.affineX) + coordinate(publicKey.w.affineY)
            decodePoint(point)
            return point
        }

        internal fun decodePoint(raw: ByteArray): ECPublicKey {
            require(raw.size == 65 && raw[0] == 4.toByte()) { "Invalid P-256 point encoding" }
            val x = BigInteger(1, raw.copyOfRange(1, 33))
            val y = BigInteger(1, raw.copyOfRange(33, 65))
            val p = (params.curve.field as ECFieldFp).p
            require(x < p && y < p &&
                y.modPow(BigInteger.valueOf(2), p) == x.modPow(BigInteger.valueOf(3), p)
                    .add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)) { "Invalid P-256 point" }
            return KeyFactory.getInstance("EC")
                .generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
        }
    }
}
