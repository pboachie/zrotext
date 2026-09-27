// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Dedicated dormant root-state key. Decryption never creates or replaces a key. */
internal class Draft02RootStorageKey(private val alias: String, aad: ByteArray) {
    private val aad = aad.copyOf()
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun state(): Draft02TrustStore.KeyState {
        if (Build.VERSION.SDK_INT < 31) return Draft02TrustStore.KeyState.UNSUPPORTED
        if (!store().containsAlias(alias)) return Draft02TrustStore.KeyState.ABSENT
        return try { existing(); Draft02TrustStore.KeyState.READY }
        catch (failure: Draft02TrustStore.Failure) {
            if (failure.status == Draft02TrustStore.Status.UNSUPPORTED) Draft02TrustStore.KeyState.UNSUPPORTED else throw failure
        }
    }

    fun create() {
        if (Build.VERSION.SDK_INT < 31) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.UNSUPPORTED)
        check(!store().containsAlias(alias)) { "Root storage key already exists" }
        // Do not try software or another alias if the platform cannot supply acceptable custody.
        try { KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).setRandomizedEncryptionRequired(true).build())
            generateKey()
        } } catch (_: GeneralSecurityException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.UNSUPPORTED) }
            catch (_: ProviderException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.UNSUPPORTED) }
        existing()
    }

    fun seal(plaintext: ByteArray): ByteArray = Draft02RootStateCipher.seal(supportedExisting(), aad, plaintext)
    fun open(ciphertext: ByteArray): ByteArray = Draft02RootStateCipher.open(supportedExisting(), aad, ciphertext)

    private fun supportedExisting(): SecretKey {
        if (Build.VERSION.SDK_INT < 31) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.UNSUPPORTED)
        return existing()
    }

    @RequiresApi(31)
    private fun existing(): SecretKey {
        val key = try { store().getKey(alias, null) as? SecretKey }
        catch (_: GeneralSecurityException) { null }
            ?: throw Draft02TrustStore.Failure(Draft02TrustStore.Status.KEY_LOST)
        val info = SecretKeyFactory.getInstance("AES", "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val acceptable = key.encoded == null && info.origin == KeyProperties.ORIGIN_GENERATED &&
            info.keySize == 256 && info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) &&
            info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM) &&
            info.encryptionPaddings.toSet() == setOf(KeyProperties.ENCRYPTION_PADDING_NONE) &&
            !info.isUserAuthenticationRequired &&
            (info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX)
        if (!acceptable) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.UNSUPPORTED)
        return key
    }
}
