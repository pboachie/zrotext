// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyStore

/** Public file candidates select existing resources. They create no trust, session or key. */
internal class ConversationUserSetupProvider(private val context: Context, private val lines: SmsAttemptDao) {
    class ExistingHardwareEnrollmentRequired : IllegalStateException("Existing enrolled hardware reader required")
    class Prepared internal constructor(val selection: ConversationUserSetupController.Selection,
                                        val payloadAlias: String) {
        override fun toString() = "ConversationPreparedSetup(redacted)"
    }
    class ReplyAuthority internal constructor(manifest: ByteArray, signer: ByteArray) {
        private val bytes = manifest.copyOf(); private val id = signer.copyOf()
        fun signedSuccessor() = bytes.copyOf()
        fun signerId() = id.copyOf()
        override fun toString() = "ConversationReplyAuthorityCandidate(redacted)"
    }

    /** Explicit worker action; disabled resolution touches no host, database or Keystore. */
    fun resolve(publicSetupBytes: ByteArray, enabled: Boolean = false,
                initialManifests: List<ByteArray> = emptyList()): Prepared? {
        if (!enabled) return null
        check(Build.VERSION.SDK_INT >= 31)
        val application = checkNotNull(context.applicationContext)
        val host = checkNotNull(ConversationSocketComposition.currentAuthenticatedIdentity())
        val identity = host.identity
        val decoded = decodeSelection(publicSetupBytes, identity)
        val line = checkNotNull(lines.currentLineBinding())
        check(line.accountId == identity.accountId && line.deviceId == identity.deviceId &&
            line.lineId == decoded.first.lineId && line.generation == decoded.first.bindingGeneration)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val matches = store.aliases().toList().mapNotNull { alias ->
            runCatching { DevicePayloadKeyStore(application, alias).existingPublic() }.getOrNull()?.let { key ->
                alias.takeIf { key.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                    key.keyId.contentEquals(decoded.second) }
            }
        }
        if (matches.size != 1) throw ExistingHardwareEnrollmentRequired()
        host.requireCurrent()
        check(lines.currentLineBinding() == line)
        host.requireCurrent()
        val selected = decoded.first
        require(initialManifests.size <= ConversationEnrollmentSession.MAX_CHAIN)
        return Prepared(ConversationUserSetupController.Selection(selected.identity, selected.intervalId,
            selected.lineId, selected.bindingGeneration, selected.peer, selected.bindings,
            selected.site, selected.instance, selected.phoneReaderId, initialManifests), matches.single())
    }

    companion object {
        internal fun decodeSelection(bytes: ByteArray, identity: EvidenceIdentity): Pair<ConversationUserSetupController.Selection, ByteArray> {
            require(bytes.size in (7 + 380 + 97)..(7 + 1024 + 97))
            val input = DataInputStream(ByteArrayInputStream(bytes.copyOf()))
            fun fixed(n: Int) = ByteArray(n).also(input::readFully)
            require(fixed(5).contentEquals(byteArrayOf(90,84,80,83,1)))
            val length = input.readUnsignedShort(); require(length in 380..1024)
            val original = fixed(length); val archive = fixed(65); val reader = fixed(32)
            require(input.available() == 0 && reader.any { it != 0.toByte() })
            val parsed = ConversationActivationCodec.decode(original)
            DevicePayloadKeyStore.decodePoint(archive)
            require(parsed.scope.accountId == identity.accountId && parsed.scope.deviceId == identity.deviceId &&
                Draft02OutboundPreparation.hex(original.copyOfRange(109,141)) == identity.originHash &&
                Draft02OutboundPreparation.hex(DevicePayloadKeyStore.keyId(archive)) == parsed.scope.readerKeyId)
            return ConversationUserSetupController.Selection(identity, parsed.scope.intervalId, parsed.scope.lineId,
                parsed.scope.bindingGeneration, parsed.scope.peer, ConversationConnectionBindings(archive, ByteArray(32)),
                parsed.site, parsed.instance, reader) to reader.copyOf()
        }

        fun decodeReplyAuthority(bytes: ByteArray): ReplyAuthority {
            require(bytes.size in (7 + 218 + 32)..(7 + 16384 + 32))
            val input = DataInputStream(ByteArrayInputStream(bytes.copyOf()))
            fun fixed(n: Int) = ByteArray(n).also(input::readFully)
            require(fixed(5).contentEquals(byteArrayOf(90,84,80,82,1)))
            val length = input.readUnsignedShort(); require(length in 218..16384)
            val manifest = fixed(length); val signer = fixed(32)
            require(input.available() == 0 && signer.any { it != 0.toByte() })
            return ReplyAuthority(manifest, signer)
        }
    }
}
