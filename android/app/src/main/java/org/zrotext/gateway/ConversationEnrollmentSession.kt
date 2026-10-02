// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.Base64
import java.util.UUID
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/** Deliberate enrollment only. No session, content consent or dispatch is granted here. */
internal class ConversationEnrollmentSession(
    private val accountId: String,
    private val requireCurrent: () -> Unit,
    private val createReader: () -> DevicePayloadPublic,
    storage: Draft02TrustStore.Storage,
    private val prepareProtection: () -> Unit,
    private val release: () -> Unit = {},
    private val exportPublic: (DevicePayloadPublic) -> ConversationPhonePublicExport = { error("Public export unavailable") }
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val comparison = Draft02RootComparison()
    private fun current() { check(!closed.get()); requireCurrent(); check(!closed.get()) }
    private val trust = Draft02TrustStore(object : Draft02TrustStore.Storage {
        override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = storage.locked {
            val delegate = this
            action(object : Draft02TrustStore.Session {
                private fun <V> checked(work: () -> V): V { current(); return work().also { current() } }
                override fun keyState() = checked { delegate.keyState() }
                override fun read() = checked { delegate.read() }
                override fun createKey() = checked { delegate.createKey() }
                override fun seal(plaintext: ByteArray) = checked { delegate.seal(plaintext) }
                override fun open(ciphertext: ByteArray) = checked { delegate.open(ciphertext) }
                override fun write(ciphertext: ByteArray, preCommit: () -> Unit) = checked {
                    delegate.write(ciphertext) { current(); preCommit(); current() }
                }
            })
        }
    })

    fun enrollReader(): DevicePayloadPublic {
        current()
        val reader = createReader()
        current()
        check(reader.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
        prepareProtection()
        current()
        return reader
    }

    fun reviewRoot(pin: ByteArray): Draft02RootComparison.Display {
        current()
        check(trust.inspect().status == Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON)
        val display = comparison.begin(pin, uuid(accountId))
        current()
        return display
    }

    fun enrollReaderPublicExport(): ConversationPhonePublicExport {
        val reader = enrollReader()
        current()
        return exportPublic(reader).also { current(); it.requireCurrent() }
    }

    fun enrollComparedRoot(fingerprint: String, independentlyCompared: Boolean): Draft02TrustStore.Result {
        current()
        val receipt = comparison.confirm(fingerprint, independentlyCompared)
        try {
            current()
            return trust.enroll(receipt).also { current() }
        } finally { comparison.cancel() }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            comparison.cancel() // Can fence a root write while a worker is inside storage.
            release()
        }
    }
    override fun toString() = "ConversationEnrollmentSession(redacted)"

    companion object {
        internal fun uuid(text: String): ByteArray = UUID.fromString(text).let {
            require(it != UUID(0, 0)); ByteBuffer.allocate(16).putLong(it.mostSignificantBits).putLong(it.leastSignificantBits).array()
        }
        internal fun decodePublic(value: String, minimum: Int, maximum: Int): ByteArray {
            require(value.length in ((minimum + 2) / 3 * 4)..((maximum + 2) / 3 * 4))
            return Base64.getDecoder().decode(value).also {
                require(it.size in minimum..maximum && Base64.getEncoder().encodeToString(it) == value)
            }
        }
        internal fun decodeChain(value: String): List<ByteArray> {
            require(value.length <= MAX_CHAIN_TEXT)
            if (value.isBlank()) return emptyList()
            val lines = value.trim().lines()
            require(lines.size in 1..MAX_CHAIN)
            return lines.map { decodePublic(it.trim(), 364, 9751) }
        }
        internal const val MAX_CHAIN = 64
        internal const val MAX_CHAIN_TEXT = MAX_CHAIN * (13004 + 1)
    }
}
