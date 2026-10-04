// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest

/** Public local custody metadata. Neither a root grant nor a hardware attestation. */
internal sealed interface PayloadKeyRecord {
    data object Absent : PayloadKeyRecord
    data object Pending : PayloadKeyRecord
    class Bound(keyId: ByteArray) : PayloadKeyRecord {
        private val id = keyId.copyOf()
        fun keyId(): ByteArray = id.copyOf()
    }
    class Revoked(keyId: ByteArray) : PayloadKeyRecord {
        private val id = keyId.copyOf()
        fun keyId(): ByteArray = id.copyOf()
    }
}

internal interface PayloadKeyRecordAccess {
    fun read(): PayloadKeyRecord
    fun write(record: PayloadKeyRecord)
}

/** Holds a shared thread/process lock across metadata and the complete key operation. */
internal interface PayloadKeyRecordStore {
    fun <T> locked(operation: (PayloadKeyRecordAccess) -> T): T
}

/** The persisted pending fence precedes key generation. Loss, revocation and
 * interrupted enrollment never become an implicit request for a new identity. */
internal class PayloadKeyLifecycle(private val store: PayloadKeyRecordStore) {
    fun <T> enroll(exists: () -> Boolean, create: () -> Unit, load: () -> T,
                   keyId: (T) -> ByteArray): T {
        PayloadKeyCustodyEntry.requireUnscopedEntry()
        return store.locked { record ->
            when (val state = record.read()) {
                PayloadKeyRecord.Absent -> {
                    check(!exists()) { "Unregistered payload recipient identity" }
                    record.write(PayloadKeyRecord.Pending)
                    create()
                    val material = load()
                    val id = checkedId(keyId(material))
                    record.write(PayloadKeyRecord.Bound(id))
                    material
                }
                is PayloadKeyRecord.Bound -> {
                    val material = load()
                    check(MessageDigest.isEqual(state.keyId(), checkedId(keyId(material)))) {
                        "Payload recipient identity changed"
                    }
                    material
                }
                else -> error("Payload recipient enrollment unavailable")
            }
        }
    }

    fun <T, R> existing(pinnedKeyId: ByteArray?, load: () -> T,
                       keyId: (T) -> ByteArray, use: (T) -> R): R {
        PayloadKeyCustodyEntry.requireUnscopedEntry()
        val pinned = pinnedKeyId?.let(::checkedId)
        return store.locked { record ->
            val state = record.read() as? PayloadKeyRecord.Bound
                ?: error("Payload recipient custody unavailable")
            if (pinned != null) require(MessageDigest.isEqual(state.keyId(), pinned)) {
                "Payload key identity changed"
            }
            val material = load()
            check(MessageDigest.isEqual(state.keyId(), checkedId(keyId(material)))) {
                "Payload recipient identity changed"
            }
            use(material)
        }
    }

    /** Material stays in the trusted adapter; scope methods expose no private handle. */
    fun <T, R> scopedExisting(pinnedKeyId: ByteArray, source: PayloadKeyCustodySource<T>,
                            use: (T, PayloadKeyCustodyScope) -> R): R {
        PayloadKeyCustodyEntry.requireUnscopedEntry()
        val pinned = checkedId(pinnedKeyId)
        return store.locked { record ->
            val token = PayloadKeyCustodyEntry.enter()
            var scope: PayloadKeyCustodyScope? = null
            try {
                val initial = loadBound(record, pinned, source)
                val owned = PayloadKeyCustodyScope(token, Thread.currentThread()) {
                    source.requireSameIdentity(initial, loadBound(record, pinned, source))
                }
                scope = owned
                val result = use(initial, owned)
                owned.revalidate() // The SAME record access/file lock is still held.
                result
            } finally {
                scope?.expire()
                PayloadKeyCustodyEntry.leave(token)
            }
        }
    }

    private fun <T> loadBound(record: PayloadKeyRecordAccess, pinned: ByteArray,
                             source: PayloadKeyCustodySource<T>): T {
        fun requireBound() {
            val state = record.read() as? PayloadKeyRecord.Bound
                ?: error("Payload recipient custody unavailable")
            require(MessageDigest.isEqual(state.keyId(), pinned)) { "Payload key identity changed" }
        }
        requireBound()
        val material = source.load()
        check(MessageDigest.isEqual(pinned, checkedId(source.keyId(material)))) {
            "Payload recipient identity changed"
        }
        requireBound() // Reload may have waited; do not rely only on the earlier record read.
        return material
    }

    fun revoke(pinnedKeyId: ByteArray) {
        PayloadKeyCustodyEntry.requireUnscopedEntry()
        val pinned = checkedId(pinnedKeyId)
        store.locked { record ->
            val state = record.read()
            val id = when (state) {
                is PayloadKeyRecord.Bound -> state.keyId()
                is PayloadKeyRecord.Revoked -> state.keyId()
                else -> error("Payload recipient custody unavailable")
            }
            require(MessageDigest.isEqual(id, pinned)) { "Payload key identity changed" }
            if (state !is PayloadKeyRecord.Revoked) record.write(PayloadKeyRecord.Revoked(id))
        }
    }

    private fun checkedId(value: ByteArray): ByteArray {
        require(value.size == 32 && value.any { it != 0.toByte() }) { "Invalid payload key ID" }
        return value.copyOf()
    }
}
