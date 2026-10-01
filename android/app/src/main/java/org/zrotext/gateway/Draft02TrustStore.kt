// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Dormant persistence, never permission for envelope/grant effects. Every load remains NeedsFreshness. */
internal class Draft02TrustStore(private val storage: Storage) {
    enum class Status { UNENROLLED_NEEDS_COMPARISON, NEEDS_FRESHNESS, RECOVERY_REQUIRED, KEY_LOST,
        CORRUPT, UNSUPPORTED, CONFLICT, STALE, REJECTED, IO_FAILURE }
    enum class KeyState { ABSENT, READY, UNSUPPORTED }
    class Failure(val status: Status) : Exception()
    class Result internal constructor(val status: Status, val snapshot: Snapshot? = null)
    class Snapshot internal constructor(state: ByteArray) {
        private val state = state.copyOf()
        internal fun bytes() = state.copyOf()
        val revision: Long get() = ByteBuffer.wrap(state, 5, 8).long
        val version: Long get() = ByteBuffer.wrap(state, 13, 8).long
        val verifiedAtMs: Long get() = ByteBuffer.wrap(state, 21, 8).long
        val pin: ByteArray get() = state.copyOfRange(29, 123)
        override fun toString() = "PersistedRootNeedsFreshness"
    }
    interface Storage {
        fun <T> locked(action: Session.() -> T): T
    }
    interface Session {
        fun keyState(): KeyState
        /** Null means absent, not a decoding error. Orphaned partial writes must not appear absent. */
        fun read(): ByteArray?
        fun createKey()
        fun seal(plaintext: ByteArray): ByteArray
        fun open(ciphertext: ByteArray): ByteArray
        /** Must preserve old-or-new bytes atomically; preCommit runs after blocking writes, before commit. */
        fun write(ciphertext: ByteArray, preCommit: () -> Unit)
    }

    fun inspect(): Result = guarded { storage.locked { readState() } }

    /** Reverify existing accepted bytes against independently authenticated current UTC.
     * Creates no key and does not promote stored time into live authority.
     */
    fun currentAuthority(trustedNow: () -> Long): Draft02ManifestAuthority = storage.locked {
        val current=readState();val saved=checkNotNull(current.snapshot)
        check(current.status==Status.NEEDS_FRESHNESS && saved.version>0)
        val decoded=decode(saved.bytes());val now=trustedNow();check(now>0 && now>=decoded.time)
        val trust=Draft02ManifestAuthority.Trust(decoded.pin.copyOfRange(5,21),Draft02RootComparison.fingerprint(decoded.pin),1,
            Draft02ManifestAuthority.Position.current(decoded.version,digest(decoded.manifest)))
        val result=Draft02ManifestAuthority.verify(decoded.pin,decoded.manifest,trust,now)
        val finalNow=trustedNow();check(finalNow>=now);Draft02ManifestAuthority.verify(decoded.pin,decoded.manifest,trust,finalNow)
        result
    }

    fun enroll(receipt: Draft02RootComparison.Receipt): Result = guarded {
        // Consume even on conflict/failure: retry requires a new deliberate comparison.
        val pin = receipt.consume()
        storage.locked {
            receipt.requireCurrent()
            val current = readState()
            if (current.status != Status.UNENROLLED_NEEDS_COMPARISON) {
                return@locked if (current.status == Status.NEEDS_FRESHNESS) Result(Status.CONFLICT) else current
            }
            receipt.requireCurrent()
            createKey() // The only key-creation path; an interrupted initial enrollment requires recovery.
            if (keyState() != KeyState.READY) return@locked Result(Status.UNSUPPORTED)
            val encoded = encode(1, 0, 0, pin, ByteArray(0))
            write(seal(encoded)) { receipt.requireCurrent() }
            Result(Status.NEEDS_FRESHNESS, Snapshot(encoded))
        }
    }

    /**
     * Caller supplies an independently trusted clock, not a relay or OS-clock promotion.
     * No provider is implemented here. Return value still requires fresh trust and live-grant fences.
     */
    fun acceptManifest(expected: Snapshot, manifest: ByteArray, trustedNow: () -> Long): Result = guarded {
        require(manifest.size in 364..9751)
        val bytes = manifest.copyOf()
        storage.locked {
            val current = readState()
            val snapshot = current.snapshot ?: return@locked current
            if (!MessageDigest.isEqual(snapshot.bytes(), expected.bytes())) return@locked Result(Status.STALE)
            val old = decode(snapshot.bytes())
            val pin = old.pin
            val fingerprint = Draft02RootComparison.fingerprint(pin)
            val oldDigest = if (old.manifest.isEmpty()) ByteArray(32) else digest(old.manifest)
            val candidateVersion = ByteBuffer.wrap(bytes, 29, 8).long
            val position = when {
                old.version == 0L -> Draft02ManifestAuthority.Position.genesis(ByteArray(32))
                candidateVersion == old.version -> Draft02ManifestAuthority.Position.current(old.version, oldDigest)
                else -> Draft02ManifestAuthority.Position.after(old.version, oldDigest)
            }
            val trust = Draft02ManifestAuthority.Trust(pin.copyOfRange(5, 21), fingerprint, 1, position)
            val now = trustedNow()
            require(now >= old.time && now > 0) { "Clock regression" }
            val verified = Draft02ManifestAuthority.verify(pin, bytes, trust, now)
            require(old.revision < Long.MAX_VALUE) { "Revision exhausted" }
            val encoded = encode(old.revision + 1, verified.version, now, pin, bytes)
            val ciphertext = seal(encoded)
            write(ciphertext) {
                val finalNow = trustedNow()
                require(finalNow >= now) { "Clock regression during write" }
                Draft02ManifestAuthority.verify(pin, bytes, trust, finalNow)
            }
            Result(Status.NEEDS_FRESHNESS, Snapshot(encoded))
        }
    }

    private fun Session.readState(): Result {
        val key = keyState()
        if (key == KeyState.UNSUPPORTED) return Result(Status.UNSUPPORTED)
        val ciphertext = read()
        if (ciphertext == null) return Result(if (key == KeyState.ABSENT) Status.UNENROLLED_NEEDS_COMPARISON else Status.RECOVERY_REQUIRED)
        if (key == KeyState.ABSENT) return Result(Status.KEY_LOST)
        if (ciphertext.size > MAX_BYTES) throw Failure(Status.CORRUPT)
        val plaintext = open(ciphertext)
        try {
            val decoded = decode(plaintext)
            // Verify at the recorded time, never treating that time as present time.
            if (decoded.version > 0) {
                val trust = Draft02ManifestAuthority.Trust(decoded.pin.copyOfRange(5, 21),
                    Draft02RootComparison.fingerprint(decoded.pin), 1,
                    Draft02ManifestAuthority.Position.current(decoded.version, digest(decoded.manifest)))
                Draft02ManifestAuthority.verify(decoded.pin, decoded.manifest, trust, decoded.time)
            }
            return Result(Status.NEEDS_FRESHNESS, Snapshot(plaintext))
        } catch (_: IllegalArgumentException) { throw Failure(Status.CORRUPT) }
          catch (_: IllegalStateException) { throw Failure(Status.CORRUPT) }
    }

    private class Record(val revision: Long, val version: Long, val time: Long, val pin: ByteArray, val manifest: ByteArray)
    private fun decode(bytes: ByteArray): Record {
        require(bytes.size in 127..MAX_BYTES && bytes.copyOfRange(0, 5).contentEquals(MAGIC))
        val buffer = ByteBuffer.wrap(bytes)
        val revision = buffer.getLong(5)
        val version = buffer.getLong(13)
        val time = buffer.getLong(21)
        val pin = Draft02RootComparison.validatePin(bytes.copyOfRange(29, 123))
        val size = buffer.getInt(123)
        require(revision > 0 && version >= 0 && time >= 0 && size in 0..9751 && bytes.size == 127 + size)
        require(if (version == 0L) size == 0 && time == 0L else size >= 364 && time > 0)
        return Record(revision, version, time, pin, bytes.copyOfRange(127, bytes.size))
    }
    private fun encode(revision: Long, version: Long, time: Long, pin: ByteArray, manifest: ByteArray): ByteArray =
        ByteBuffer.allocate(127 + manifest.size).put(MAGIC).putLong(revision).putLong(version).putLong(time)
            .put(pin).putInt(manifest.size).put(manifest).array()
    private fun digest(manifest: ByteArray) = MessageDigest.getInstance("SHA-256").digest(manifest.copyOfRange(0, manifest.size - 64))
    private fun guarded(action: () -> Result): Result = try { action() }
        catch (failure: Failure) { Result(failure.status) }
        catch (_: IllegalArgumentException) { Result(Status.REJECTED) }
        catch (_: IllegalStateException) { Result(Status.REJECTED) }

    companion object {
        internal const val MAX_BYTES = 16 * 1024
        private val MAGIC = byteArrayOf(0x5a, 0x54, 0x54, 0x53, 1)
    }
}
