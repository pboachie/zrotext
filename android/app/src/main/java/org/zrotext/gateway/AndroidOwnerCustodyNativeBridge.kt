// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Narrow typed JNI surface. No root scalar, general signing, or persistent unlocked signer. */
internal object AndroidOwnerCustodyNativeBridge {
    val available: Boolean = try { System.loadLibrary("zrotext_android_owner_custody"); true } catch (_: LinkageError) { false } catch (_: SecurityException) { false }
    external fun nativeCreate(account: ByteArray, origin: String): Array<ByteArray>?
    external fun nativeRecoveryCheck(backup: ByteArray, card: ByteArray, token: ByteArray,
        expectedAccount: ByteArray, expectedOrigin: String, expectedFingerprint: ByteArray): Boolean
    external fun nativeOpenCustody(challenge: ByteArray, backup: ByteArray, card: ByteArray,
        expectedAccount: ByteArray, expectedOrigin: String, expectedFingerprint: ByteArray, expectedBundleId: ByteArray,
        currentAccount: ByteArray, currentUser: ByteArray, currentSession: ByteArray,
        authenticatedServerTimeMs: Long, authenticatedAtElapsedRealtimeMs: Long, uncertaintyMs: Long,
        nowElapsedRealtimeMs: Long): Long
    external fun nativeReviewCustody(handle: Long): ByteArray?
    external fun nativeSignCustody(handle: Long, token: ByteArray, currentAccount: ByteArray,
        currentUser: ByteArray, currentSession: ByteArray, nowElapsedRealtimeMs: Long): Array<ByteArray>?
    external fun nativeClose(handle: Long)
    external fun nativeCloseAll()
    external fun nativeOpenTyped(kind: Int, proposal: ByteArray, expectedJson: ByteArray, backup: ByteArray, card: ByteArray,
        expectedAccount: ByteArray, expectedOrigin: String, expectedFingerprint: ByteArray,
        currentAccount: ByteArray, currentUser: ByteArray, currentSession: ByteArray,
        serverMs: Long, anchoredElapsed: Long, uncertainty: Long, nowElapsed: Long): Long
    external fun nativeReviewTyped(handle: Long): Array<ByteArray>?
    external fun nativeSignTyped(handle: Long, rootToken: ByteArray, archiveBackup: ByteArray, archiveRecovery: ByteArray,
        currentAccount: ByteArray, currentUser: ByteArray, currentSession: ByteArray, nowElapsed: Long): Array<ByteArray>?
    external fun nativeArchiveRecoveryCheck(archiveBackup: ByteArray, recovery: ByteArray, expectedAccount: ByteArray,
        expectedOrigin: String, rootFingerprint: ByteArray, archiveId: ByteArray, archivePoint: ByteArray): Boolean
}

internal interface AndroidOwnerCustodyNativePort {
    val available: Boolean
    fun create(account: ByteArray, origin: String): Array<ByteArray>
    fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity): Boolean
    fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
        authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long
    fun review(handle: Long): ByteArray
    fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray>
    fun close(handle: Long)
    fun closeAll()
    fun openTyped(kind: Int, proposal: ByteArray, expectedJson: ByteArray, kit: AndroidOwnerCustodyKit,
        expected: AndroidOwnerCustodyIdentity, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long =
        error("Typed native custody unavailable")
    fun reviewTyped(handle: Long): Array<ByteArray> = error("Typed native custody unavailable")
    fun signTyped(handle: Long, token: ByteArray, archiveBackup: ByteArray, archiveRecovery: ByteArray,
        authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> = error("Typed native custody unavailable")
    fun archiveRecoveryCheck(backup: ByteArray, recovery: ByteArray, expected: AndroidOwnerCustodyIdentity,
        archiveId: ByteArray, archivePoint: ByteArray): Boolean = error("Typed native custody unavailable")
}

internal class AndroidOwnerCustodyNative : AndroidOwnerCustodyNativePort {
    override val available get() = AndroidOwnerCustodyNativeBridge.available
    private fun requireAvailable() { check(available) { "Native owner custody unavailable" } }
    override fun create(account: ByteArray, origin: String): Array<ByteArray> {
        requireAvailable(); return checkNotNull(AndroidOwnerCustodyNativeBridge.nativeCreate(account, origin))
    }
    override fun recoveryCheck(kit: AndroidOwnerCustodyKit, token: ByteArray, expected: AndroidOwnerCustodyIdentity): Boolean {
        requireAvailable()
        return AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(kit.backup(), kit.card(), token,
            expected.accountBytes(), expected.origin, expected.fingerprintBytes())
    }
    override fun open(challenge: ByteArray, kit: AndroidOwnerCustodyKit, expected: AndroidOwnerCustodyIdentity,
        authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long {
        requireAvailable()
        return AndroidOwnerCustodyNativeBridge.nativeOpenCustody(challenge, kit.backup(), kit.card(), expected.accountBytes(),
            expected.origin, expected.fingerprintBytes(), kit.bundleId, authority.bytes(authority.account), authority.bytes(authority.user),
            authority.bytes(authority.session), authority.utcMs, authority.anchoredElapsedMs, authority.uncertaintyMs, elapsed)
    }
    override fun review(handle: Long): ByteArray {
        requireAvailable(); return checkNotNull(AndroidOwnerCustodyNativeBridge.nativeReviewCustody(handle))
    }
    override fun sign(handle: Long, token: ByteArray, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> {
        requireAvailable()
        return checkNotNull(AndroidOwnerCustodyNativeBridge.nativeSignCustody(handle, token, authority.bytes(authority.account),
            authority.bytes(authority.user), authority.bytes(authority.session), elapsed))
    }
    override fun close(handle: Long) { if (available && handle > 0) AndroidOwnerCustodyNativeBridge.nativeClose(handle) }
    override fun closeAll() { if (available) AndroidOwnerCustodyNativeBridge.nativeCloseAll() }
    override fun openTyped(kind: Int, proposal: ByteArray, expectedJson: ByteArray, kit: AndroidOwnerCustodyKit,
        expected: AndroidOwnerCustodyIdentity, authority: AndroidOwnerCustodyAuthority, elapsed: Long): Long {
        requireAvailable()
        return AndroidOwnerCustodyNativeBridge.nativeOpenTyped(kind, proposal, expectedJson, kit.backup(), kit.card(),
            expected.accountBytes(), expected.origin, expected.fingerprintBytes(), authority.bytes(authority.account),
            authority.bytes(authority.user), authority.bytes(authority.session), authority.utcMs,
            authority.anchoredElapsedMs, authority.uncertaintyMs, elapsed)
    }
    override fun reviewTyped(handle: Long): Array<ByteArray> {
        requireAvailable(); return checkNotNull(AndroidOwnerCustodyNativeBridge.nativeReviewTyped(handle))
    }
    override fun signTyped(handle: Long, token: ByteArray, archiveBackup: ByteArray, archiveRecovery: ByteArray,
        authority: AndroidOwnerCustodyAuthority, elapsed: Long): Array<ByteArray> {
        requireAvailable()
        return checkNotNull(AndroidOwnerCustodyNativeBridge.nativeSignTyped(handle, token, archiveBackup, archiveRecovery,
            authority.bytes(authority.account), authority.bytes(authority.user), authority.bytes(authority.session), elapsed))
    }
    override fun archiveRecoveryCheck(backup: ByteArray, recovery: ByteArray, expected: AndroidOwnerCustodyIdentity,
        archiveId: ByteArray, archivePoint: ByteArray): Boolean {
        requireAvailable()
        return AndroidOwnerCustodyNativeBridge.nativeArchiveRecoveryCheck(backup, recovery, expected.accountBytes(),
            expected.origin, expected.fingerprintBytes(), archiveId, archivePoint)
    }
}
