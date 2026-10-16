// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Separate one-shot review custody interface. No generic signer or ordinary authority. */
internal object AndroidReviewRootCustodyNativeBridge {
    val available:Boolean=try{System.loadLibrary("zrotext_android_owner_custody");true}catch(_:LinkageError){false}catch(_:SecurityException){false}
    external fun nativeOpen(challenge:ByteArray,backup:ByteArray,card:ByteArray,
        expectedAccount:ByteArray,expectedOrigin:String,expectedFingerprint:ByteArray,bundle:ByteArray,
        currentContext:ByteArray,serverMs:Long,anchoredElapsed:Long,uncertainty:Long,nowElapsed:Long):Long
    external fun nativeReview(handle:Long):ByteArray?
    external fun nativeSign(handle:Long,token:ByteArray,currentContext:ByteArray,nowElapsed:Long):Array<ByteArray>?
    external fun nativeClose(handle:Long)
    external fun nativeCloseAll()
}
internal interface AndroidReviewRootCustodyNativePort {
    val available:Boolean
    fun open(challenge:ByteArray,kit:AndroidOwnerCustodyKit,expected:AndroidOwnerCustodyIdentity,authority:AndroidReviewWorkspaceAuthority,elapsed:Long):Long
    fun review(handle:Long):ByteArray
    fun sign(handle:Long,token:ByteArray,authority:AndroidReviewWorkspaceAuthority,elapsed:Long):Array<ByteArray>
    fun close(handle:Long)
    fun closeAll()
}
internal class AndroidReviewRootCustodyNative:AndroidReviewRootCustodyNativePort {
    override val available get()=AndroidReviewRootCustodyNativeBridge.available
    override fun open(challenge:ByteArray,kit:AndroidOwnerCustodyKit,expected:AndroidOwnerCustodyIdentity,authority:AndroidReviewWorkspaceAuthority,elapsed:Long):Long {
        check(available)
        return AndroidReviewRootCustodyNativeBridge.nativeOpen(challenge.copyOf(),kit.backup(),kit.card(),expected.accountBytes(),expected.origin,
            expected.fingerprintBytes(),kit.bundleId,authority.nativeSnapshot(),authority.serverMs,authority.anchoredElapsedMs,authority.uncertaintyMs,elapsed)
    }
    override fun review(handle:Long):ByteArray=checkNotNull(AndroidReviewRootCustodyNativeBridge.nativeReview(handle))
    override fun sign(handle:Long,token:ByteArray,authority:AndroidReviewWorkspaceAuthority,elapsed:Long):Array<ByteArray> =
        try{checkNotNull(AndroidReviewRootCustodyNativeBridge.nativeSign(handle,token,authority.nativeSnapshot(),elapsed))}finally{token.fill(0)}
    override fun close(handle:Long){if(available)AndroidReviewRootCustodyNativeBridge.nativeClose(handle)}
    override fun closeAll(){if(available)AndroidReviewRootCustodyNativeBridge.nativeCloseAll()}
}
