// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/** Reads the established suppression key only; never creates/replaces it. Pins its identity for
 * this connection using a domain-separated MAC probe, without exporting key material. */
internal class ConversationExistingSuppressionTokens internal constructor(private val existingKey:()->SecretKey) {
    constructor():this({
        val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        checkNotNull(store.getKey(ALIAS,null) as? SecretKey)
    })
    private val lock=Any()
    private var identity:ByteArray?=null
    private fun mac(key:SecretKey,domain:String,fields:Array<out ByteArray>):ByteArray {
        check(key.algorithm.equals("HmacSHA256",ignoreCase=true))
        val data=ByteArrayOutputStream()
        for(field in arrayOf(domain.toByteArray(Charsets.US_ASCII),*fields)) {
            require(field.size<=8192)
            data.write((field.size ushr 24) and 255);data.write((field.size ushr 16) and 255)
            data.write((field.size ushr 8) and 255);data.write(field.size and 255);data.write(field)
        }
        return Mac.getInstance("HmacSHA256").apply {init(key)}.doFinal(data.toByteArray())
    }
    fun requireAvailable()=synchronized(lock) { key();Unit }
    private fun key():SecretKey {
        val key=existingKey()
        val probe=mac(key,"zrotext-conversation-suppression-continuity-v1",emptyArray())
        val pinned=identity
        if(pinned==null)identity=probe.copyOf() else check(MessageDigest.isEqual(pinned,probe))
        probe.fill(0)
        return key
    }
    fun sender(peer:String):String=synchronized(lock) {
        require(peer.matches(Regex("\\+[1-9][0-9]{1,14}")))
        mac(key(),"sender-v1",arrayOf(peer.toByteArray(Charsets.US_ASCII))).joinToString("") {"%02x".format(it.toInt() and 255)}
    }
    override fun toString()="ConversationExistingSuppressionTokens(redacted)"
    companion object {const val ALIAS="zt_m1_inbound_hmac_v1"}
}
