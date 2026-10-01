// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.io.*
import java.util.Base64

/** Versioned content INSIDE the existing protectedScope column and existing AAD, not a new store.
 * Original canonical approval bytes preserve closed-only ACK recovery after server statement erasure.
 * Legacy scope-only records still read; they cannot reconstruct a missing original proof.
 */
internal object ConversationProtectedInstallation {
    class Value(val scope:ConversationCaptureScope, original:ByteArray?) {
        val originalStatement=original?.copyOf()
        override fun toString()="ProtectedConversationInstallation(redacted)"
    }
    fun encode(scope:ConversationCaptureScope, original:ByteArray?):String {
        if(original==null)return scope.encode()
        require(ConversationActivationCodec.decode(original).scope==scope)
        val bytes=ByteArrayOutputStream()
        DataOutputStream(bytes).use{it.writeInt(2);it.writeUTF(scope.encode());it.writeShort(original.size);it.write(original)}
        return Base64.getEncoder().encodeToString(bytes.toByteArray())
    }
    fun decode(encoded:String):Value {
        require(encoded.length<=65536)
        val bytes=Base64.getDecoder().decode(encoded)
        DataInputStream(ByteArrayInputStream(bytes)).use {
            if(it.readInt()==1)return Value(ConversationCaptureScope.decode(encoded),null)
        }
        return DataInputStream(ByteArrayInputStream(bytes)).use {
            require(it.readInt()==2)
            val scope=ConversationCaptureScope.decode(it.readUTF());val length=it.readUnsignedShort()
            require(length in 380..1024)
            val original=ByteArray(length).also(it::readFully)
            require(it.available()==0 && ConversationActivationCodec.decode(original).scope==scope)
            Value(scope,original)
        }
    }
}
