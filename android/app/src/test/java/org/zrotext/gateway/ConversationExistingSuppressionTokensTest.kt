// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Test
import org.junit.Assert.*
class ConversationExistingSuppressionTokensTest {
    @Test fun exactExistingDomainFramingMatchesSuppressionRows() {
        val key=SecretKeySpec(ByteArray(32){7},"HmacSHA256")
        val tokens=ConversationExistingSuppressionTokens {key}
        tokens.requireAvailable()
        val data=java.io.ByteArrayOutputStream()
        listOf("sender-v1","+123").forEach {val bytes=it.toByteArray(Charsets.US_ASCII)
            data.write(ByteBuffer.allocate(4).putInt(bytes.size).array());data.write(bytes)}
        val expected=Mac.getInstance("HmacSHA256").apply{init(key)}.doFinal(data.toByteArray())
            .joinToString(""){"%02x".format(it.toInt() and 255)}
        assertEquals(expected,tokens.sender("+123"))
    }
    @Test fun missingAndReplacementKeysFailClosedWithoutCreatingKey() {
        var reads=0
        val missing=ConversationExistingSuppressionTokens {reads++;error("missing")}
        assertThrows(IllegalStateException::class.java){missing.requireAvailable()};assertEquals(1,reads)
        var key=SecretKeySpec(ByteArray(32){1},"HmacSHA256")
        val tokens=ConversationExistingSuppressionTokens {key}
        tokens.requireAvailable();key=SecretKeySpec(ByteArray(32){2},"HmacSHA256")
        assertThrows(IllegalStateException::class.java){tokens.sender("+123")}
    }
    @Test fun wrongAlgorithmAndNonCanonicalPeerRefused() {
        assertThrows(IllegalStateException::class.java){ConversationExistingSuppressionTokens {
            SecretKeySpec(ByteArray(32),"AES")}.requireAvailable()}
        val tokens=ConversationExistingSuppressionTokens {SecretKeySpec(ByteArray(32),"HmacSHA256")}
        assertThrows(IllegalArgumentException::class.java){tokens.sender("123")}
    }
}
