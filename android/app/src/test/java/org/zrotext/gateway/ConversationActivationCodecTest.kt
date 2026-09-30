// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class ConversationActivationCodecTest {
    private val vector = "5a54434101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b100000000000000013131313131313131313131313131313141414141414141414141414141414141515151515151515151515151515151516161616161616161616161616161616161616161616161616161616161616161000001e8f1c10800032b313217636f6e766572736174696f6e2d636f6e74656e742d7631059d0d3aa72a6b03303e86000241fc71cd452714356f51617ae2bb02c5b85ece717171717171717171717171717171717171717171717171717171717171717181818181818181818181818181818181818181818181818181818181818181810000000000000001000000000000000191919191919191919191919191919191919191919191919191919191919191910000000000000002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2000000000000000100000000000000010c666978747572652d7369746510666978747572652d696e7374616e6365".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun canonicalServerVectorBindsExactScopeAndDomains() {
        val parsed = ConversationActivationCodec.decode(vector)
        assertEquals("+12", parsed.scope.peer)
        assertEquals(2L, parsed.scope.activationVersion)
        assertEquals("8506fb9cec0957933e156fad8c44fce7fa2328eeac0c363ba36a4e85fa31576a", parsed.scope.transcriptDigest)
        assertEquals("fixture-site", parsed.site)
        assertEquals("fixture-instance", parsed.instance)
        val approve = ConversationActivationCodec.transcript(ConversationActivationCodec.APPROVE_DOMAIN, vector)
        val install = ConversationActivationCodec.transcript(ConversationActivationCodec.INSTALL_DOMAIN, vector)
        assertFalse(approve.contentEquals(install))
        assertFalse(MessageDigest.getInstance("SHA-256").digest(approve).contentEquals(MessageDigest.getInstance("SHA-256").digest(install)))
        for (end in vector.indices) assertThrows(Exception::class.java) { ConversationActivationCodec.decode(vector.copyOf(end)) }
        assertThrows(IllegalArgumentException::class.java) { ConversationActivationCodec.decode(vector + byteArrayOf(0)) }
    }
}
