// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class ConversationReplyTextTest {
    @Test fun canonicalPublicCandidatePreservesExactManifestAndSigner() {
        val (text, manifest, signer) = conversationReplyTextFixture()
        val result = decodeConversationReplyText(text)
        assertArrayEquals(manifest, result.signedSuccessor()); assertArrayEquals(signer, result.signerId())
    }
    @Test fun exactDecodedMaximumIsAcceptedButEncodedOrDecodedOverflowIsRejected() {
        val (text, manifest, _) = conversationReplyTextFixture(16384)
        assertEquals(21900, text.length)
        assertArrayEquals(manifest, decodeConversationReplyText(text).signedSuccessor())
        for (invalid in listOf("A".repeat(21904), "A".repeat(21900)))
            assertThrows(IllegalArgumentException::class.java) { decodeConversationReplyText(invalid) }
    }
    @Test fun whitespacePartialAndUrlSafeInputsAreNeverRepaired() {
        val (text, _, _) = conversationReplyTextFixture()
        for (invalid in listOf(" $text", "$text\n", text.dropLast(1), "----", "", text.replaceFirst('B', '-')))
            assertThrows(IllegalArgumentException::class.java) { decodeConversationReplyText(invalid) }
    }
    @Test fun noncanonicalPaddingBitsCannotAliasTheSameCandidate() {
        val (text, _, _) = conversationReplyTextFixture()
        assertTrue(text.endsWith("=="))
        val chars = text.toCharArray(); val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        chars[chars.size - 3] = alphabet[alphabet.indexOf(chars[chars.size - 3]) + 1]
        assertThrows(IllegalArgumentException::class.java) { decodeConversationReplyText(String(chars)) }
    }
}

/** Public wrapper fixture only; a controller must independently verify its signed authority. */
internal fun conversationReplyTextFixture(length: Int = 364): Triple<String, ByteArray, ByteArray> {
    val manifest = ByteArray(length) { 7 }; val signer = ByteArray(32) { 6 }
    val output = ByteArrayOutputStream()
    DataOutputStream(output).use { stream ->
        stream.write(byteArrayOf(90, 84, 80, 82, 1)); stream.writeShort(length); stream.write(manifest); stream.write(signer)
    }
    return Triple(Base64.getEncoder().encodeToString(output.toByteArray()), manifest, signer)
}
