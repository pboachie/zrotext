// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayInputStream
import org.junit.Assert.*
import org.junit.Test

class AndroidOwnerCustodyKitTest {
    @Test fun encryptedRecordRoundTripsPublicIdentityWithoutRecoveryToken() {
        val kit = AndroidOwnerCustodyFixture.kit
        assertTrue(AndroidOwnerCustodyKit.decode(kit.encode()).matches(kit))
        assertEquals(kit.identity, AndroidOwnerCustodyKit.decode(kit.encode()).identity)
    }
    @Test fun corruptedTruncatedOversizedAndSubstitutedCardAreRefused() {
        val kit = AndroidOwnerCustodyFixture.kit
        val backup = kit.backup(); backup[backup.lastIndex] = 1
        assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyKit(backup, kit.card()) }
        val card = kit.card(); card[20] = 0
        assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyKit(kit.backup(), card) }
        assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyKit.decode(kit.encode().copyOf(50)) }
        assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyKit.decode(ByteArray(AndroidOwnerCustodyKit.MAX_RECORD + 1)) }
    }
    @Test fun inputReaderRejectsOneExtraByteBeforeDecoding() {
        assertArrayEquals(byteArrayOf(1, 2, 3), readAndroidOwnerCustodyFile(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 3))
        assertThrows(IllegalArgumentException::class.java) { readAndroidOwnerCustodyFile(ByteArrayInputStream(ByteArray(4)), 3) }
        assertThrows(IllegalArgumentException::class.java) { readAndroidOwnerCustodyFile(ByteArrayInputStream(ByteArray(0)), 3) }
    }
    @Test fun tokenUsesExistingCanonicalAsciiSyntaxWithNoBase64Alias() {
        val text = String(AndroidOwnerCustodyFixture.token, Charsets.US_ASCII)
        assertArrayEquals(AndroidOwnerCustodyFixture.token, decodeAndroidOwnerRecoveryToken(text))
        for (bad in listOf(text.lowercase(), "$text\n", text.replaceFirst("AAAA", "aaaa"), java.util.Base64.getEncoder().encodeToString(AndroidOwnerCustodyFixture.token)))
            assertThrows(IllegalArgumentException::class.java) { decodeAndroidOwnerRecoveryToken(bad) }
    }
    @Test fun explicitIdentityRejectsUrlAliasesAndZeroAccounts() {
        for (origin in listOf("http://owner.invalid", "https://owner.invalid/", "https://owner.invalid:443", "https://owner.invalid:08443", "https://OWNER.invalid", "https://owner.invalid?query=1"))
            assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyIdentity(AndroidOwnerCustodyFixture.account, origin, "11".repeat(32)) }
        assertThrows(IllegalArgumentException::class.java) { AndroidOwnerCustodyIdentity(java.util.UUID(0, 0), AndroidOwnerCustodyFixture.origin, "11".repeat(32)) }
    }
    @Test fun reviewDisplaysExactAccountOriginRootOwnerSessionAndExpiry() {
        val review = AndroidOwnerCustodyReview.parse(AndroidOwnerCustodyFixture.challenge())
        assertEquals(AndroidOwnerCustodyFixture.account, review.account); assertEquals(AndroidOwnerCustodyFixture.user, review.user)
        assertEquals(AndroidOwnerCustodyFixture.session, review.session); assertEquals(AndroidOwnerCustodyFixture.origin, review.origin)
        assertEquals(AndroidOwnerCustodyFixture.kit.identity.fingerprint, review.fingerprint); assertEquals(61000L, review.expiresMs)
    }
}
