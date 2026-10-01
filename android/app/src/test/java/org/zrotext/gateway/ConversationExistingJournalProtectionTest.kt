// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Test

class ConversationExistingJournalProtectionTest {
    @Test fun absentKeyNeverCreatesReplacementAndRefusesEveryOperation() {
        var reads = 0
        val protection = ConversationExistingJournalProtection {
            reads++
            throw ConversationExistingJournalProtection.Failure(ConversationExistingJournalProtection.Reason.MISSING_KEY)
        }
        assertEquals(0, reads)
        listOf<() -> Unit>({ protection.requireAvailable() }, { protection.seal("fixture", "fixture-aad") },
            { protection.open(InboundVault.Sealed(ByteArray(16), ByteArray(12)), "fixture-aad") }).forEach { action ->
            try { action(); fail("Missing key accepted") }
            catch (failure: ConversationExistingJournalProtection.Failure) {
                assertEquals(ConversationExistingJournalProtection.Reason.MISSING_KEY, failure.reason)
            }
        }
        assertEquals(3, reads)
    }
    @Test fun fixtureCiphertextBindsAadAndLostKeyNeverDecrypts() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        var available = true
        val protection = ConversationExistingJournalProtection { check(available); key }
        val sealed = protection.seal("synthetic body", "fixture-aad")
        assertEquals("synthetic body", protection.open(sealed, "fixture-aad"))
        try { protection.open(sealed, "other-aad"); fail("Changed AAD accepted") }
        catch (_: java.security.GeneralSecurityException) { }
        available = false
        try { protection.open(sealed, "fixture-aad"); fail("Lost key accepted") }
        catch (failure: ConversationExistingJournalProtection.Failure) {
            assertEquals(ConversationExistingJournalProtection.Reason.KEY_UNAVAILABLE, failure.reason)
        }
    }
}
