// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayInputStream
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class ConversationSetupFileTest {
    @Test fun exactSetupAndReplyLimitsAreAccepted() {
        for (limit in listOf(1128, 16423)) assertEquals(limit,
            readConversationSetupFile(ByteArrayInputStream(ByteArray(limit)), limit).size)
    }
    @Test fun firstOverflowByteIsRejectedBeforeProviderCopies() {
        for (limit in listOf(1128, 16423)) {
            val input = ByteArrayInputStream(ByteArray(limit + 100))
            assertThrows(IllegalArgumentException::class.java) { readConversationSetupFile(input, limit) }
            assertEquals(99, input.available())
        }
    }
    @Test fun emptyPublicCandidateCannotBeAccepted() {
        assertThrows(IllegalArgumentException::class.java) { readConversationSetupFile(ByteArrayInputStream(byteArrayOf()), 1128) }
    }
    @Test fun selectedSimCannotRelabelAnotherAuthoritativeLineOrGeneration() {
        val account = UUID.randomUUID().toString(); val device = UUID.randomUUID().toString(); val line = UUID.randomUUID().toString()
        val selection = ConversationUserSetupController.Selection(EvidenceIdentity(account, device, "a".repeat(64)),
            UUID.randomUUID().toString(), line, 1, "+12", ConversationConnectionBindings(ByteArray(65), ByteArray(32)), "fixture-site", "fixture-instance")
        val binding = LocalLineBinding(accountId = account, deviceId = device, lineId = line,
            generation = 1, subscriptionId = 1, installedAtMs = 1)
        val labels = mapOf(1 to "Fixture line A", 2 to "Fixture line B")
        assertNull(conversationEntryLineLabel(binding, selection, 2, labels))
        assertEquals("Fixture line A", conversationEntryLineLabel(binding, selection, 1, labels))
        assertNull(conversationEntryLineLabel(binding.copy(generation = 2), selection, 1, labels))
    }
}
