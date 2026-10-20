// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Display projection only; signature and live mapping authentication are separate runtime gates. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ConversationInterval03ReviewTest {
    @Test fun sameCountDifferentSignedMappingChangesTheExactVisibleReaderSelection(): Unit = ConversationInterval03TestFixture().use { fixture ->
        fun shown(connector: Long, grant: Long, key: Byte) = ConversationInterval03Mount.Review.from(
            ConversationInterval03.Statement.decode(fixture.statement().bytes().let { original ->
                ByteBuffer.allocate(original.size + 64).put(original.copyOf(original.size - 1)).put(1)
                    .putLong(0).putLong(connector).putLong(0).putLong(grant).put(ByteArray(32) { key }).array()
            }))
        val first = shown(41, 42, 1).integrationReaders().single()
        val second = shown(43, 44, 2).integrationReaders().single()
        assertEquals("01".repeat(32), first.fingerprint); assertEquals(UUID(0, 41), first.connector)
        assertEquals(UUID(0, 42), first.readGrant)
        assertNotEquals(first.fingerprint, second.fingerprint)
        assertNotEquals(first.connector, second.connector); assertNotEquals(first.readGrant, second.readGrant)
        assertTrue(ConversationInterval03Mount.Review.from(fixture.statement()).integrationReaders().isEmpty())
    }
}
