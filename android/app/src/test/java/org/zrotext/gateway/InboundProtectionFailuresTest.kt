// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

/** Pure negative-error ordering. These ports supply no key, pin or usable effect lease. */
class InboundProtectionFailuresTest {
    @Test fun originalFailureAndBothNegativeWriteFailuresRemainInTheStableRefusal() {
        val original = IOException("synthetic original storage fault")
        val file = IOException("synthetic negative file failure")
        val room = IllegalStateException("synthetic negative Room failure")
        val events = mutableListOf<String>(); var withdrawn = false
        val refusal = assertThrows(InboundProtection.Unavailable::class.java) {
            InboundProtectionFailures.refuse("storage_unavailable", original) {
                InboundProtectionFailures.persist({ withdrawn = true; events += "ram" },
                    { check(withdrawn); events += "files"; throw file },
                    { check(withdrawn); events += "room"; throw room })
            }
        }
        assertEquals(listOf("ram", "files", "room"), events)
        assertSame(original, refusal.cause); assertEquals("storage_unavailable", refusal.reason)
        assertEquals(1, refusal.suppressed.size); assertSame(room, refusal.suppressed.single())
        assertEquals(1, room.suppressed.size); assertSame(file, room.suppressed.single())
    }

    @Test fun successfulNegativeWritesStillRefuseTheOriginalOperation() {
        val original = IOException("synthetic original fault"); val events = mutableListOf<String>()
        val refusal = assertThrows(InboundProtection.Unavailable::class.java) {
            InboundProtectionFailures.refuse("storage_unavailable", original) {
                InboundProtectionFailures.persist({ events += "ram" }, { events += "files" }, { events += "room" })
            }
        }
        assertSame(original, refusal.cause); assertTrue(refusal.suppressed.isEmpty())
        assertEquals(listOf("ram", "files", "room"), events)
    }

    @Test fun aFileFailureDoesNotSkipRoomOrReturnSuccess() {
        val file = IOException("synthetic directory flush fault"); var roomWrites = 0
        val thrown = assertThrows(IOException::class.java) {
            InboundProtectionFailures.persist({}, { throw file }, { roomWrites++ })
        }
        assertSame(file, thrown); assertEquals(1, roomWrites)
    }

    @Test fun aRoomFailureAfterSuccessfulFilePersistenceIsPreserved() {
        val room = IllegalStateException("synthetic Room fault"); val events = mutableListOf<String>()
        val thrown = assertThrows(IllegalStateException::class.java) {
            InboundProtectionFailures.persist({ events += "ram" }, { events += "files" }, { events += "room"; throw room })
        }
        assertSame(room, thrown); assertEquals(listOf("ram", "files", "room"), events)
    }

    @Test fun oneSharedStorageFailureIsNeverSuppressedOntoItself() {
        val shared = IOException("synthetic shared storage fault")
        val refusal = assertThrows(InboundProtection.Unavailable::class.java) {
            InboundProtectionFailures.refuse("storage_unavailable", shared) {
                InboundProtectionFailures.persist({}, { throw shared }, { throw shared })
            }
        }
        assertSame(shared, refusal.cause); assertTrue(shared.suppressed.isEmpty()); assertTrue(refusal.suppressed.isEmpty())
    }
}
