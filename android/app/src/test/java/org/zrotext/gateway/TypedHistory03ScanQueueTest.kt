// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

/** The actual runtime queue/cursor component; no model of Room or transport authority. */
class TypedHistory03ScanQueueTest {
    private fun full(prefix: String) = (0..15).map { "$prefix${it.toString().padStart(2, '0')}" }
    private fun overflow(queue: TypedHistory03ScanQueue, behindCursor: String) {
        val queued = full("queued")
        queued.forEach(queue::enqueue)
        queue.enqueue(behindCursor)
        assertEquals(queued, (0..15).map { queue.nextQueued() })
        assertNull(queue.nextQueued()) // the 17th ID is durable scan work, not an unbounded RAM item.
    }

    @Test fun overflowBehindTheFirstPageRequiresWraparoundAfterTheLaterFinalPage() {
        val queue = TypedHistory03ScanQueue(); val host = Any()
        queue.enqueue(null)
        val first = queue.page(host)
        val earlierPage = full("middle")
        queue.complete(first, earlierPage)
        overflow(queue, "a-behind")
        val next = queue.page(host)
        assertEquals(earlierPage.last(), next.after)
        assertEquals(first.generation, next.generation)
        queue.complete(next, listOf("z-final"))
        assertTrue(queue.hasWork()); assertTrue(queue.needsScan())
        val wraparound = queue.page(host)
        assertEquals("", wraparound.after)
        assertTrue(wraparound.generation > next.generation)
        queue.complete(wraparound, listOf("a-behind"))
        assertFalse(queue.hasWork()) // no repeated transport or autonomous failed-work loop.
    }

    @Test fun overflowDuringAPageRemainsVisibleAcrossFurtherFullPagesAndAnEmptyEnd() {
        val queue = TypedHistory03ScanQueue(); val host = Any()
        queue.enqueue(null)
        val first = queue.page(host)
        overflow(queue, "a-behind")
        queue.complete(first, full("middle"))
        val next = queue.page(host)
        queue.complete(next, full("next"))
        val final = queue.page(host)
        assertEquals(first.generation, final.generation)
        queue.complete(final, emptyList())
        assertTrue(queue.needsScan())
        val wraparound = queue.page(host)
        assertEquals("", wraparound.after)
        queue.complete(wraparound, emptyList())
        assertFalse(queue.hasWork())
    }

    @Test fun anActualDifferentHostStartsAtTheBeginningWithoutLosingQueuedAttemptNames() {
        val queue = TypedHistory03ScanQueue(); val firstHost = Any(); val nextHost = Any()
        queue.enqueue(null)
        queue.complete(queue.page(firstHost), full("old"))
        queue.enqueue("actual-queued"); queue.enqueue(null)
        assertEquals("actual-queued", queue.nextQueued())
        val next = queue.page(nextHost)
        assertEquals("", next.after)
        queue.complete(next, emptyList())
        assertFalse(queue.hasWork())
    }
}
