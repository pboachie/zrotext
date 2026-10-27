// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** RAM scheduling only; the runtime holds its queue lock for each operation. Overflow
 * requests a full traversal, whose generation cannot be replaced at a later page. These
 * identifiers/cursors confer no clock, actor, journal, retry or effect authority. */
internal class TypedHistory03ScanQueue {
    class Page internal constructor(internal val owner: Any, val after: String, internal val generation: Long)
    private val queued = LinkedHashSet<String>()
    private var scanning = false
    private var requestedGeneration = 0L
    private var traversalGeneration: Long? = null
    private var owner: Any? = null
    private var cursor = ""

    fun enqueue(attempt: String?) {
        if (attempt == null || queued.size >= 16) { scanning = true; requestedGeneration++ }
        else queued.add(attempt)
    }
    fun nextQueued() = queued.firstOrNull()?.also(queued::remove)
    fun needsScan() = scanning
    fun hasWork() = queued.isNotEmpty() || scanning

    fun page(host: Any): Page {
        check(scanning)
        if (owner !== host) { owner = host; cursor = ""; traversalGeneration = null }
        val original = traversalGeneration ?: requestedGeneration.also { traversalGeneration = it }
        return Page(host, cursor, original)
    }

    fun complete(page: Page, attempts: List<String>) {
        check(owner === page.owner && cursor == page.after && traversalGeneration == page.generation)
        require(attempts.size <= 16)
        if (attempts.size == 16) cursor = attempts.last()
        else {
            cursor = ""; traversalGeneration = null
            // An overflow during ANY earlier page/inter-page gap requires a wraparound.
            // A later page cannot consume that notification as its own new generation.
            if (requestedGeneration == page.generation) scanning = false
        }
    }
}
