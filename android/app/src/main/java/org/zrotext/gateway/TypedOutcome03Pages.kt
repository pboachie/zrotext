// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Navigation for ONE explicit sync action, never automatic retry or evidence authority.
 * An empty suffix cannot establish global emptiness while earlier originals are pending. */
internal object TypedOutcome03Pages {
    fun select(after: String, current: () -> Unit, query: (String) -> List<String>): List<String> {
        current()
        val suffix = query(after).toList().also { require(it.size <= 16) }
        current() // Includes withdrawal while the first actual storage read waited.
        val page = if (suffix.isEmpty() && after.isNotEmpty()) {
            query("").toList().also { require(it.size <= 16) }
        } else suffix
        current()
        return page
    }
}
