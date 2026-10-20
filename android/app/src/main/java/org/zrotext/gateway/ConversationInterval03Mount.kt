// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** A foreground display ticket, never a credential. The live socket owner compares its exact
 * object identity, original proof and current custody again before committing any signature.
 */
internal object ConversationInterval03Mount {
    class Review internal constructor(val interval: UUID, val peer: String, val line: UUID,
        val archiveKey: String, val phoneSigner: String, val browserSigner: String,
        val integrationCount: Int, val intervalExpiresMs: Long) {
        override fun toString() = "ConversationInterval03Review(redacted)"
    }
    private class Entry(val owner: Any, val current: () -> Boolean,
        val approve: (Review, AtomicBoolean) -> Unit, val retry: (Review, AtomicBoolean) -> Unit,
        val readStatus: (Review) -> Unit, val stop: (Review) -> Unit)
    @Volatile private var entry: Entry? = null
    var review by mutableStateOf<Review?>(null)
        private set
    var status by mutableStateOf("No conversation approval waiting")
        private set
    @Synchronized fun attach(owner: Any, current: () -> Boolean, approve: (Review, AtomicBoolean) -> Unit,
        retry: (Review, AtomicBoolean) -> Unit, readStatus: (Review) -> Unit, stop: (Review) -> Unit) {
        check(current()); entry = Entry(owner, current, approve, retry, readStatus, stop); review = null
        status = "No conversation approval waiting"
    }
    @Synchronized fun publish(owner: Any, shown: Review, text: String) {
        check(entry?.let { it.owner === owner && it.current() } == true); review = shown; status = text
    }
    @Synchronized fun update(owner: Any, shown: Review, text: String) {
        if (entry?.owner === owner && review === shown) status = text
    }
    private fun selected(shown: Review): Entry = checkNotNull(entry).also { check(it.current() && review === shown) }
    fun approve(shown: Review, foreground: AtomicBoolean) { check(foreground.get()); selected(shown).approve(shown, foreground) }
    fun retry(shown: Review, foreground: AtomicBoolean) { check(foreground.get()); selected(shown).retry(shown, foreground) }
    fun readStatus(shown: Review) { selected(shown).readStatus(shown) }
    /** Stop is dispatched synchronously first so a queued worker cannot keep the RAM handle live. */
    fun stop(shown: Review) { selected(shown).stop(shown) }
    @Synchronized fun detach(owner: Any) {
        if (entry?.owner === owner) { entry = null; review = null; status = "Conversation access paused; original approvals are saved" }
    }
}
