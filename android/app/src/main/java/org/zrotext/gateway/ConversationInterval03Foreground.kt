// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** RAM-only foreground lifetime. Resuming permits a new explicit action; it never revives
 * a decision captured before any pause, disposal or display replacement. */
internal class ConversationInterval03Foreground : AutoCloseable {
    private val resumed = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val epoch = AtomicLong(0)

    class Decision private constructor(private val owner: ConversationInterval03Foreground, private val captured: Long) {
        fun isCurrent() = !owner.closed.get() && owner.resumed.get() && owner.epoch.get() == captured
        override fun toString() = "ConversationInterval03ForegroundDecision(redacted)"
        companion object {
            internal fun capture(owner: ConversationInterval03Foreground): Decision {
                val at = owner.epoch.get()
                return Decision(owner, at).also { check(it.isCurrent()) }
            }
        }
    }

    @Synchronized fun update(isResumed: Boolean) {
        if (closed.get()) return
        if (!isResumed) {
            resumed.set(false)
            epoch.incrementAndGet() // Irreversible withdrawal, even if resume precedes a blocked sign's return.
        } else resumed.set(true)
    }
    /** Called only by an actual affirmative UI action, never by a lifecycle callback. */
    fun decision(): Decision = Decision.capture(this)
    @Synchronized override fun close() {
        closed.set(true); resumed.set(false); epoch.incrementAndGet()
    }
}
