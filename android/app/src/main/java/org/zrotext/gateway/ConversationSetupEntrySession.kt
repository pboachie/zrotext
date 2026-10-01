// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Does not enable setup implicitly; caller must supply the owner's exact selected interval. */
internal fun ConversationUserSetupController.entryHandle(
    selection: ConversationUserSetupController.Selection,
    enabled: Boolean = false
): ConversationSetupEntrySession.Handle = object : ConversationSetupEntrySession.Handle {
    override fun begin(): Boolean = this@entryHandle.begin(selection, enabled)
    override fun close() = this@entryHandle.close()
}

/** Owns one explicitly opened review. Closing the view never claims durable interval closure. */
internal class ConversationSetupEntrySession(
    private val factory: ((ConversationPresentationPort) -> Unit) -> Handle,
    private val changed: (State, ConversationPresentationPort?) -> Unit
) : AutoCloseable {
    interface Handle : AutoCloseable { fun begin(): Boolean }
    enum class State { CLOSED, OPENING, READY, UNAVAILABLE, CLOSE_FAILED }
    private var generation = 0L
    private var handle: Handle? = null
    private var state = State.CLOSED

    @Synchronized fun open() {
        if (state !in setOf(State.CLOSED, State.UNAVAILABLE)) return
        val token = ++generation
        state = State.OPENING
        changed(state, null)
        if (generation != token || state != State.OPENING) return
        var accepted = false
        var staged: ConversationPresentationPort? = null
        try {
            val owned = factory { port -> synchronized(this) {
                if (generation == token && state in setOf(State.OPENING, State.READY)) {
                    if (accepted) {
                        state = State.READY
                        changed(state, port)
                    } else staged = port
                }
            } }
            if (generation != token || state != State.OPENING) {
                if (runCatching { owned.close() }.isFailure && state == State.CLOSED) {
                    state = State.CLOSE_FAILED
                    changed(state, null)
                }
                return
            }
            handle = owned
            val begun = owned.begin()
            if (generation != token || state != State.OPENING) return
            if (!begun) discard(State.UNAVAILABLE) else {
                accepted = true
                staged?.let { state = State.READY; changed(state, it) }
            }
        } catch (_: Exception) {
            if (generation == token) discard(State.UNAVAILABLE)
        }
    }

    private fun discard(next: State) {
        ++generation // Reject callbacks queued before cancellation, including during close.
        val owned = handle
        handle = null
        state = next
        if (runCatching { owned?.close() }.isFailure) state = State.CLOSE_FAILED
        changed(state, null)
    }

    @Synchronized override fun close() {
        if (state == State.CLOSED || state == State.CLOSE_FAILED) return
        discard(State.CLOSED)
    }
}
