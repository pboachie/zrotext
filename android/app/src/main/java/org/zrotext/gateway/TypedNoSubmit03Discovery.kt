// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Metadata discovery only. A load generation is not a decision, clock or report ticket.
 * Pausing/replacing the Host/display invalidates every old load and affirmative decision. */
internal class TypedNoSubmit03Discovery(private val foreground: ConversationInterval03Foreground) : AutoCloseable {
    class Load internal constructor(internal val owner: TypedNoSubmit03Discovery,
        internal val generation: Long, val host: TypedHistory03Connections.Host)
    class Display internal constructor(val row: TypedSubmit03Record, val host: TypedHistory03Connections.Host)
    private var generation = 0L
    private var selected: Display? = null
    private var closed = false

    @Synchronized fun begin(host: TypedHistory03Connections.Host?, resumed: Boolean): Load? {
        check(!closed)
        withdraw(resumed)
        selected = null
        if (!resumed || host == null) return null
        host.requireCurrent()
        return Load(this, generation, host)
    }
    @Synchronized fun publish(load: Load, row: TypedSubmit03Record?, resumed: Boolean): Display? {
        if (closed || !resumed || load.owner !== this || load.generation != generation) return null
        load.host.requireCurrent()
        if (row == null) return null
        require(row.phase == "closed_no_submit"); load.host.requireOriginal(row)
        // A decision captured before any async display publication cannot survive it.
        foreground.update(false); foreground.update(resumed)
        return Display(row, load.host).also { selected = it }
    }
    @Synchronized fun isDisplayed(display: Display) = !closed && selected === display
    @Synchronized fun capture(display: Display): TypedNoSubmit03Action {
        check(!closed && selected === display)
        return TypedNoSubmit03Action.capture(display.row, display.host, foreground.decision())
    }
    /** Candidate completion/metadata refresh from an old operation cannot overwrite a new
     * selection, even if the same Host object is observed again after pause/resume. */
    @Synchronized fun refresh(display: Display, row: TypedSubmit03Record, resumed: Boolean): Display? {
        if (closed || selected !== display) return null
        display.host.requireCurrent()
        require(row.attemptId == display.row.attemptId && row.phase == "closed_no_submit")
        display.host.requireOriginal(row)
        withdraw(resumed)
        return Display(row, display.host).also { selected = it }
    }
    private fun withdraw(resumed: Boolean) {
        foreground.update(false)
        generation = Math.addExact(generation, 1)
        foreground.update(resumed)
    }
    @Synchronized override fun close() {
        closed = true; selected = null; foreground.close()
    }
}
