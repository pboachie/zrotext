// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Negative-only process lifetime. An epoch cannot establish absence while an arrival
 * is pending/unknown. There is no reset, timeout or recovery-to-success operation.
 * Test-local instances exercise failure paths without clearing production state. */
internal class TypedNoSubmit03CallbackLifetime {
    private val lock = Any()
    private var epoch = 0L
    private var outstanding = 0L
    class Ticket internal constructor(private val current: () -> Unit) {
        fun requireCurrent() = current()
    }
    class Arrival internal constructor(private val record: () -> Unit, private val uncertain: () -> Unit) {
        /** Called ONLY after an actual typed/legacy writer returns successfully. */
        fun recorded() = record()
        fun unknown() = uncertain()
        fun <T> guard(work: () -> T): T = try { work() } catch (failure: Throwable) {
            unknown(); throw failure
        }
    }
    fun capture(): Ticket = synchronized(lock) {
        check(outstanding == 0L)
        val captured = epoch
        Ticket { synchronized(lock) { check(epoch == captured && outstanding == 0L) } }
    }
    fun begin(): Arrival = synchronized(lock) {
        val nextEpoch = Math.addExact(epoch, 1)
        val nextOutstanding = Math.addExact(outstanding, 1)
        epoch = nextEpoch; outstanding = nextOutstanding
        var state = 0 //0 pending;1 observed committed;2 unknown, permanently outstanding.
        Arrival(record = {
            synchronized(lock) {
                check(state == 0 && outstanding > 0)
                val completedEpoch = Math.addExact(epoch, 1)
                outstanding--; epoch = completedEpoch; state = 1
            }
        }, uncertain = {
            synchronized(lock) { if (state == 0) state = 2 }
        })
    }
}

internal object TypedNoSubmit03Lifetimes {
    private val callbacks = TypedNoSubmit03CallbackLifetime()
    fun capture() = callbacks.capture()
    fun callbackArriving() = callbacks.begin()
}
