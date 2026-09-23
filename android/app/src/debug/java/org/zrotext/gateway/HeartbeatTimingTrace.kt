// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import android.util.Log
import java.util.concurrent.atomic.AtomicInteger

/** Explicitly opted-in debug trace; bounded to avoid long-running log spam. */
internal class HeartbeatTimingTrace {
    @Volatile private var enabled = false
    private val emitted = AtomicInteger(0)

    fun start(requested: Boolean) {
        enabled = requested
        emitted.set(0)
    }

    fun mark(event: HeartbeatTraceEvent, epoch: Long, loss: DeviceReconnectPolicy.Loss? = null) {
        if (!enabled) return
        val index = emitted.getAndIncrement()
        if (index > MAX_MARKERS) return
        val elapsedMs = SystemClock.elapsedRealtime()
        if (index == MAX_MARKERS) {
            Log.i(TAG, "elapsed_ms=$elapsedMs epoch=$epoch event=LIMIT")
            return
        }
        val category = if (loss == null) "" else " loss=${loss.name}"
        Log.i(TAG, "elapsed_ms=$elapsedMs epoch=$epoch event=${event.name}$category")
    }

    companion object {
        private const val TAG = "ZTHeartbeatTiming"
        private const val MAX_MARKERS = 256
    }
}
