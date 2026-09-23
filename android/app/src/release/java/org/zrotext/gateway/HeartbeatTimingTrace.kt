// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** No timing trace is emitted from a release build, even if an extra is supplied. */
internal class HeartbeatTimingTrace {
    fun start(requested: Boolean) = Unit
    fun mark(event: HeartbeatTraceEvent, epoch: Long, loss: DeviceReconnectPolicy.Loss? = null) = Unit
}
