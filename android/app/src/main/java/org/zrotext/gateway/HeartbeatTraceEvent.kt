// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Fixed, content-free markers shared by debug and release build variants. */
internal enum class HeartbeatTraceEvent {
    SESSION,
    SEND_CALL,
    SEND_QUEUED,
    SEND_REJECTED,
    ACK,
    SOCKET_CLOSING,
    SOCKET_CLOSED,
    SOCKET_FAILURE,
    DISCONNECT,
}
