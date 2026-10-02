// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Metadata for the existing ACK/one-use CAS consumer, never a radio permission by itself. */
internal interface JournaledRadioContext {
    val message: String
    val attempt: String
    val accountId: String
    val deviceId: String
    val peer: String
    val originalDeadlineMs: Long
    val deadlineMs: Long
    val grant: SealedExecutionGrantValidator.Fields
    val session: SealedDispatchExecutor.Session
    val local: SealedDispatchExecutor.Local
}
