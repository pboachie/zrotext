// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.ConcurrentHashMap

/** One-way process-only withdrawal of an older content protocol. No positive03 permission,
 * observer/OS/storage callback, reset or timer. Pending and ever-signed durable history restores
 * this exclusion on actual cold legacy setup; initial03 setup withdraws BEFORE any key wait. */
internal object Capture03LegacyFence {
    private data class Scope(val account: String, val device: String, val line: String)
    private val excluded = ConcurrentHashMap.newKeySet<Scope>()
    fun withdraw(account: String, device: String, line: String) {
        listOf(account, device, line).forEach(Profile03ClosedUnaccepted::uuid)
        excluded.add(Scope(account, device, line))
    }
    fun requireLegacy(account: String, device: String, line: String) {
        check(!excluded.contains(Scope(account, device, line))) { "Older content protocol withdrawn" }
    }
    fun requireLegacy(scope: ConversationCaptureScope) = requireLegacy(scope.accountId, scope.deviceId, scope.lineId)
}
