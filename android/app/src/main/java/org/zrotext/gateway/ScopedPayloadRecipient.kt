// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Public metadata only; a completed scope is not current custody or execution authority. */
internal class ScopedPayloadRecipient internal constructor(private val scope: PayloadKeyCustodyScope,
    private val identity: DevicePayloadPublic) {
    fun publicIdentity(): DevicePayloadPublic {
        scope.requireCurrent()
        return identity
    }

    fun revalidateLocalIdentity() = scope.revalidate()

    override fun toString() = "ScopedPayloadRecipient(redacted)"
}
