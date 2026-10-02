// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Missing-key recovery is distinct from explicit first enrollment, even when a key lookup fails. */
internal object ConversationProtectionEnrollment {
    fun prepare(keysPresent: () -> Boolean, retainedState: () -> Boolean, createKeys: () -> Unit,
                verifyKeys: () -> Unit, requireCurrent: () -> Unit) {
        requireCurrent()
        if (!keysPresent()) {
            check(!retainedState()) { "Existing protection requires recovery" }
            requireCurrent()
            createKeys()
        }
        requireCurrent()
        verifyKeys() // An existing but unusable key is never treated as permission to replace it.
        requireCurrent()
    }
}
