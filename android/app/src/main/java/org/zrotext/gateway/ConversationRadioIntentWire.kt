// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Metadata only, on the existing authenticated socket. A send is never authorized by a write. */
internal interface ConversationRadioIntentWire {
    fun submitIntent(session: ConversationPhoneSession, event: AlphaRadioEvent): Boolean
}

internal enum class ConversationRadioAckRoute { NOT_OURS, CONSUMED, KNOWN_STALE }
