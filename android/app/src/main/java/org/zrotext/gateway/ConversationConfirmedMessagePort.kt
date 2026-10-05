// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Receive-only view of the exact installed connection. Sampling never renews its observation. */
internal interface ConversationConfirmedMessagePort : ConversationPresentationPort {
    fun currentReceiveAuthority(): ConversationMessageReceiveController.Current?
}
