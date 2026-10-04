// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Exact phone-approved identities; points are obtained only from verified manifest authority. */
internal data class ConversationIntegrationReader(val connectorId: String, val readGrantId: String, val keyId: String) {
    init {
        listOf(connectorId, readGrantId).forEach { require(UUID.fromString(it).toString()==it && UUID.fromString(it)!=UUID(0,0)) }
        require(Regex("[0-9a-f]{64}").matches(keyId))
    }
    override fun toString() = "ConversationIntegrationReader(redacted)"
    companion object {
        fun validate(values: List<ConversationIntegrationReader>) {
            require(values.size<=6)
            require(values.map { it.connectorId }.toSet().size==values.size && values.map { it.readGrantId }.toSet().size==values.size)
            require(values.zipWithNext().all { (a,b) -> a.keyId<b.keyId })
        }
    }
}

internal class ConversationReaderSelection(values: List<ConversationIntegrationReader>) {
    private val selected = values.toList().also(ConversationIntegrationReader::validate)
    val values get() = selected.toList()
    override fun equals(other: Any?) = other is ConversationReaderSelection && selected == other.selected
    override fun hashCode() = selected.hashCode()
    override fun toString() = "ConversationReaderSelection(redacted)"
}
