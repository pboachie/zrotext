// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Narrow orchestration port. Public points do not establish custody; the sole shipping adapter
 * below delegates every proof to the existing selected, nonexportable hardware signing path.
 */
internal interface ConversationInterval03ProofSigner {
    fun readerPoint(): ByteArray
    fun phonePoint(): ByteArray
    fun approval(statement: ConversationInterval03.Statement, owner: ByteArray, expected: ByteArray, current: () -> Unit): ByteArray
    fun installed(statement: ConversationInterval03.Statement, owner: ByteArray, phone: ByteArray, expected: ByteArray, current: () -> Unit): ByteArray
}

internal class ConversationInterval03HardwareProofSigner(private val keys: DeviceSigningKeyStore,
    private val payload: () -> DevicePayloadKeyStore) : ConversationInterval03ProofSigner {
    override fun readerPoint() = payload().existingPublic().point
    override fun phonePoint() = keys.existingConversationPublicPoint()
    override fun approval(statement: ConversationInterval03.Statement, owner: ByteArray, expected: ByteArray, current: () -> Unit) =
        keys.signConversationApproval03(statement, owner, expected, current)
    override fun installed(statement: ConversationInterval03.Statement, owner: ByteArray, phone: ByteArray, expected: ByteArray, current: () -> Unit) =
        keys.signConversationInstalled03(statement, owner, phone, expected, current)
}
