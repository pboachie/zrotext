// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID

/** Public untrusted bytes. The host must verify the independent root/chain/time before accepting this manifest. */
internal class ConversationActivationBundle(statement:ByteArray,manifest:ByteArray) {
    private val original=statement.copyOf()
    private val signed=manifest.copyOf()
    fun statement()=original.copyOf()
    fun manifest()=signed.copyOf()
    override fun toString()="ConversationActivationBundle(redacted)"
}

/** Retrieves an original proposal; it grants neither trust nor phone consent or capture admission. */
internal class ConversationProposalTransport(private val wire: ConversationAuthenticatedWire) {
    fun proposal(interval: String, site: String, instance: String): ConversationActivationBundle {
        val selected = UUID.fromString(interval)
        require(selected != UUID(0, 0) && selected.toString() == interval)
        for (value in listOf(site, instance)) require(value.length in 1..64 && value.all { it.code in 33..126 })
        val session = checkNotNull(wire.currentSession())
        val challenge = UUID.randomUUID()
        val reply = wire.exchange(ConversationChannelCodec.proposalRequest(session, challenge, selected))
        check(reply.authenticatedSession == session && wire.currentSession() == session)
        val (nonce, statement, manifest) = ConversationChannelCodec.parseProposalReply(reply.bytes, session)
        try {
            check(nonce == challenge)
            val parsed = ConversationActivationCodec.decode(statement)
            check(parsed.scope.accountId == session.account.toString() && parsed.scope.deviceId == session.device.toString() &&
                parsed.scope.intervalId == interval && parsed.connectionEpoch == session.connectionEpoch &&
                parsed.deploymentEpoch == session.deploymentEpoch && parsed.site == site && parsed.instance == instance)
            // Identity excludes the signature. This is a bounded shape/identity precheck,
            // never a substitute for independent root, signature, chain and time verification.
            check(manifest.copyOfRange(0,5).contentEquals(byteArrayOf(90,84,77,65,2)))
            val records=manifest[150].toInt() and 255
            check(records in 1..64 && manifest.size==215+149*records)
            check(UUID(ByteBuffer.wrap(manifest,5,8).long,ByteBuffer.wrap(manifest,13,8).long)==session.account)
            check(ByteBuffer.wrap(manifest,21,8).long==parsed.scope.trustGeneration &&
                ByteBuffer.wrap(manifest,29,8).long==parsed.scope.activationVersion &&
                manifest.copyOfRange(53,85).contentEquals(parsed.predecessorDigest))
            check(Draft02OutboundPreparation.hash(manifest.copyOfRange(0,manifest.size-64))==parsed.scope.activationDigest)
            check(wire.currentSession() == session)
            return ConversationActivationBundle(statement,manifest)
        } finally { statement.fill(0);manifest.fill(0) }
    }
}
