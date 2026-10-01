// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Explicit current authenticated connection only. No bearer API, automatic retry or SMS dispatch. */
internal class ConversationContentTransport(private val wire: ConversationAuthenticatedWire) {
    private fun exchange(session: ConversationPhoneSession, request: ByteArray): ByteArray {
        check(wire.currentSession() == session)
        val reply = wire.exchange(request)
        check(reply.authenticatedSession == session && wire.currentSession() == session)
        return reply.bytes.copyOf()
    }
    fun upload(content: ConversationCapturedBody, envelope: ByteArray): ConversationCaptureAck {
        val session = checkNotNull(wire.currentSession())
        val owned = envelope.copyOf(); val challenge = UUID.randomUUID()
        try {
            val response = ConversationChannelCodec.parseCaptureReply(exchange(session,
                ConversationChannelCodec.captureRequest(session,challenge,content.scope,owned)),session)
            val digest = MessageDigest.getInstance("SHA-256").digest(owned).joinToString("") { "%02x".format(it.toInt() and 255) }
            check(response.challenge == challenge && response.event.toString() == content.captureId && response.digest == digest)
            return response
        } finally { owned.fill(0) }
    }
    /** Transfers evidence only. The confirmed-send journal independently verifies and claims it. */
    fun confirmed(scope: ConversationCaptureScope, message: String): ByteArray {
        require(UUID.fromString(message).toString() == message && UUID.fromString(message) != UUID(0,0))
        val session=checkNotNull(wire.currentSession()); val challenge=UUID.randomUUID()
        val (nonce, packet)=ConversationChannelCodec.parseDeliveryReply(exchange(session,
            ConversationChannelCodec.deliveryRequest(session,challenge,scope,UUID.fromString(message))),session)
        check(nonce==challenge)
        return packet
    }
}
