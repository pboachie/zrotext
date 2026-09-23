// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Heartbeat-only device stream state. A session never authorizes SMS here. */
internal class DeviceStreamMachine(
    private val deviceId: UUID,
    private val signer: (UUID, UUID, UUID, ByteArray) -> ByteArray
) {
    enum class Phase { NEW, HELLO_SENT, PROOF_SENT, ACTIVE, CLOSED }

    data class Proof(
        val challengeId: UUID,
        val accountId: UUID,
        val deviceId: UUID,
        val nonce: ByteArray,
        val signatureDer: ByteArray
    )

    var phase: Phase = Phase.NEW
        private set
    var connectionEpoch: Long? = null
        private set
    var acknowledgments: Int = 0
        private set

    @Synchronized
    fun helloDeviceId(): UUID {
        check(phase == Phase.NEW) { "Hello already sent" }
        phase = Phase.HELLO_SENT
        return deviceId
    }

    @Synchronized
    fun challenge(challengeId: UUID, accountId: UUID, receivedDeviceId: UUID, nonce: ByteArray): Proof {
        check(phase == Phase.HELLO_SENT) { "Unexpected challenge" }
        check(receivedDeviceId == deviceId && nonce.size == 32) { "Challenge identity mismatch" }
        val signature = signer(accountId, deviceId, challengeId, nonce.copyOf())
        check(signature.size in 8..80) { "Invalid signature length" }
        phase = Phase.PROOF_SENT
        return Proof(challengeId, accountId, deviceId, nonce.copyOf(), signature)
    }

    @Synchronized
    fun session(epoch: Long, heartbeatSeconds: Int) {
        check(phase == Phase.PROOF_SENT && epoch > 0 && heartbeatSeconds in 15..120) {
            "Unexpected session"
        }
        connectionEpoch = epoch
        phase = Phase.ACTIVE
    }

    @Synchronized
    fun heartbeatEpoch(): Long {
        check(phase == Phase.ACTIVE) { "No authenticated session" }
        return checkNotNull(connectionEpoch)
    }

    @Synchronized
    fun heartbeatAck(epoch: Long): Int {
        check(phase == Phase.ACTIVE && connectionEpoch == epoch) { "Stale heartbeat" }
        acknowledgments += 1
        return acknowledgments
    }

    @Synchronized
    fun close() {
        phase = Phase.CLOSED
        connectionEpoch = null
    }
}
