// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

class DeviceStreamMachineTest {
    @Test
    fun challengeProofSessionAndEpochAreFenced() {
        val account = UUID.randomUUID()
        val device = UUID.randomUUID()
        val challenge = UUID.randomUUID()
        val nonce = ByteArray(32) { it.toByte() }
        val machine = DeviceStreamMachine(device) { actualAccount, actualDevice, actualChallenge, actualNonce ->
            assertEquals(account, actualAccount)
            assertEquals(device, actualDevice)
            assertEquals(challenge, actualChallenge)
            assertArrayEquals(nonce, actualNonce)
            ByteArray(70) { 0x30.toByte() }
        }
        assertThrows(IllegalStateException::class.java) { machine.heartbeatEpoch() }
        assertEquals(device, machine.helloDeviceId())
        val proof = machine.challenge(challenge, account, device, nonce)
        assertEquals(challenge, proof.challengeId)
        assertArrayEquals(nonce, proof.nonce)
        assertThrows(IllegalStateException::class.java) {
            machine.challenge(challenge, account, device, nonce)
        }
        machine.session(4, 30)
        assertEquals(4L, machine.heartbeatEpoch())
        assertThrows(IllegalStateException::class.java) { machine.heartbeatAck(3) }
        assertEquals(1, machine.heartbeatAck(4))
        machine.close()
        assertThrows(IllegalStateException::class.java) { machine.heartbeatEpoch() }
    }

    @Test
    fun wrongIdentityAndInvalidTimingFailClosed() {
        val device = UUID.randomUUID()
        val machine = DeviceStreamMachine(device) { _, _, _, _ -> ByteArray(70) }
        assertThrows(IllegalStateException::class.java) { machine.session(1, 30) }
        machine.helloDeviceId()
        assertThrows(IllegalStateException::class.java) {
            machine.challenge(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), ByteArray(32))
        }
        assertThrows(IllegalStateException::class.java) {
            machine.challenge(UUID.randomUUID(), UUID.randomUUID(), device, ByteArray(31))
        }
        machine.challenge(UUID.randomUUID(), UUID.randomUUID(), device, ByteArray(32))
        assertThrows(IllegalStateException::class.java) { machine.session(0, 30) }
        assertThrows(IllegalStateException::class.java) { machine.session(1, 300) }
    }
}
