// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InboundVaultDeviceTest {
    @Test fun keystoreSealsAndAuthenticatesLocalInboundBody() {
        val sender = "+12025550199".toByteArray(Charsets.US_ASCII)
        val senderToken = InboundVault.token("sender-v1", sender)
        assertEquals(64, senderToken.length)
        assertEquals(senderToken, InboundVault.token("sender-v1", sender))
        assertNotEquals(senderToken, InboundVault.token("pdu-v1", sender))

        val body = "pilot reply\nsegment two"
        val sealed = InboundVault.seal(body, senderToken)
        assertEquals(12, sealed.nonce.size)
        assertNotEquals(body, sealed.ciphertext.toString(Charsets.UTF_8))
        assertEquals(body, InboundVault.open(sealed, senderToken))
        assertThrows(Exception::class.java) {
            InboundVault.open(sealed, InboundVault.token("other-v1", sender))
        }
    }
}
