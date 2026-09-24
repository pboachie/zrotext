// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.provider.Telephony
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class InboundPduParserTest {
    private fun broadcast(pdu: ByteArray) = Intent(Telephony.Sms.Intents.SMS_RECEIVED_ACTION)
        .putExtra("pdus", arrayOf(pdu))

    @Test fun stopPduWithoutFormatIsDecodedAndClassified() {
        // 3GPP SMS-DELIVER, from +15551234567, GSM 7-bit body "STOP".
        val pdu = "00040B915155214365F70000429042214365000453EA130A"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val message = InboundPduParser.decode(broadcast(pdu))?.second
        assertEquals("+15551234567", message?.senderE164)
        assertEquals(OptOutParser.OPT_OUT, OptOutParser.classify(message?.body ?: ""))
    }

    @Test fun missingFormatWithConflictingDecodesDoesNotChooseALineOrBody() {
        val intent = broadcast(byteArrayOf(1))
        val decode: (ByteArray, String) -> InboundNormalizer.Part? = { _, format ->
            InboundNormalizer.Part(if (format == "3gpp") "+15551234567" else "+15557654321",
                "STOP", 1700000000000L)
        }
        assertNull(InboundPduParser.decode(intent, decode))
        intent.putExtra("format", "unknown")
        assertNull(InboundPduParser.decode(intent, decode))
    }
}
