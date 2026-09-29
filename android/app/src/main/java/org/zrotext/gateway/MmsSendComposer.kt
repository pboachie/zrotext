// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream

/** One outbound MMS spike request. The attachment is always a PNG image. */
internal data class MmsSpikeRequest(
    val recipientE164: String,
    val subject: String,
    val transactionId: String,
    val imageName: String,
    val imageData: ByteArray
)

/**
 * Minimal OMA-TS-MMS m-send.req composer for the outbound MMS spike. The byte
 * layout mirrors AOSP's com.google.android.mms.pdu.PduComposer, the shape
 * carrier MMSCs already accept from Android: value-length-wrapped content
 * types, charset-prefixed encoded strings, uintvar multipart lengths, and a
 * part whose headers begin with the content-type value and carry no field
 * code. MMSC acceptance itself is a device-spike finding, not a JVM fact.
 */
internal object MmsSendComposer {
    // OMA-TS-MMS-ENC message header field assignments.
    private const val MESSAGE_TYPE = 0x8C
    private const val MESSAGE_TYPE_SEND_REQ = 0x80
    private const val MMS_VERSION = 0x8D
    private const val MMS_VERSION_1_2 = 0x12
    private const val FROM = 0x89
    private const val FROM_INSERT_ADDRESS_TOKEN = 0x81
    private const val TO = 0x97
    private const val SUBJECT = 0x96
    private const val CONTENT_TYPE = 0x84

    // WAP-230-WSP encodings used inside the PDU.
    private const val LENGTH_QUOTE = 0x1F
    private const val NAME_PARAM = 0x85
    private const val TYPE_PARAM = 0x89
    private const val CHARSET_UTF_8 = 0x6A
    private const val MULTIPART_MIXED = 0x23
    private const val IMAGE_PNG = 0x20

    private const val MAX_SUBJECT_CHARS = 64
    private const val MAX_IMAGE_BYTES = 300_000
    private val PNG_SIGNATURE =
        byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)

    fun validationError(request: MmsSpikeRequest): String? = when {
        !request.recipientE164.matches(Regex("^\\+[1-9][0-9]{1,14}$")) ->
            "recipient must be +E.164"
        request.subject.length > MAX_SUBJECT_CHARS || request.subject.contains('\u0000') ->
            "subject is longer than $MAX_SUBJECT_CHARS characters or contains NUL"
        !request.transactionId.matches(Regex("^[A-Za-z0-9-]{1,64}$")) ->
            "transaction id must be 1-64 ASCII letters, digits, or hyphens"
        !request.imageName.matches(Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")) ->
            "image name must be a simple 1-40 character file name"
        request.imageData.size !in 1..MAX_IMAGE_BYTES ->
            "image is empty or larger than $MAX_IMAGE_BYTES bytes"
        !request.imageData.copyOfRange(0, 8).contentEquals(PNG_SIGNATURE) ->
            "attachment does not start with the PNG signature"
        else -> null
    }

    /** Composes one m-send.req. Requires a request with no [validationError]. */
    fun compose(request: MmsSpikeRequest): ByteArray {
        check(validationError(request) == null)
        val out = ByteArrayOutputStream()
        out.write(MESSAGE_TYPE); out.write(MESSAGE_TYPE_SEND_REQ)
        out.write(TRANSACTION_ID_FIELD)
        textString(out, request.transactionId.toByteArray(Charsets.US_ASCII))
        out.write(MMS_VERSION); shortInteger(out, MMS_VERSION_1_2)
        out.write(FROM); out.write(1); out.write(FROM_INSERT_ADDRESS_TOKEN)
        out.write(TO)
        encodedString(out, (request.recipientE164 + "/TYPE=PLMN").toByteArray(Charsets.US_ASCII))
        if (request.subject.isNotEmpty()) {
            out.write(SUBJECT)
            encodedString(out, request.subject.toByteArray(Charsets.UTF_8))
        }
        // Envelope content type: multipart/mixed plus AOSP's "type" parameter
        // naming the single image part's media type.
        val envelope = ByteArrayOutputStream()
        shortInteger(envelope, MULTIPART_MIXED)
        envelope.write(TYPE_PARAM)
        textString(envelope, "image/png".toByteArray(Charsets.US_ASCII))
        out.write(CONTENT_TYPE)
        valueLength(out, envelope.size())
        envelope.writeTo(out)
        // One part: the PNG, with a name parameter and no charset (binary data).
        val partHeaders = ByteArrayOutputStream()
        val partContentType = ByteArrayOutputStream()
        shortInteger(partContentType, IMAGE_PNG)
        partContentType.write(NAME_PARAM)
        textString(partContentType, request.imageName.toByteArray(Charsets.US_ASCII))
        valueLength(partHeaders, partContentType.size())
        partContentType.writeTo(partHeaders)
        uintvar(out, 1)
        val headerBytes = partHeaders.toByteArray()
        uintvar(out, headerBytes.size)
        uintvar(out, request.imageData.size)
        out.write(headerBytes)
        out.write(request.imageData)
        return out.toByteArray()
    }

    private const val TRANSACTION_ID_FIELD = 0x98

    /** Encoded-string = value-length (charset text-string), always, as AOSP emits it. */
    private fun encodedString(out: ByteArrayOutputStream, text: ByteArray) {
        val value = ByteArrayOutputStream()
        shortInteger(value, CHARSET_UTF_8)
        textString(value, text)
        valueLength(out, value.size())
        value.writeTo(out)
    }

    /** Text-string = [quote] bytes NUL, with the quote only when the first byte is > 127. */
    private fun textString(out: ByteArrayOutputStream, text: ByteArray) {
        if (text.isEmpty() || (text[0].toInt() and 0xFF) > 0x7F) out.write(0x7F)
        out.write(text)
        out.write(0)
    }

    private fun shortInteger(out: ByteArrayOutputStream, value: Int) {
        out.write((value or 0x80) and 0xFF)
    }

    /** Value-length = short-length, or length-quote followed by a uintvar. */
    private fun valueLength(out: ByteArrayOutputStream, length: Int) {
        if (length in 0..30) {
            out.write(length)
        } else {
            out.write(LENGTH_QUOTE)
            uintvar(out, length)
        }
    }

    private fun uintvar(out: ByteArrayOutputStream, value: Int) {
        require(value >= 0)
        var remaining = value
        val stack = ArrayDeque<Byte>()
        stack.addFirst((remaining and 0x7F).toByte())
        remaining = remaining ushr 7
        while (remaining > 0) {
            stack.addFirst(((remaining and 0x7F) or 0x80).toByte())
            remaining = remaining ushr 7
        }
        for (byte in stack) out.write(byte.toInt() and 0xFF)
    }
}
