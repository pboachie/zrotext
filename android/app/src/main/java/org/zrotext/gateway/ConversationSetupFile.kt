// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.Base64

/** Standard canonical base64 only; bound decoded size before allocating the candidate. */
internal fun decodeConversationReplyText(text: String): ConversationUserSetupProvider.ReplyAuthority {
    require(text.length in 4..21900 && text.length % 4 == 0)
    require(Regex("[A-Za-z0-9+/]+={0,2}").matches(text))
    val padding = if (text.endsWith("==")) 2 else if (text.endsWith("=")) 1 else 0
    require(text.length / 4 * 3 - padding in 1..16423)
    val bytes = Base64.getDecoder().decode(text)
    require(Base64.getEncoder().encodeToString(bytes) == text)
    return ConversationUserSetupProvider.decodeReplyAuthority(bytes)
}

/** A SIM chosen elsewhere cannot rename the authoritative line in a consent disclosure. */
internal fun conversationEntryLineLabel(binding: LocalLineBinding,
    selection: ConversationUserSetupController.Selection, selectedSubscription: Int?, labels: Map<Int, String>): String? =
    labels[binding.subscriptionId]?.takeIf {
        binding.accountId == selection.identity.accountId && binding.deviceId == selection.identity.deviceId &&
            binding.lineId == selection.lineId && binding.generation == selection.bindingGeneration &&
            selectedSubscription == binding.subscriptionId && it.isNotBlank()
    }

/** Enforce the public candidate format limit before provider decoding can copy it. */
internal fun readConversationSetupFile(input: InputStream, maximum: Int): ByteArray {
    require(maximum in 1..16423)
    val output = ByteArrayOutputStream(maximum)
    val buffer = ByteArray(minOf(4096, maximum + 1))
    while (true) {
        val count = input.read(buffer, 0, minOf(buffer.size, maximum - output.size() + 1))
        if (count == -1) break
        require(count > 0 && output.size() + count <= maximum)
        output.write(buffer, 0, count)
    }
    require(output.size() > 0)
    return output.toByteArray()
}
