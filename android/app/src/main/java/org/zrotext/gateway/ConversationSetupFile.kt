// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.io.InputStream

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
