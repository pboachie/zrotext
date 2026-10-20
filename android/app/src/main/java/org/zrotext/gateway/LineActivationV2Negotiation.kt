// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** One selected WebSocket protocol describes one installed implementation tuple. */
internal object LineActivationV2Negotiation {
    const val STATUS_LINE = "zrotext-device-status-v2-line-activation-v2"
    const val SEALED_STATUS_LINE = "zrotext-sealed-dispatch-v2-device-status-v2-line-activation-v2"
    data class Selection(val status: String?, val sealed: Boolean, val lineVersion: Int,
        val sealedVersion: Int = if (sealed) 2 else 0)

    fun offer(lineConsumer: Boolean, sealedConsumer: Boolean, profile03Consumer: Boolean = false): List<String> = buildList {
        require(!profile03Consumer || lineConsumer)
        if (profile03Consumer) add(Profile03SessionTime.PROTOCOL)
        if (lineConsumer && sealedConsumer) add(SEALED_STATUS_LINE)
        if (lineConsumer) add(STATUS_LINE)
        if (sealedConsumer) add(SealedSocketTime.PROTOCOL)
        add(DeviceStatusPublisher.PROTOCOL_V2)
        add(DeviceStatusPublisher.PROTOCOL)
    }

    fun select(selected: String?, offered: List<String>): Selection {
        require(offered.distinct().size == offered.size)
        if (selected == null) return Selection(null, false, 1)
        require(selected in offered)
        return when (selected) {
            Profile03SessionTime.PROTOCOL -> Selection(DeviceStatusPublisher.PROTOCOL_V2, true, 2, 3)
            SEALED_STATUS_LINE -> Selection(DeviceStatusPublisher.PROTOCOL_V2, true, 2)
            STATUS_LINE -> Selection(DeviceStatusPublisher.PROTOCOL_V2, false, 2)
            SealedSocketTime.PROTOCOL -> Selection(DeviceStatusPublisher.PROTOCOL_V2, true, 1)
            DeviceStatusPublisher.PROTOCOL_V2 -> Selection(selected, false, 1)
            DeviceStatusPublisher.PROTOCOL -> Selection(selected, false, 1)
            else -> throw IllegalArgumentException("Unsupported selected device protocol")
        }
    }
}
