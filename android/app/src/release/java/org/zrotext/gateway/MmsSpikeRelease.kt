// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.compose.runtime.Composable
import org.json.JSONObject
import java.util.UUID

/**
 * Release builds carry no MMS spike: no screen section, no receiver or file
 * provider, and no radio call. A grant frame is treated as an unexpected frame.
 */
internal object MmsSpikeGrants {
    fun onGrantFrame(context: Context, frame: JSONObject, deviceId: UUID, connectionEpoch: Long): Unit =
        error("Unexpected device frame")
}

@Composable
internal fun MmsSpikeSection(selectedSim: Int?, activeSimIds: List<Int>) = Unit
