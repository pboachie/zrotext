// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.telephony.SubscriptionManager

/** Reported preconditions only: never permission to dispatch or carrier-delivery evidence. */
internal data class DevicePreconditions(
    val selectedSim: SelectedSim,
    val smsPermission: SmsPermission,
    val airplaneMode: AirplaneMode
) {
    enum class SelectedSim(val wire: String) {
        NOT_SELECTED("not_selected"), ACTIVE("active"), INACTIVE("inactive"), UNAVAILABLE("unavailable")
    }
    enum class SmsPermission(val wire: String) {
        GRANTED("granted"), DENIED("denied"), UNAVAILABLE("unavailable")
    }
    enum class AirplaneMode(val wire: String) {
        ENABLED("enabled"), DISABLED("disabled"), UNAVAILABLE("unavailable")
    }

    fun frame(epoch: Long): String {
        require(epoch > 0)
        // Only fixed enums and the authenticated epoch cross this boundary. Local
        // subscription IDs are used for matching but are never retained here.
        return """{"v":1,"type":"device_status","connection_epoch":$epoch,"selected_sim":"${selectedSim.wire}","sms_permission":"${smsPermission.wire}","airplane_mode":"${airplaneMode.wire}"}"""
    }

    fun frameV2(epoch: Long, network: NetworkService): String {
        require(epoch > 0)
        val currentNetwork = if (selectedSim == SelectedSim.ACTIVE) network else NetworkService.UNAVAILABLE
        return """{"v":1,"type":"device_status_v2","connection_epoch":$epoch,"selected_sim":"${selectedSim.wire}","sms_permission":"${smsPermission.wire}","airplane_mode":"${airplaneMode.wire}","network_service":"${currentNetwork.wire}"}"""
    }

    companion object {
        fun selectedSim(selected: Int, activeIds: List<Int>?): SelectedSim = when {
            selected < 0 -> SelectedSim.NOT_SELECTED
            activeIds == null -> SelectedSim.UNAVAILABLE
            selected in activeIds -> SelectedSim.ACTIVE
            else -> SelectedSim.INACTIVE
        }

        /**
         * The one SubscriptionManager lookup a status report is allowed: resolved
         * off the main thread, and the value lives for that report only. Null
         * means no selection, no READ_PHONE_STATE grant, or a platform failure.
         */
        fun resolveActiveSubscriptionIds(context: Context, selected: Int): List<Int>? = try {
            if (selected < 0 ||
                context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED
            ) null
            else context.getSystemService(SubscriptionManager::class.java)
                ?.activeSubscriptionInfoList?.map { it.subscriptionId }
        } catch (_: RuntimeException) { null }

        fun observe(context: Context): DevicePreconditions =
            observe(context, resolveActiveSubscriptionIds(context,
                context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)))

        fun observe(context: Context, activeSubscriptionIds: List<Int>?): DevicePreconditions {
            val permission = try {
                if (context.checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED)
                    SmsPermission.GRANTED else SmsPermission.DENIED
            } catch (_: RuntimeException) { SmsPermission.UNAVAILABLE }
            val sim = try {
                val selected = context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                    .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                selectedSim(selected, activeSubscriptionIds)
            } catch (_: RuntimeException) { SelectedSim.UNAVAILABLE }
            val airplane = try {
                when (Settings.Global.getInt(context.contentResolver, Settings.Global.AIRPLANE_MODE_ON)) {
                    0 -> AirplaneMode.DISABLED
                    1 -> AirplaneMode.ENABLED
                    else -> AirplaneMode.UNAVAILABLE
                }
            } catch (_: Settings.SettingNotFoundException) { AirplaneMode.UNAVAILABLE }
              catch (_: RuntimeException) { AirplaneMode.UNAVAILABLE }
            return DevicePreconditions(sim, permission, airplane)
        }
    }
}

/** New peers opt in at upgrade time; old peers receive only their existing frames. */
internal class DeviceStatusPublisher {
    private var negotiated: Version? = null
    private var lastReportElapsedMs: Long? = null

    fun selectProtocol(selected: String?) {
        negotiated = when (selected) {
            PROTOCOL -> Version.V1
            PROTOCOL_V2 -> Version.V2
            else -> null
        }
    }

    enum class Version { V1, V2 }

    @Synchronized fun nextVersion(epoch: Long, elapsedMs: Long): Version? {
        val version = negotiated ?: return null
        if (epoch <= 0 || elapsedMs < 0) return null
        val previous = lastReportElapsedMs
        if (previous != null && (elapsedMs < previous || elapsedMs - previous < REPORT_INTERVAL_MS)) return null
        lastReportElapsedMs = elapsedMs
        return version
    }

    fun nextFrame(epoch: Long, elapsedMs: Long, sample: () -> DevicePreconditions): String? =
        when (nextVersion(epoch, elapsedMs)) {
            Version.V1 -> sample().frame(epoch)
            Version.V2 -> sample().frameV2(epoch, NetworkService.UNAVAILABLE)
            null -> null
        }

    companion object {
        const val PROTOCOL = "zrotext-device-status-v1"
        const val PROTOCOL_V2 = "zrotext-device-status-v2"
        const val OFFER = "$PROTOCOL_V2, $PROTOCOL"
        const val REPORT_INTERVAL_MS = 30_000L
    }
}
