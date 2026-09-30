// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Each Android prompt follows an affirmative, purpose-specific disclosure. */
internal enum class GatewayPermissionPurpose(val title: String, val disclosure: String) {
    SIM("SIM and connection notifications",
        "ZROtext uses phone-state access to list active SIMs and check the selected line. On supported Android versions it also requests notification access for the visible connection status and Pause control. This does not grant SMS access."),
    SEND("Send SMS from this phone",
        "ZROtext uses SMS sending access to send the controlled test message from your selected SIM after you arm the one-shot test and the authenticated server grants it. Carrier charges may apply. Granting access alone does not start a send. You can decline and still pair or test the connection."),
    RECEIVE("Process incoming SMS",
        "ZROtext uses SMS receiving access to inspect newly received SMS in the background, including when the app is closed. It processes STOP and review requests to block further sending locally, storing encrypted sender information and suppression records. During an approved reply window it stores an encrypted reply body locally. If you start the authenticated inbound pilot, signed reply metadata is uploaded to your configured server; reply bodies stay on this phone. Opt-out synchronization can send the sender number and withdrawal metadata to that server. Pause stops the connection but does not revoke local SMS receiving access. To stop local processing, revoke SMS access in Android app settings. No existing SMS inbox history is read.");

    fun permissions(apiLevel: Int): List<String> = when (this) {
        SIM -> listOf("android.permission.READ_PHONE_STATE") +
            if (apiLevel >= 33) listOf("android.permission.POST_NOTIFICATIONS") else emptyList()
        SEND -> listOf("android.permission.SEND_SMS")
        RECEIVE -> listOf("android.permission.RECEIVE_SMS")
    }
}
