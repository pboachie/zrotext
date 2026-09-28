// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.provider.Telephony

/**
 * Local RCS risk observation for the inbound SMS pilot. RCS chat messages are
 * delivered inside the default messaging app and never produce the
 * SMS_RECEIVED broadcast this gateway captures, and no public Android API
 * reports whether RCS chats are enabled or registered. This classification
 * only says whether the current default messaging app is one known to
 * register RCS chats; it never proves RCS is off or that inbound capture is
 * ready.
 */
internal object DefaultSmsAppRcsRisk {
    /** Default messaging apps known to register RCS chats when enabled. */
    private val rcsCapablePackages = setOf(
        "com.google.android.apps.messaging", // Google Messages
        "com.samsung.android.messaging"      // Samsung Messages
    )

    enum class Risk { RCS_CAPABLE_APP, UNKNOWN_APP, UNAVAILABLE }

    fun classify(defaultSmsPackage: String?): Risk = when {
        defaultSmsPackage == null -> Risk.UNAVAILABLE
        rcsCapablePackages.contains(defaultSmsPackage) -> Risk.RCS_CAPABLE_APP
        else -> Risk.UNKNOWN_APP
    }

    fun observe(context: Context): Risk = try {
        classify(Telephony.Sms.getDefaultSmsPackage(context))
    } catch (_: RuntimeException) {
        Risk.UNAVAILABLE
    }
}
