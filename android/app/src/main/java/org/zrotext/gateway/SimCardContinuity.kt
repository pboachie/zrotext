// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager

/** Public, device-local identifiers only. A subscription ID alone cannot establish continuity. */
data class ActiveSimCard(val subscriptionId: Int, val cardId: Int?,
                         val isEmbedded: Boolean = false)

/** Snapshot taken at an owner-approved activation, never inferred from the saved SIM selection. */
internal data class ActivatedSimCard(val subscriptionId: Int, val cardId: Int)

internal object SimCardContinuity {
    /**
     * An ordinary app has no usable card ID on API 28. Null also means the telephony state could
     * not be read; callers must not turn either case into an attributed or uploaded line event.
     */
    fun observe(context: Context): List<ActiveSimCard>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) !=
            PackageManager.PERMISSION_GRANTED) return null
        return try {
            val manager = context.getSystemService(SubscriptionManager::class.java) ?: return null
            // API 30 can include hidden opportunistic subscriptions. On API 29 the platform
            // exposes only the active list visible to this app, which is a known limitation.
            val subscriptions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                manager.completeActiveSubscriptionInfoList
            } else {
                manager.activeSubscriptionInfoList
            }
            subscriptions?.map { info ->
                ActiveSimCard(info.subscriptionId, info.cardId, info.isEmbedded)
            }
        } catch (_: RuntimeException) {
            null
        }
    }

    /**
     * A match is a conservative local continuity signal, not carrier ownership proof. Card IDs
     * are only useful when Android supplies a nonnegative value for one observed active SIM.
     */
    fun activationCandidate(active: List<ActiveSimCard>?): ActivatedSimCard? {
        if (active?.size != 1) return null
        val only = active.single()
        val card = only.cardId ?: return null
        // An eSIM card ID identifies the eUICC, not an individual profile. A profile swap may
        // preserve the card ID and cannot pass until a separate profile identity is verified.
        return if (only.subscriptionId >= 0 && card >= 0 && !only.isEmbedded) {
            ActivatedSimCard(only.subscriptionId, card)
        } else null
    }

    fun matches(activated: ActivatedSimCard?, active: List<ActiveSimCard>?): Boolean {
        return activated != null && activationCandidate(active) == activated
    }
}
