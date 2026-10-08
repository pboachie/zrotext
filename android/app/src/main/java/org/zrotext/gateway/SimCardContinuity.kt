// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager

/** Public, device-local identifiers only. A subscription ID alone cannot establish continuity. */
data class ActiveSimCard(val subscriptionId: Int, val cardId: Int?,
                         val isEmbedded: Boolean = false,
                         val portIndex: Int? = null, val logicalSlotIndex: Int? = null) {
    private var observedProfile: EsimProfileCandidate? = null
    internal val profileCandidate: EsimProfileCandidate? get() = observedProfile
    /** Public constructor/copy/components cannot manufacture or copy this opaque capability. */
    internal fun withProfile(candidate: EsimProfileCandidate?): ActiveSimCard = copy().also {
        it.observedProfile = candidate
    }
}

/** Snapshot taken at an owner-approved activation, never inferred from the saved SIM selection. */
internal data class ActivatedSimCard(val subscriptionId: Int, val cardId: Int,
                                     val profile: EsimProfileCandidate? = null)

internal object SimCardContinuity {
    /**
     * An ordinary app has no usable card ID on API 28. Null also means the telephony state could
     * not be read; callers must not turn either case into an attributed or uploaded line event.
     */
    fun observe(context: Context): List<ActiveSimCard>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) !=
            PackageManager.PERMISSION_GRANTED) {
            SimProfileContinuity.stop()
            return null
        }
        return try {
            if (Build.VERSION.SDK_INT >= 33) {
                val records = SimProfileContinuity.observe(context)
                if (records != null) return records.map { info ->
                    ActiveSimCard(info.subscriptionId, info.cardId, info.embedded, info.portIndex,
                        info.logicalSlotIndex).withProfile(SimProfileContinuity.candidate(info.subscriptionId))
                }
            }
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
     * are only useful when Android supplies a nonnegative value for the selected physical SIM.
     */
    fun activationCandidate(active: List<ActiveSimCard>?): ActivatedSimCard? {
        if (active?.size != 1) return null
        return activationCandidate(active, active.single().subscriptionId)
    }

    /** A second SIM never selects a line or replaces a missing explicitly selected SIM. */
    fun activationCandidate(active: List<ActiveSimCard>?, selectedSubscriptionId: Int): ActivatedSimCard? {
        if (active == null || selectedSubscriptionId < 0 ||
            active.map { it.subscriptionId }.distinct().size != active.size) return null
        val selected = active.singleOrNull { it.subscriptionId == selectedSubscriptionId } ?: return null
        val card = selected.cardId ?: return null
        // The eUICC is not a profile identity. Only a live observer-issued record lease qualifies.
        if (selected.isEmbedded) {
            val profile = selected.profileCandidate ?: return null
            val record = profile.record
            return if (profile.isCurrent() && record.subscriptionId == selectedSubscriptionId &&
                record.cardId == card && record.portIndex == selected.portIndex &&
                record.logicalSlotIndex == selected.logicalSlotIndex &&
                active.none { it.subscriptionId != selectedSubscriptionId && it.cardId == card &&
                    (it.portIndex == null || it.portIndex < 0 || it.portIndex == record.portIndex || !it.isEmbedded) })
                ActivatedSimCard(selectedSubscriptionId, card, profile) else null
        }
        return if (card >= 0 && !selected.isEmbedded &&
            active.none { it.subscriptionId != selectedSubscriptionId && it.cardId == card }) {
            ActivatedSimCard(selectedSubscriptionId, card)
        } else null
    }

    fun matches(activated: ActivatedSimCard?, active: List<ActiveSimCard>?): Boolean {
        return activated != null && activationCandidate(active, activated.subscriptionId) == activated
    }
}

internal fun ActivatedSimCard.observedCard(): ActiveSimCard =
    ActiveSimCard(subscriptionId, cardId, profile != null, profile?.record?.portIndex,
        profile?.record?.logicalSlotIndex).withProfile(profile)
