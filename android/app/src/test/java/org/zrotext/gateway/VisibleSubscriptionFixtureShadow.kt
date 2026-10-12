// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowSubscriptionManager

/** These fixtures contain only visible synthetic rows, so their complete list is the same list. */
@Implements(SubscriptionManager::class)
class VisibleSubscriptionFixtureShadow : ShadowSubscriptionManager() {
    @Implementation(minSdk = 33)
    protected fun getCompleteActiveSubscriptionInfoList(): List<SubscriptionInfo>? =
        super.getActiveSubscriptionInfoList()
}
