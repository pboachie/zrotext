// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.rules.ExternalResource
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf

/** Reproduce the merged manifest's signature permission before an API 28 activity starts. */
class ConversationReceiverPermissionRule : ExternalResource() {
    override fun before() {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).grantPermissions("${app.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
    }
}
