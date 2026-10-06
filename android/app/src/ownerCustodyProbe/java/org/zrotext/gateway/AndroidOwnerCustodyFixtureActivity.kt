// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

/** Local synthetic fixture only. Not a release entry point or owner authentication source. */
class AndroidOwnerCustodyFixtureActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { GatewayTheme { AndroidOwnerCustodyScreen(onClose = { finish() }) } }
    }
}
