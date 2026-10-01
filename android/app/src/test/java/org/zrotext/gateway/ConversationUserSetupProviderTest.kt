// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.ContextWrapper
import java.lang.reflect.Proxy
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationUserSetupProviderTest {
    @Test fun disabledResolutionDoesNotReadContextLineHardwareOrPublicCandidate() {
        val context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = error("Disabled context access")
        }
        val lines = Proxy.newProxyInstance(SmsAttemptDao::class.java.classLoader,
            arrayOf(SmsAttemptDao::class.java)) { _, _, _ -> error("Disabled journal access") } as SmsAttemptDao
        val provider = ConversationUserSetupProvider(context, lines)
        // API 28, malformed public bytes and throwing providers must remain untouched.
        assertNull(provider.resolve(ByteArray(0)))
        assertNull(provider.resolve(byteArrayOf(1), enabled = false))
    }
}
