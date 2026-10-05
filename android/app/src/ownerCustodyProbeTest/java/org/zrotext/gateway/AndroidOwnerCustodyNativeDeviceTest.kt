// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.content.pm.PackageManager
import android.Manifest
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Real JNI and Android native-memory recovery, synthetic identities only; no SMS/network. */
@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyNativeDeviceTest {
    @Test fun isolatedFixtureCannotUseInternetOrSmsAfterDependencyManifestMerge() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("org.zrotext.gateway.ownercustodyfixture", target.packageName)
        val requested = target.packageManager.getPackageInfo(target.packageName,
            PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty().toSet()
        for (permission in listOf(Manifest.permission.INTERNET, Manifest.permission.SEND_SMS,
                Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS)) {
            assertFalse("Synthetic custody fixture must not request $permission", permission in requested)
        }
    }

    @OptIn(ExperimentalComposeUiApi::class)
    @Test fun freshFixtureScreenCreatesNativeKitAndRequiresRecordedTokenBeforeExport() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(Intent()
            .setClassName(instrumentation.targetContext, "org.zrotext.gateway.AndroidOwnerCustodyFixtureActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        fun root(view: View): RootForTest? {
            if (view is ViewRootForTest) return view
            if (view is ViewGroup) for (index in 0 until view.childCount) root(view.getChildAt(index))?.let { return it }
            return null
        }
        fun nodes(node: SemanticsNode): List<SemanticsNode> = listOf(node) + node.children.flatMap(::nodes)
        fun text(node: SemanticsNode): String = node.config.getOrNull(SemanticsProperties.Text)
            ?.joinToString(" ") { it.text }.orEmpty()
        try {
            instrumentation.waitForIdleSync()
            instrumentation.runOnMainSync {
                assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                val compose = checkNotNull(root(activity.window.decorView))
                compose.measureAndLayoutForTest()
                val fields = nodes(compose.semanticsOwner.rootSemanticsNode)
                    .filter { it.config.contains(SemanticsActions.SetText) }
                fun field(label: String) = fields.single { candidate -> nodes(candidate).any { text(it).contains(label) } }
                checkNotNull(field("Independent account UUID").config[SemanticsActions.SetText].action)
                    .invoke(AnnotatedString(UUID.randomUUID().toString()))
                checkNotNull(field("Independent HTTPS owner origin").config[SemanticsActions.SetText].action)
                    .invoke(AnnotatedString("https://owner.example"))
            }
            instrumentation.waitForIdleSync()
            instrumentation.runOnMainSync {
                val compose = checkNotNull(root(activity.window.decorView)); compose.measureAndLayoutForTest()
                val create = nodes(compose.semanticsOwner.rootSemanticsNode).single { text(it) == "Create encrypted owner kit" }
                assertTrue(checkNotNull(create.config[SemanticsActions.OnClick].action).invoke())
            }
            var created = false
            for (attempt in 0 until 150) {
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync {
                    val compose = checkNotNull(root(activity.window.decorView)); compose.measureAndLayoutForTest()
                    val current = nodes(compose.semanticsOwner.rootSemanticsNode)
                    created = current.any { text(it).startsWith("Encrypted owner kit created.") }
                    if (created) {
                        val save = current.single { text(it) == "Save encrypted backup to chosen destination" }
                        assertTrue("Export must await deliberate recorded-token acknowledgement", save.config.contains(SemanticsProperties.Disabled))
                    }
                }
                if (created) break
                Thread.sleep(100)
            }
            assertTrue("The real fresh Android screen must create the kit through JNI", created)
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    @Test fun separatelyRetainedKitRecoversInFreshInvocationAndClearsManagedToken() {
        assertTrue("Fixture must package the native custody library", AndroidOwnerCustodyNativeBridge.available)
        val account = ByteArray(16) { 0x41 }
        val created = checkNotNull(AndroidOwnerCustodyNativeBridge.nativeCreate(account, "https://owner.example"))
        val retainedBackup = created[0].copyOf()
        val retainedCard = created[1].copyOf()
        val retainedToken = created[2].copyOf()
        val fingerprint = created[3].copyOf()
        created[2].fill(0)
        AndroidOwnerCustodyNativeBridge.nativeCloseAll()
        // No creation handle, app-private store or Android wrapping key participates.
        assertTrue(AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(retainedBackup, retainedCard,
            retainedToken, account, "https://owner.example", fingerprint))
        assertTrue(retainedToken.all { it == 0.toByte() })
    }

    @Test fun mismatchedIndependentIdentityAndCorruptionRejectAndClearManagedInput() {
        assertTrue(AndroidOwnerCustodyNativeBridge.available)
        val account = ByteArray(16) { 0x42 }
        val created = checkNotNull(AndroidOwnerCustodyNativeBridge.nativeCreate(account, "https://owner.example"))
        val token = created[2].copyOf()
        try {
            val wrongFingerprint = created[3].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(created[0], created[1], token,
                account, "https://owner.example", wrongFingerprint)
            fail("Wrong independent fingerprint must reject")
        } catch (_: IllegalStateException) {
            assertTrue(token.all { it == 0.toByte() })
        }
        val corrupted = created[0].copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val secondToken = created[2].copyOf()
        try {
            AndroidOwnerCustodyNativeBridge.nativeRecoveryCheck(corrupted, created[1], secondToken,
                account, "https://owner.example", created[3])
            fail("Corrupted encrypted backup must reject")
        } catch (_: IllegalStateException) {
            assertTrue(secondToken.all { it == 0.toByte() })
        } finally {
            created[2].fill(0)
            AndroidOwnerCustodyNativeBridge.nativeCloseAll()
        }
    }
}
