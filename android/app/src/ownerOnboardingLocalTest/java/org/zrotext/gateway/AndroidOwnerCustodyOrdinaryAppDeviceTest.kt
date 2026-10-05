// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.Build
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inspector.WindowInspector
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
import java.io.File
import java.util.UUID
import java.util.zip.ZipFile
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Ordinary MainActivity under a separate local debug ID. This synthetic entry/create test
 * requests no carrier permissions and invokes no pairing, network login, runtime or send action.
 * Creation never reveals its token or establishes owner session/enrollment/hardware authority.
 */
@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyOrdinaryAppDeviceTest {
    @OptIn(ExperimentalComposeUiApi::class)
    @Test fun ordinarySetupEntryCreatesNativeKitWithEveryAbiPackagedAndNoTokenReveal() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        assertEquals("org.zrotext.gateway.owneronboardinglocal", target.packageName)
        assertFalse("The local debug candidate must start with no prior owner kit",
            File(target.noBackupFilesDir, "android-owner-custody-v1").exists())
        ZipFile(target.applicationInfo.sourceDir).use { apk ->
            for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")) {
                assertNotNull("Ordinary candidate must package each reviewed native ABI",
                    apk.getEntry("lib/$abi/libzrotext_android_owner_custody.so"))
            }
        }
        assertTrue("Ordinary APK must load the real native custody library", AndroidOwnerCustodyNativeBridge.available)
        val activity = instrumentation.startActivitySync(Intent().setClassName(target, "org.zrotext.gateway.MainActivity")
            .putExtra("gateway_screen", "SETUP").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        fun root(view: View): RootForTest? {
            if (view is ViewRootForTest) return view
            if (view is ViewGroup) for (index in 0 until view.childCount) root(view.getChildAt(index))?.let { return it }
            return null
        }
        fun nodes(node: SemanticsNode): List<SemanticsNode> = listOf(node) + node.children.flatMap(::nodes)
        fun text(node: SemanticsNode): String = node.config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text }.orEmpty()
        fun views(): List<View> = if (Build.VERSION.SDK_INT >= 29) WindowInspector.getGlobalWindowViews()
            else listOf(activity.window.decorView)
        fun current(): List<SemanticsNode> = views().mapNotNull(::root).flatMap { compose ->
            compose.measureAndLayoutForTest(); nodes(compose.semanticsOwner.rootSemanticsNode)
        }
        fun waitForSemantics(description: String, ready: (List<SemanticsNode>) -> Boolean) {
            var found = false
            for (attempt in 0 until 150) {
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync { found = ready(current()) }
                if (found) break
                Thread.sleep(100)
            }
            assertTrue(description, found)
        }
        try {
            instrumentation.waitForIdleSync()
            instrumentation.runOnMainSync {
                val setup = current().single { text(it) == "Set up or recover owner custody on Android" }
                assertTrue(checkNotNull(setup.config[SemanticsActions.OnClick].action).invoke())
            }
            waitForSemantics("The secure owner dialog must mount both independent identity fields") { current ->
                val fields = current.filter { it.config.contains(SemanticsActions.SetText) }
                listOf("Independent account UUID", "Independent HTTPS owner origin").all { label ->
                    fields.count { candidate -> nodes(candidate).any { text(it).contains(label) } } == 1
                }
            }
            instrumentation.runOnMainSync {
                val current = current()
                val fields = current.filter { it.config.contains(SemanticsActions.SetText) }
                fun field(label: String): SemanticsNode = fields.single { candidate -> nodes(candidate).any { text(it).contains(label) } }
                checkNotNull(field("Independent account UUID").config[SemanticsActions.SetText].action)
                    .invoke(AnnotatedString(UUID.randomUUID().toString()))
                checkNotNull(field("Independent HTTPS owner origin").config[SemanticsActions.SetText].action)
                    .invoke(AnnotatedString("https://owner.example"))
                assertTrue("The owner dialog must protect its window", views().any { view ->
                    (((view.layoutParams as? WindowManager.LayoutParams)?.flags ?: 0) and WindowManager.LayoutParams.FLAG_SECURE) != 0
                })
            }
            waitForSemantics("The owner dialog must expose its native kit creation action") { current ->
                current.count { text(it) == "Create encrypted owner kit" && it.config.contains(SemanticsActions.OnClick) } == 1
            }
            instrumentation.runOnMainSync {
                val create = current().single { text(it) == "Create encrypted owner kit" }
                assertTrue(checkNotNull(create.config[SemanticsActions.OnClick].action).invoke())
            }
            var created = false
            for (attempt in 0 until 150) {
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync {
                    val current = current()
                    created = current.any { text(it).startsWith("Encrypted owner kit created.") }
                    if (created) {
                        val save = current.single { text(it) == "Save encrypted backup to chosen destination" }
                        assertTrue(save.config.contains(SemanticsProperties.Disabled))
                        assertFalse("Creation must never reveal the private recovery token", current.any {
                            Regex("ZTRK1-(?:[A-Z2-7]{4}-){13}[0-9A-F]{8}").containsMatchIn(text(it))
                        })
                    }
                }
                if (created) break
                Thread.sleep(100)
            }
            assertTrue("Ordinary setup must execute real native kit creation", created)
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
