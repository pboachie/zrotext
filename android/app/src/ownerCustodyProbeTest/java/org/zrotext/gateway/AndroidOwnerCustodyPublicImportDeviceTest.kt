// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.ViewGroup
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONTokener
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Navigation response fixture only: the actual hardened client still checks URLs/SSL.
 * Exactly one pinned HTTPS main frame gets static local HTML; every other request is denied.
 * No network permission, native JavaScript bridge or production client is changed.
 */
internal fun loadAndroidOwnerCustodyHttpsFixture(browser: AndroidOwnerCustodyOwnerBrowser,
    origin: String, path: String, html: String) {
    val expected = origin + path
    require(AndroidOwnerCustodyOwnerBrowser.allowed(origin, expected))
    val hardened = browser.webViewClient
    browser.stopLoading()
    browser.webViewClient = object : android.webkit.WebViewClient() {
        override fun shouldOverrideUrlLoading(view: android.webkit.WebView,
            request: android.webkit.WebResourceRequest) = hardened.shouldOverrideUrlLoading(view, request)
        override fun shouldInterceptRequest(view: android.webkit.WebView,
            request: android.webkit.WebResourceRequest): android.webkit.WebResourceResponse {
            if (request.isForMainFrame && request.url.toString() == expected &&
                AndroidOwnerCustodyOwnerBrowser.allowed(origin, request.url.toString())) {
                return android.webkit.WebResourceResponse("text/html", "UTF-8", 200, "OK",
                    mapOf("Cache-Control" to "no-store"), java.io.ByteArrayInputStream(html.toByteArray(Charsets.UTF_8)))
            }
            return hardened.shouldInterceptRequest(view, request) ?: android.webkit.WebResourceResponse(
                "text/plain", "UTF-8", 403, "Fixture request refused", mapOf("Cache-Control" to "no-store"),
                java.io.ByteArrayInputStream(byteArrayOf()))
        }
        override fun onPageStarted(view: android.webkit.WebView, url: String?, favicon: android.graphics.Bitmap?) {
            hardened.onPageStarted(view, url, favicon)
        }
        override fun onReceivedSslError(view: android.webkit.WebView, handler: android.webkit.SslErrorHandler,
            error: android.net.http.SslError) { hardened.onReceivedSslError(view, handler, error) }
    }
    browser.loadUrl(expected)
}

/** Real WebView chooser/FileReader on frozen public fixture bytes. No root/recovery material,
 * network, native JavaScript bridge, SMS or signature-validity claim participates.
 */
@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyPublicImportDeviceTest {
    @Test fun hardenedBrowserReadsExactlyFrozenPublicChooserBytesWithoutContentNavigation() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        assertEquals("org.zrotext.gateway.ownercustodyfixture", target.packageName)
        val activity = instrumentation.startActivitySync(Intent()
            .setClassName(target, "org.zrotext.gateway.AndroidOwnerCustodyFixtureActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val owner = UUID.randomUUID()
        val original = ByteArray(64) { (it + 1).toByte() } // Synthetic public-signature framing only.
        val expected = AndroidOwnerCustodyKit.hex(original)
        val chooserCalls = AtomicInteger(0)
        lateinit var browser: AndroidOwnerCustodyOwnerBrowser
        var browserCreated = false
        fun script(source: String): String {
            val result = AtomicReference<String>()
            val returned = CountDownLatch(1)
            instrumentation.runOnMainSync {
                browser.evaluateJavascript(source) { value -> result.set(value); returned.countDown() }
            }
            assertTrue("Controlled fixture JavaScript must return", returned.await(5, TimeUnit.SECONDS))
            return checkNotNull(result.get())
        }
        data class PublicProbe(val exact: Boolean, val state: String?, val size: String)
        fun readControlledInput(allowContent: Boolean, generation: Int): PublicProbe {
            instrumentation.runOnMainSync {
                // Fixture-only diagnostic matrix. Production remains content-access disabled.
                browser.settings.allowContentAccess = allowContent
                loadAndroidOwnerCustodyHttpsFixture(browser, "https://owner.example", "/owner/synthetic-public-import", """
                    <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
                    <style>body{margin:0}input{display:block;width:100%;height:160px}</style></head><body>
                    <input id="fixtureFile" type="file"><script>
                    window.fixtureGeneration=$generation;window.publicResult='waiting';window.selectedPublicSize=null;
                    document.getElementById('fixtureFile').addEventListener('change', function(event) {
                      const file=event.target.files[0];window.selectedPublicSize=file?file.size:null;
                      if(!file || file.size!==64){window.publicResult='wrong size';return;}
                      const reader=new FileReader();
                      reader.onerror=()=>{window.publicResult='read error';};
                      reader.onload=()=>{window.publicResult=Array.from(new Uint8Array(reader.result),
                        value=>value.toString(16).padStart(2,'0')).join('');};
                      reader.readAsArrayBuffer(file);
                    });
                    </script></body></html>
                """.trimIndent())
                assertEquals(allowContent, browser.settings.allowContentAccess)
                assertFalse(browser.settings.allowFileAccess)
            }
            var loaded = false
            for (attempt in 0 until 100) {
                if (script("window.fixtureGeneration === $generation && document.getElementById('fixtureFile') !== null") == "true") { loaded = true; break }
                Thread.sleep(100)
            }
            assertTrue("Controlled inline page must load without network access", loaded)
            instrumentation.waitForIdleSync()
            val location = IntArray(2)
            instrumentation.runOnMainSync { browser.getLocationOnScreen(location) }
            val down = SystemClock.uptimeMillis()
            val x = location[0] + 50f; val y = location[1] + 150f
            for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
                val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, x, y, 0)
                event.source = InputDevice.SOURCE_TOUCHSCREEN
                try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
            }
            var observedState: String? = null
            for (attempt in 0 until 150) {
                val result = JSONTokener(script("window.publicResult")).nextValue() as? String
                observedState = result
                if (result == expected || result == "wrong size" || result == "read error") break
                Thread.sleep(100)
            }
            assertEquals("A real user gesture must invoke each diagnostic chooser", generation, chooserCalls.get())
            return PublicProbe(observedState == expected, observedState?.take(160), script("window.selectedPublicSize"))
        }
        try {
            val staged = AndroidOwnerCustodyPublicImportProvider.stage(target, owner, original)
            original.fill(0) // Later reads must use the exact validated immutable copy.
            target.contentResolver.openAssetFileDescriptor(staged, "r")!!.use { asset ->
                assertEquals("Direct provider AFD must declare the exact public length", 64L, asset.declaredLength)
                assertEquals(0L, asset.startOffset)
                val direct = asset.createInputStream().use { readAndroidOwnerCustodyFile(it, 64) }
                assertEquals("Direct provider payload must match all frozen public bytes", expected, AndroidOwnerCustodyKit.hex(direct))
            }
            instrumentation.runOnMainSync {
                browser = AndroidOwnerCustodyOwnerBrowser(activity, "https://owner.example", {}) { callback ->
                    chooserCalls.incrementAndGet(); callback.onReceiveValue(arrayOf(staged))
                }
                browserCreated = true
                activity.setContentView(browser, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT))
                assertFalse(browser.settings.allowContentAccess)
                assertFalse(browser.settings.allowFileAccess)
            }
            val disabled = readControlledInput(false, 1)
            val enabledDiagnostic = readControlledInput(true, 2)
            instrumentation.runOnMainSync {
                browser.settings.allowContentAccess = false
                assertFalse(browser.settings.allowContentAccess)
                assertFalse(browser.settings.allowFileAccess)
            }
            // The enabled row is diagnostic only and cannot satisfy the hardened acceptance.
            val webViewVersion = android.webkit.WebView.getCurrentWebViewPackage()?.versionName?.take(80)
            assertTrue("Hardened FileReader requires every frozen public byte; disabled=$disabled, enabledDiagnostic=$enabledDiagnostic, WebView=$webViewVersion", disabled.exact)
        } finally {
            original.fill(0)
            AndroidOwnerCustodyPublicImportProvider.clear(owner)
            instrumentation.runOnMainSync {
                if (browserCreated) {
                    browser.settings.allowContentAccess = false
                    (browser.parent as? ViewGroup)?.removeView(browser)
                    browser.close()
                }
                activity.finish()
            }
            instrumentation.waitForIdleSync()
        }
    }
}
