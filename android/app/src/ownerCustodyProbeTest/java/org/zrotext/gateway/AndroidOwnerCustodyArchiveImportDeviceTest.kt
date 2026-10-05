// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.ViewGroup
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONTokener
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real native archive AEAD and actual WebView File.arrayBuffer on synthetic material only.
 * The injected session predicate is a fixture; this test grants no live owner authority.
 * No private bytes are printed, returned through JavaScript evaluation or stored on disk.
 */
@RunWith(AndroidJUnit4::class)
class AndroidOwnerCustodyArchiveImportDeviceTest {
    @Test fun exactNativeArchiveProofRejectsRawRootScalarThenAllowsFrozenOneShotPrivateRead() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        assertEquals("org.zrotext.gateway.ownercustodyfixture", target.packageName)
        val native = AndroidOwnerCustodyNative()
        assertTrue("Fixture must package actual native archive custody", native.available)
        val account = UUID.randomUUID()
        val accountBytes = ByteBuffer.allocate(16).putLong(account.mostSignificantBits).putLong(account.leastSignificantBits).array()
        val created = native.create(accountBytes, "https://owner.example")
        var archiveOutput: Array<ByteArray>? = null
        var handle = 0L
        var activity: android.app.Activity? = null
        lateinit var browser: AndroidOwnerCustodyOwnerBrowser
        var browserCreated = false
        val owner = UUID.randomUUID()
        val selected = AtomicReference<ByteArray>()
        val stagedUri = AtomicReference<Uri>()
        val chooserCalls = AtomicInteger(0)
        val proofCalls = AtomicInteger(0)
        val proofAccepted = AtomicInteger(0)
        val metadataOpens = AtomicInteger(0)
        val metadataProbe = AtomicReference("not attempted")
        val metadataState = AtomicReference("not attempted")
        val retainedGrantCounters = AtomicReference<(() -> GrantReadCounters)?>()
        var pageGeneration = 0
        fun script(source: String): String {
            val result = AtomicReference<String>()
            val returned = CountDownLatch(1)
            instrumentation.runOnMainSync {
                browser.evaluateJavascript(source) { value -> result.set(value); returned.countDown() }
            }
            assertTrue("Controlled fixture JavaScript must return", returned.await(5, TimeUnit.SECONDS))
            return checkNotNull(result.get())
        }
        fun loadControlledInput() {
            val generation = ++pageGeneration
            instrumentation.runOnMainSync {
                loadAndroidOwnerCustodyHttpsFixture(browser, "https://owner.example", "/owner/synthetic-archive-import", """
                    <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
                    <style>body{margin:0}input{display:block;width:100%;height:160px}</style></head><body>
                    <input id="fixtureFile" type="file" accept="application/vnd.zrotext.archive-recovery.v1"><script>
                    window.fixtureGeneration=$generation;window.archiveResult='waiting';window.privateReads=0;window.privateReadCalls=0;
                    window.selectedArchiveSize=null;window.selectedArchiveType=null;window.archiveReadError=null;window.archiveHashAvailable=!!(window.crypto&&window.crypto.subtle);
                    document.getElementById('fixtureFile').addEventListener('change',function(event){
                      const file=event.target.files[0];window.selectedArchiveSize=file?file.size:null;window.selectedArchiveType=file?file.type:null;
                      if(!file || file.size!==32){window.archiveResult='wrong size';return;}
                      try{
                        if(typeof file.arrayBuffer!=='function')throw Error('Fixture File.arrayBuffer unavailable');
                        window.privateReadCalls++;
                        file.arrayBuffer().then(async buffer=>{
                          const privateInput=new Uint8Array(buffer);window.privateReads++;
                          try{
                            if(privateInput.byteLength!==32||!window.archiveHashAvailable)throw Error('Fixture hash unavailable');
                            const hash=await window.crypto.subtle.digest('SHA-256',privateInput);
                            window.archiveResult=Array.from(new Uint8Array(hash),
                              value=>value.toString(16).padStart(2,'0')).join('');
                          }catch(_){window.archiveResult='hash error';}finally{privateInput.fill(0);}
                        }).catch(error=>{window.archiveReadError=error&&error.name?error.name:'unknown';window.archiveResult='read error';});
                      }catch(error){window.archiveReadError=error&&error.name?error.name:'unknown';window.archiveResult='read error';}
                    });
                    </script></body></html>
                """.trimIndent())
            }
            var loaded = false
            for (attempt in 0 until 100) {
                if (script("window.fixtureGeneration === $generation && document.getElementById('fixtureFile') !== null") == "true") { loaded = true; break }
                Thread.sleep(100)
            }
            assertTrue("Controlled private input must load without network access", loaded)
            instrumentation.waitForIdleSync()
        }
        fun touchInput(expectedCalls: Int) {
            val location = IntArray(2)
            instrumentation.runOnMainSync { browser.getLocationOnScreen(location) }
            val down = SystemClock.uptimeMillis()
            for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
                val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action,
                    location[0] + 50f, location[1] + 150f, 0)
                event.source = InputDevice.SOURCE_TOUCHSCREEN
                try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
            }
            for (attempt in 0 until 100) {
                if (chooserCalls.get() == expectedCalls) break
                Thread.sleep(100)
            }
            assertEquals("Actual user gesture must invoke the private chooser", expectedCalls, chooserCalls.get())
            instrumentation.waitForIdleSync()
        }
        try {
            require(created.size == 5)
            val kit = AndroidOwnerCustodyKit(created[0], created[1])
            // Original creation inputs and returned public identity are retained independently
            // from the selected key; no selected file supplies expected root/archive identity.
            val identity = AndroidOwnerCustodyIdentity(account, "https://owner.example", AndroidOwnerCustodyKit.hex(created[3]))
            val anchored = SystemClock.elapsedRealtime()
            val authority = AndroidOwnerCustodyAuthority(account, UUID.randomUUID(), UUID.randomUUID(), 2_000_000, anchored, 0)
            val expected = createAndroidOwnerArchiveContext(created[4], identity, authority).bytes()
            handle = native.openTyped(2, byteArrayOf(), expected, kit, identity, authority, anchored)
            assertTrue(handle > 0)
            val reviewed = native.reviewTyped(handle)
            assertTrue(reviewed.size == 2 && reviewed[0].isEmpty() && reviewed[1].contentEquals(expected))
            val output = native.signTyped(handle, created[2], byteArrayOf(), byteArrayOf(), authority, SystemClock.elapsedRealtime())
            archiveOutput = output
            assertTrue(created[2].all { it == 0.toByte() })
            require(output.size == 5 && output[2].size == 32)
            val archiveIdentity = AndroidOwnerCustodyArchiveIdentity(identity,
                AndroidOwnerCustodyKit.hex(output[3]), AndroidOwnerCustodyKit.hex(output[4]))
            val archiveKit = AndroidOwnerCustodyArchiveKit(output[0], archiveIdentity)
            val publicDigest = AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(output[2]))
            activity = instrumentation.startActivitySync(Intent()
                .setClassName(target, "org.zrotext.gateway.AndroidOwnerCustodyFixtureActivity")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            instrumentation.runOnMainSync {
                browser = AndroidOwnerCustodyOwnerBrowser(checkNotNull(activity), identity.origin, {}, chooseArchiveFile = { callback ->
                    val input = checkNotNull(selected.get())
                    val result = runCatching {
                        AndroidOwnerCustodyArchiveImportProvider.stage(target, owner, input, { proof ->
                            proofCalls.incrementAndGet()
                            try {
                                native.archiveRecoveryCheck(archiveKit.backup(), proof, identity,
                                    archiveIdentity.keyBytes(), archiveIdentity.pointBytes()).also { accepted ->
                                    if (accepted) proofAccepted.incrementAndGet()
                                }
                            } catch (_: IllegalStateException) { false }
                            finally { check(proof.all { it == 0.toByte() }) }
                        }, { true })
                    }.getOrNull()
                    input.fill(0) // File.arrayBuffer must read the frozen verified provider copy.
                    if (result != null) {
                        // Chromium obtains file metadata through a readonly FD before its
                        // payload read. Exercise that real platform path without reading
                        // any recovery bytes; it must leave the single payload available.
                        val preserved = runCatching {
                            retainedGrantCounters.set(captureSyntheticGrantCounters(owner))
                            target.contentResolver.openAssetFileDescriptor(result, "r")!!.use { metadata ->
                                metadataOpens.incrementAndGet()
                                check(metadata.startOffset == 0L && metadata.declaredLength == 32L)
                                check(metadata.parcelFileDescriptor.statSize == 32L)
                                val state = syntheticGrantCounts(owner)
                                metadataState.set(state.toString())
                                check(state.entries == 1 && state.grants == 1 && state.opened == 1 && state.delivered == 0)
                                target.contentResolver.query(result,
                                    arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)!!.use {
                                    check(it.moveToFirst() && it.getInt(0) == 32)
                                }
                            }
                            target.contentResolver.query(result,
                                arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)!!.use {
                                check(it.moveToFirst() && it.getInt(0) == 32)
                            }
                        }.isSuccess
                        metadataProbe.set(if (preserved) "payload preserved" else "metadata denied")
                    }
                    stagedUri.set(result)
                    callback.onReceiveValue(result?.let { arrayOf(it) })
                    chooserCalls.incrementAndGet()
                })
                browserCreated = true
                checkNotNull(activity).setContentView(browser, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT))
                assertFalse(browser.settings.allowContentAccess)
                assertFalse(browser.settings.allowFileAccess)
            }
            // This is the published synthetic P-256 scalar 1, never a generated or live root.
            // Raw32 length/MIME/nonzero checks accept it; actual archive AEAD must reject it.
            selected.set(ByteArray(32).also { it[31] = 1 })
            loadControlledInput(); touchInput(1)
            assertEquals(1, proofCalls.get())
            assertEquals(0, proofAccepted.get())
            assertNull("Rejected raw root scalar must never produce a provider URI", stagedUri.get())
            assertEquals("0", script("document.getElementById('fixtureFile').files.length"))
            assertEquals("0", script("window.privateReads"))
            assertEquals("0", script("window.privateReadCalls"))

            selected.set(output[2].copyOf())
            loadControlledInput(); touchInput(2)
            assertEquals(2, proofCalls.get())
            assertEquals(1, proofAccepted.get())
            assertTrue("A real metadata-only FD open/query/close must preserve the sole payload grant; ${metadataState.get()}",
                metadataProbe.get() == "payload preserved")
            assertEquals("Exactly one fixture metadata FD was opened without reading payload", 1, metadataOpens.get())
            val delivered = checkNotNull(stagedUri.get())
            var read = false
            var observedState: String? = null
            for (attempt in 0 until 150) {
                val result = JSONTokener(script("window.archiveResult")).nextValue() as? String
                observedState = result
                if (result == publicDigest) { read = true; break }
                if (result in setOf("wrong size", "read error", "hash error")) break
                Thread.sleep(100)
            }
            val status = if (observedState in setOf("waiting", "wrong size", "read error", "hash error")) observedState else "hash mismatch"
            // Diagnose only status/size/count/capability; no private bytes or filenames escape.
            val diagnostic = "status=$status,size=${script("window.selectedArchiveSize")},reads=${script("window.privateReads")}," +
                "type=${script("window.selectedArchiveType").take(100)},error=${script("window.archiveReadError").take(80)}," +
                "grant=${retainedGrantCounters.get()?.invoke()},subtle=${script("window.archiveHashAvailable")},secure=${script("window.isSecureContext")}"
            assertTrue("File.arrayBuffer must receive exactly the native-verified frozen archive recovery bytes; $diagnostic", read)
            // The purpose is established by the native exact custom-MIME chooser and
            // actual archive AEAD. Chromium may infer only generic file metadata.
            assertEquals(AndroidOwnerCustodyArchiveImportProvider.MIME,
                JSONTokener(script("document.getElementById('fixtureFile').accept")).nextValue())
            val selectedMime = JSONTokener(script("window.selectedArchiveType")).nextValue() as? String
            assertTrue("Selected metadata MIME must match the narrowly allowed native archive input",
                selectedMime != null && selectedMime in setOf(
                    AndroidOwnerCustodyArchiveImportProvider.MIME, "", "application/octet-stream"))
            assertEquals("1", script("window.privateReads"))
            assertEquals("The ordinary private input method must be invoked exactly once", "1", script("window.privateReadCalls"))
            try {
                target.contentResolver.openInputStream(delivered)?.use { stream ->
                    val unexpected = ByteArray(32)
                    try { stream.read(unexpected); fail("Archive recovery provider must deny a second payload") }
                    finally { unexpected.fill(0) }
                }
                fail("Consumed archive recovery grant remained available")
            } catch (_: java.io.FileNotFoundException) { }
            instrumentation.runOnMainSync {
                assertFalse(browser.settings.allowContentAccess)
                assertFalse(browser.settings.allowFileAccess)
            }
        } finally {
            selected.get()?.fill(0)
            archiveOutput?.getOrNull(2)?.fill(0)
            created.getOrNull(2)?.fill(0)
            if (handle > 0) native.close(handle)
            native.closeAll()
            AndroidOwnerCustodyArchiveImportProvider.clear(owner)
            instrumentation.runOnMainSync {
                if (browserCreated) { (browser.parent as? ViewGroup)?.removeView(browser); browser.close() }
                activity?.finish()
            }
            instrumentation.waitForIdleSync()
        }
    }

    /** Inspect only synthetic ownership/counts; never read keys, URI IDs or filenames. */
    private data class GrantCounts(val entries: Int, val grants: Int, val handles: Int,
        val opened: Int, val delivered: Int)

    private fun syntheticGrantCounts(owner: UUID): GrantCounts {
        val provider = AndroidOwnerCustodyArchiveImportProvider::class.java
        val gate = checkNotNull(provider.getDeclaredField("gate").apply { isAccessible = true }.get(null))
        return synchronized(gate) {
            fun owned(field: String): List<Any> = provider.getDeclaredField(field).apply { isAccessible = true }
                .get(null).let { value -> (value as Map<*, *>).values.filterNotNull().filter { grant ->
                    grant.javaClass.getDeclaredField("owner").apply { isAccessible = true }.get(grant) == owner
                } }
            val entries = owned("entries")
            // The prior open-consumes-URI policy has no tracked shared-grant map.
            // This fallback diagnoses it without touching any recovery buffer.
            val grants = runCatching { owned("grants") }.getOrDefault(emptyList())
            fun number(grant: Any, field: String) = grant.javaClass.getDeclaredField(field)
                .apply { isAccessible = true }.getInt(grant)
            GrantCounts(entries.size, grants.size, grants.sumOf { grant ->
                (grant.javaClass.getDeclaredField("handles").apply { isAccessible = true }.get(grant) as Set<*>).size
            }, grants.sumOf { number(it, "opened") }, grants.sumOf { number(it, "delivered") })
        }
    }

    private data class GrantReadCounters(val opened: Int, val delivered: Int, val closed: Boolean,
        val handles: Int, val consumerPresent: Boolean)

    /** Capture the original synthetic grant before Chromium can consume/remove its URI.
     * The retained accessor exposes only bounded counters, even after map removal.
     */
    private fun captureSyntheticGrantCounters(owner: UUID): () -> GrantReadCounters {
        val provider = AndroidOwnerCustodyArchiveImportProvider::class.java
        val gate = checkNotNull(provider.getDeclaredField("gate").apply { isAccessible = true }.get(null))
        val grant = synchronized(gate) {
            val values = provider.getDeclaredField("grants").apply { isAccessible = true }.get(null) as Map<*, *>
            values.values.filterNotNull().single {
                it.javaClass.getDeclaredField("owner").apply { isAccessible = true }.get(it) == owner
            }
        }
        return { synchronized(gate) {
            fun field(name: String) = grant.javaClass.getDeclaredField(name).apply { isAccessible = true }
            GrantReadCounters(field("opened").getInt(grant), field("delivered").getInt(grant),
                field("closed").getBoolean(grant), (field("handles").get(grant) as Set<*>).size,
                field("consumer").get(grant) != null)
        } }
    }
}
