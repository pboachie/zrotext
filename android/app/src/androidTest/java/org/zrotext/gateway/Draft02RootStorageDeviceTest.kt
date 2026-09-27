// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Unique synthetic no-backup namespaces only. No app launch, existing alias, SMS or physical device. */
@RunWith(AndroidJUnit4::class)
class Draft02RootStorageDeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    @Before fun requireIsolatedEmulator() {
        check(InstrumentationRegistry.getArguments().getString("a11yIsolatedEmulator") == "true")
        check(Build.HARDWARE in setOf("ranchu", "goldfish"))
    }

    @Test fun atomicFilesPreserveOldStateOnCancellationAndDetectPartialOrOversizedState() = isolated { namespace, directory ->
        val storage = Draft02AtomicRootStorage.isolated(context, namespace)
        val old = byteArrayOf(1, 2, 3)
        storage.locked { write(old) {} }
        try {
            storage.locked { write(byteArrayOf(4, 5)) { throw IllegalStateException("Synthetic cancellation") } }
            fail("Expected cancellation")
        } catch (_: IllegalStateException) { }
        Draft02AtomicRootStorage.isolated(context, namespace).locked { assertArrayEquals(old, read()) }
        val base = File(directory, "root-state")
        assertTrue(base.delete())
        File(directory, "root-state.new").writeBytes(byteArrayOf(1))
        assertFailure(Draft02TrustStore.Status.RECOVERY_REQUIRED) { storage.locked { read() } }
        assertTrue(File(directory, "root-state.new").delete())
        base.writeBytes(ByteArray(Draft02TrustStore.MAX_BYTES + 1))
        assertFailure(Draft02TrustStore.Status.CORRUPT) { storage.locked { read() } }
    }

    @Test fun twoAdapterInstancesSerializeWholeReadModifyWriteTransactions() = isolated { namespace, _ ->
        val first = Draft02AtomicRootStorage.isolated(context, namespace)
        val second = Draft02AtomicRootStorage.isolated(context, namespace)
        first.locked { write(byteArrayOf(0)) {} }
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val futures = listOf(first, second).map { storage -> pool.submit {
                check(start.await(5, TimeUnit.SECONDS))
                repeat(8) { storage.locked { write(byteArrayOf((read()!![0] + 1).toByte())) {} } }
            } }
            start.countDown()
            futures.forEach { it.get(20, TimeUnit.SECONDS) }
            second.locked { assertArrayEquals(byteArrayOf(16), read()) }
        } finally { pool.shutdownNow() }
    }

    @Test fun platformCustodyIsHardwareOrExplicitUnsupportedAndReadNeverRecreatesKey() = isolated { namespace, _ ->
        val alias = "org.zrotext.draft02-compared-root-$namespace"
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val storage = Draft02AtomicRootStorage.isolated(context, namespace)
        val store = Draft02TrustStore(storage)
        assertEquals(Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON, store.inspect().status)
        assertFalse(keystore.containsAlias(alias))
        val fixture = JSONObject(javaClass.classLoader!!.getResourceAsStream("draft02-genesis.json")!!
            .bufferedReader().use { it.readText() })
        val pin = Base64.getDecoder().decode(fixture.getString("root_pin_b64"))
        val comparison = Draft02RootComparison()
        val display = comparison.begin(pin, pin.copyOfRange(5, 21))
        val result = store.enroll(comparison.confirm(display.fingerprintHex, true))
        if (result.status == Draft02TrustStore.Status.UNSUPPORTED) {
            // Software-only emulators must prove explicit rejection, never silently skip/fall back.
            assertNull(result.snapshot)
            assertEquals(if (keystore.containsAlias(alias)) Draft02TrustStore.Status.UNSUPPORTED
                else Draft02TrustStore.Status.UNENROLLED_NEEDS_COMPARISON, store.inspect().status)
            storage.locked { assertNull(read()) }
            InstrumentationRegistry.getInstrumentation().addResults(Bundle().apply {
                putString("rootStorageCustody", "unsupported")
            })
        } else {
            assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, result.status)
            storage.locked {
                val encrypted = read()!!
                assertFalse(encrypted.contentEquals(result.snapshot!!.bytes()))
                assertFailure(Draft02TrustStore.Status.CORRUPT) {
                    open(encrypted.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
                }
                val wrongAad = Draft02RootStorageKey(alias, byteArrayOf(1))
                assertFailure(Draft02TrustStore.Status.CORRUPT) { wrongAad.open(encrypted) }
            }
            assertEquals(Draft02TrustStore.Status.NEEDS_FRESHNESS, Draft02TrustStore(storage).inspect().status)
            InstrumentationRegistry.getInstrumentation().addResults(Bundle().apply {
                putString("rootStorageCustody", "platform-reported-hardware")
            })
        }
        keystore.deleteEntry(alias)
        // Exercise existing-key-only reads even on software-only emulators.
        storage.locked { write(byteArrayOf(1, 2, 3)) {} }
        assertEquals(Draft02TrustStore.Status.KEY_LOST, store.inspect().status)
        assertFalse(keystore.containsAlias(alias))
    }

    private fun assertFailure(expected: Draft02TrustStore.Status, action: () -> Unit) {
        try { action(); fail("Expected explicit failure") }
        catch (failure: Draft02TrustStore.Failure) { assertEquals(expected, failure.status) }
    }
    private fun isolated(action: (String, File) -> Unit) {
        val namespace = "test-" + UUID.randomUUID().toString()
        val directory = File(context.noBackupFilesDir, "draft02-compared-root-$namespace")
        check(!directory.exists())
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "org.zrotext.draft02-compared-root-$namespace"
        check(!keystore.containsAlias(alias))
        try { action(namespace, directory) }
        finally {
            keystore.deleteEntry(alias)
            check(directory.parentFile!!.canonicalFile == context.noBackupFilesDir.canonicalFile)
            check(directory.name == "draft02-compared-root-$namespace")
            check(!directory.exists() || directory.deleteRecursively())
        }
    }
}
