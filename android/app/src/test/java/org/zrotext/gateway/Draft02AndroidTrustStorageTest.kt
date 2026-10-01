// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class Draft02AndroidTrustStorageTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private val directory get() = File(context.noBackupFilesDir, "draft02-compared-root-primary")
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val aad = "synthetic-atomic-storage-fixture".toByteArray()
    private fun sealed(value: String) = Draft02RootStateCipher.seal(key, aad, value.toByteArray())
    private fun unsealFixture(value: ByteArray) = Draft02RootStateCipher.open(key, aad, value).toString(Charsets.UTF_8)

    @After fun cleanup() {
        check(directory.parentFile!!.canonicalFile == context.noBackupFilesDir.canonicalFile)
        check(!directory.exists() || directory.deleteRecursively())
    }
    private fun failure(status: Draft02TrustStore.Status, action: () -> Unit) {
        try { action(); fail("Expected storage refusal") }
        catch (error: Draft02TrustStore.Failure) { assertEquals(status, error.status) }
    }

    @Test fun constructionReadAndUnsupportedEnrollmentNeverProvisionAKey() {
        assertFalse(directory.exists())
        val storage = Draft02AndroidTrustStorage(context)
        assertFalse(directory.exists())
        storage.locked {
            assertEquals(Draft02TrustStore.KeyState.UNSUPPORTED, keyState())
            assertNull(read())
        }
        val store = Draft02TrustStore(storage)
        assertEquals(Draft02TrustStore.Status.UNSUPPORTED, store.inspect().status)
        val fixture = JSONObject(javaClass.classLoader!!.getResourceAsStream("draft02-genesis.json")!!
            .bufferedReader().use { it.readText() })
        val pin = Base64.getDecoder().decode(fixture.getString("root_pin_b64"))
        val comparison = Draft02RootComparison()
        val display = comparison.begin(pin, pin.copyOfRange(5, 21))
        val result = store.enroll(comparison.confirm(display.fingerprintHex, true))
        assertEquals(Draft02TrustStore.Status.UNSUPPORTED, result.status)
        assertNull(result.snapshot)
        assertFalse(File(directory, "root-state").exists())
        storage.close()
    }

    @Test fun atomicCancellationKeepsOldCiphertextAcrossReconstruction() {
        val storage = Draft02AndroidTrustStorage(context)
        val old = sealed("old synthetic state")
        storage.locked { write(old) {} }
        try {
            storage.locked { write(sealed("new synthetic state")) { error("Synthetic cancellation") } }
            fail("Expected cancellation")
        } catch (_: IllegalStateException) { }
        storage.close()
        Draft02AndroidTrustStorage(context).use { reopened -> reopened.locked {
            assertArrayEquals(old, read())
            assertEquals("old synthetic state", unsealFixture(checkNotNull(read())))
        } }
    }

    @Test fun partialBackupAndOversizedRecordsAreTypedRefusals() {
        Draft02AndroidTrustStorage(context).use { storage ->
            storage.locked { assertNull(read()) }
            val partial = File(directory, "root-state.new")
            partial.writeBytes(byteArrayOf(1))
            failure(Draft02TrustStore.Status.RECOVERY_REQUIRED) { storage.locked { read() } }
            assertTrue(partial.delete())
            val backup = File(directory, "root-state.bak")
            backup.writeBytes(byteArrayOf(1))
            failure(Draft02TrustStore.Status.RECOVERY_REQUIRED) { storage.locked { read() } }
            assertTrue(backup.delete())
            File(directory, "root-state").writeBytes(ByteArray(Draft02TrustStore.MAX_BYTES + 1))
            failure(Draft02TrustStore.Status.CORRUPT) { storage.locked { read() } }
        }
    }

    @Test fun sessionCannotEscapeItsTransactionOrCrossThreads() {
        Draft02AndroidTrustStorage(context).use { storage ->
            lateinit var escaped: Draft02TrustStore.Session
            val worker = Executors.newSingleThreadExecutor()
            try {
                storage.locked {
                    escaped = this
                    worker.submit { failure(Draft02TrustStore.Status.IO_FAILURE) { escaped.read() } }
                        .get(5, TimeUnit.SECONDS)
                    assertNull(read())
                }
                failure(Draft02TrustStore.Status.IO_FAILURE) { escaped.read() }
                failure(Draft02TrustStore.Status.IO_FAILURE) { escaped.createKey() }
                failure(Draft02TrustStore.Status.IO_FAILURE) { storage.locked { storage.locked { read() } } }
            } finally { worker.shutdownNow() }
        }
    }

    @Test fun closeDuringPreCommitRollsBackAndNeverDeletesExistingState() {
        val storage = Draft02AndroidTrustStorage(context)
        val old = sealed("persisted synthetic state")
        storage.locked { write(old) {} }
        failure(Draft02TrustStore.Status.IO_FAILURE) {
            storage.locked { write(sealed("cancelled synthetic state")) { storage.close() } }
        }
        storage.close()
        assertEquals(Draft02TrustStore.Status.IO_FAILURE, Draft02TrustStore(storage).inspect().status)
        Draft02AndroidTrustStorage(context).use { reopened -> reopened.locked { assertArrayEquals(old, read()) } }
    }

    @Test fun separateHandlesSerializeWholeAtomicReadModifyWrite() {
        val first = Draft02AndroidTrustStorage(context)
        val second = Draft02AndroidTrustStorage(context)
        first.locked { write(sealed("0")) {} }
        val pool = Executors.newFixedThreadPool(2)
        try {
            val tasks = listOf(first, second).map { storage -> pool.submit {
                repeat(8) { storage.locked {
                    val value = unsealFixture(checkNotNull(read())).toInt() + 1
                    write(sealed(value.toString())) {}
                } }
            } }
            tasks.forEach { it.get(15, TimeUnit.SECONDS) }
            first.locked { assertEquals("16", unsealFixture(checkNotNull(read()))) }
        } finally { pool.shutdownNow(); first.close(); second.close() }
    }
}
