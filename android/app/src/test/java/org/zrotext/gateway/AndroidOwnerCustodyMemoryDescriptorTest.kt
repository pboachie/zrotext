// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.SystemClock
import android.os.storage.StorageManager
import android.system.ErrnoException
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implements
import org.robolectric.annotation.Implementation
import org.robolectric.shadows.ShadowSystemClock
import java.io.FileNotFoundException
import java.nio.file.Files
import java.time.Duration
import java.util.UUID

/** JVM-only synthetic FUSE stand-in. Production always calls Android's proxy API;
 * actual stat/pread and WebView FileReader acceptance runs on the Android device.
 */
@Implements(StorageManager::class)
class AndroidOwnerCustodyProxyStorageFixture {
    @Implementation
    protected fun openProxyFileDescriptor(mode: Int, callback: ProxyFileDescriptorCallback,
        handler: Handler): ParcelFileDescriptor {
        check(mode == ParcelFileDescriptor.MODE_READ_ONLY && handler.looper != Looper.getMainLooper())
        val size = callback.onGetSize().toInt()
        check(size in 1..20_480)
        val data = ByteArray(size)
        check(callback.onRead(0, size, data) == size)
        val path = Files.createTempFile("owner-proxy-fixture-", ".bin").toFile()
        try {
            path.writeBytes(data)
            path.deleteOnExit()
            return ParcelFileDescriptor.open(path, mode, handler) { callback.onRelease(); path.delete() }
        } finally { data.fill(0) }
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AndroidOwnerCustodyProxyStorageFixture::class])
class AndroidOwnerCustodyMemoryDescriptorTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private fun frozen(bytes: ByteArray, available: () -> Boolean = { true }) =
        AndroidOwnerCustodyMemoryDescriptor.Frozen(UUID.randomUUID(), bytes, SystemClock.elapsedRealtime(), 30_000, available)

    @Test fun readonlyOffsetsReturnExactBytesUntilEofAndReleaseWipesOwnership() {
        val source = ByteArray(32) { it.toByte() }
        val callback = frozen(source)
        assertEquals(32L, callback.onGetSize())
        val chunk = ByteArray(9)
        assertEquals(9, callback.onRead(7, chunk.size, chunk))
        assertArrayEquals(ByteArray(9) { (it + 7).toByte() }, chunk)
        assertEquals(2, callback.onRead(30, chunk.size, chunk))
        assertEquals(0, callback.onRead(Long.MAX_VALUE, chunk.size, chunk))
        callback.onRelease()
        assertTrue(source.all { it == 0.toByte() })
        denied { callback.onRead(0, 1, chunk) }
    }

    @Test fun invalidOffsetsWritesAndWithdrawnAuthorityRevokeAndWipe() {
        for (operation in listOf<(AndroidOwnerCustodyMemoryDescriptor.Frozen) -> Unit>(
            { it.onRead(-1, 1, ByteArray(1)) }, { it.onRead(0, 2, ByteArray(1)) },
            { it.onWrite(0, 1, byteArrayOf(9)) })) {
            val source = ByteArray(32) { 7 }
            val callback = frozen(source)
            denied { operation(callback) }
            assertTrue(source.all { it == 0.toByte() })
        }
        var live = true
        val source = ByteArray(32) { 7 }
        val callback = frozen(source) { live }
        assertEquals(32L, callback.onGetSize())
        live = false
        denied { callback.onRead(0, 32, ByteArray(32)) }
        assertTrue(source.all { it == 0.toByte() })
    }

    @Test fun activeDescriptorDeadlineAndOwnerClearWipeEvenAfterUriConsumption() {
        val owner = UUID.randomUUID()
        val first = ByteArray(32) { 7 }
        val second = ByteArray(32) { 9 }
        try {
            AndroidOwnerCustodyMemoryDescriptor.open(context, owner, first, SystemClock.elapsedRealtime(), 30_000)
            AndroidOwnerCustodyMemoryDescriptor.clear(owner)
            assertTrue(first.all { it == 0.toByte() })
            AndroidOwnerCustodyMemoryDescriptor.open(context, owner, second, SystemClock.elapsedRealtime(), 30_000)
            ShadowSystemClock.advanceBy(Duration.ofMillis(30_001))
            shadowOf(Looper.getMainLooper()).idle()
            assertTrue(second.all { it == 0.toByte() })
        } finally { AndroidOwnerCustodyMemoryDescriptor.clear(owner) }
    }

    @Test fun activeDescriptorCapFailsClosedAndWipesTheRejectedCopy() {
        val owner = UUID.randomUUID()
        val opened = ArrayList<ParcelFileDescriptor>()
        try {
            repeat(64) { opened += AndroidOwnerCustodyMemoryDescriptor.open(context, owner,
                ByteArray(64) { 7 }, SystemClock.elapsedRealtime(), 30_000) }
            val rejected = ByteArray(64) { 9 }
            try { AndroidOwnerCustodyMemoryDescriptor.open(context, owner, rejected,
                SystemClock.elapsedRealtime(), 30_000); fail("Unbounded active descriptors accepted") }
            catch (_: FileNotFoundException) { }
            assertTrue(rejected.all { it == 0.toByte() })
        } finally {
            AndroidOwnerCustodyMemoryDescriptor.clear(owner)
            opened.forEach { runCatching { it.close() } }
        }
    }

    @Test fun authorityWithdrawnBeforeDescriptorRegistrationRejectsAndImmediatelyWipes() {
        val owner = UUID.randomUUID()
        val source = ByteArray(32) { 7 }
        try {
            try { AndroidOwnerCustodyMemoryDescriptor.open(context, owner, source,
                SystemClock.elapsedRealtime(), 30_000) { false }; fail("Withdrawn grant opened") }
            catch (_: FileNotFoundException) { }
            assertTrue(source.all { it == 0.toByte() })
        } finally { AndroidOwnerCustodyMemoryDescriptor.clear(owner) }
    }

    private fun denied(action: () -> Unit) {
        try { action(); fail("Unavailable callback delivered bytes") } catch (_: ErrnoException) { }
    }
}
