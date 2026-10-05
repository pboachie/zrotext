// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.content.pm.ProviderInfo
import android.content.pm.ResolveInfo
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import android.system.ErrnoException
import org.junit.Assert.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implements
import org.robolectric.annotation.Implementation
import org.robolectric.shadows.ShadowBinder
import org.robolectric.shadows.ShadowContentResolver
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.time.Duration
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Metadata-only JVM stand-in: synthetic zero-length content is extended to the
 * declared size, without requesting or writing private callback bytes. Real
 * Android stat/pread and hardened FileReader remain mandatory device acceptance.
 */
@Implements(StorageManager::class)
class AndroidOwnerCustodyArchiveMetadataStorageFixture {
    companion object { val opens = AtomicInteger() }
    @Implementation
    protected fun openProxyFileDescriptor(mode: Int, callback: ProxyFileDescriptorCallback,
        handler: Handler): ParcelFileDescriptor {
        check(mode == ParcelFileDescriptor.MODE_READ_ONLY && handler.looper != Looper.getMainLooper())
        val size = callback.onGetSize()
        check(size == 32L)
        opens.incrementAndGet()
        val path = Files.createTempFile("archive-metadata-fixture-", ".bin").toFile()
        RandomAccessFile(path, "rw").use { it.setLength(size) }
        path.deleteOnExit()
        return ParcelFileDescriptor.open(path, mode, handler) { callback.onRelease(); path.delete() }
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AndroidOwnerCustodyArchiveMetadataStorageFixture::class])
class AndroidOwnerCustodyArchiveImportDescriptorTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private val owners = ArrayList<UUID>()
    private lateinit var provider: AndroidOwnerCustodyArchiveImportProvider

    @Before fun installPrivateMetadataFixture() {
        ShadowBinder.setCallingUid(Process.myUid())
        AndroidOwnerCustodyArchiveMetadataStorageFixture.opens.set(0)
        val authority = context.packageName + ".owner-archive-import"
        provider = AndroidOwnerCustodyArchiveImportProvider()
        provider.attachInfo(context, ProviderInfo().apply {
            this.authority = authority; exported = false; grantUriPermissions = false
        })
        ShadowContentResolver.registerProviderInternal(authority, provider)
        shadowOf(context.packageManager).addResolveInfoForIntent(Intent(DocumentsContract.PROVIDER_INTERFACE),
            ResolveInfo().apply { providerInfo = ProviderInfo().apply {
                this.authority = authority; exported = false; grantUriPermissions = false
            } })
    }
    @After fun revokeEverySyntheticOwner() { owners.forEach(AndroidOwnerCustodyArchiveImportProvider::clear) }

    private fun staged(available: () -> Boolean = { true }): Pair<UUID, android.net.Uri> {
        val owner = UUID.randomUUID().also { owners.add(it) }
        return owner to AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }, available)
    }

    @Test fun eightCumulativeMetadataOpensDoNotReadOrResetTheirBudget() {
        val (_, uri) = staged()
        val retained = ownedBytes(uri)
        repeat(8) {
            val handle = provider.registerHandle(uri)
            assertEquals(32L, handle.onGetSize())
            assertEquals(0, handle.onRead(0, 0, ByteArray(0)))
            handle.onRelease()
            assertArrayEquals(ByteArray(32) { 7 }, retained)
        }
        denied { provider.registerHandle(uri) }
        provider.query(uri, null, null, null, null).use { assertTrue(it.moveToFirst()) }
        assertArrayEquals(ByteArray(32) { 7 }, retained)
    }

    @Test fun firstDataReadSelectsOnlyOneConsumerAndDeliversSequential32Bytes() {
        val (_, uri) = staged()
        val retained = ownedBytes(uri)
        val first = provider.registerHandle(uri)
        val sibling = provider.registerHandle(uri)
        val a = ByteArray(11)
        assertEquals(11, first.onRead(0, a.size, a))
        assertArrayEquals(ByteArray(11) { 7 }, a)
        denied { sibling.onRead(0, 32, ByteArray(32)) }
        denied { provider.registerHandle(uri) }
        provider.query(uri, null, null, null, null).use { assertTrue(it.moveToFirst()); assertEquals(32, it.getInt(1)) }
        val b = ByteArray(25)
        assertEquals(21, first.onRead(11, b.size, b))
        assertArrayEquals(ByteArray(21) { 7 } + ByteArray(4), b)
        assertArrayEquals(ByteArray(32), retained)
        assertEquals(0, first.onRead(32, 1, ByteArray(1)))
        denied { first.onRead(0, 1, ByteArray(1)) }
        denied { provider.query(uri, null, null, null, null) }
    }

    @Test fun consumerCloseWipesTheWholeGrantAfterUriConsumption() {
        val (_, uri) = staged()
        val retained = ownedBytes(uri)
        val consumer = provider.registerHandle(uri)
        val sibling = provider.registerHandle(uri)
        assertEquals(8, consumer.onRead(0, 8, ByteArray(8)))
        consumer.onRelease()
        assertArrayEquals(ByteArray(32), retained)
        denied { sibling.onGetSize() }
        denied { provider.query(uri, null, null, null, null) }
        denied { provider.registerHandle(uri) }
    }

    @Test fun cancellationBetweenRegistrationAndPlatformCreationReturnsNoDescriptor() {
        val (owner, uri) = staged()
        val retained = ownedBytes(uri)
        val handle = provider.registerHandle(uri)
        AndroidOwnerCustodyArchiveImportProvider.clear(owner)
        denied { AndroidOwnerCustodyArchiveImportDescriptor.open(context, handle) }
        assertEquals(0, AndroidOwnerCustodyArchiveMetadataStorageFixture.opens.get())
        assertArrayEquals(ByteArray(32), retained)
    }

    @Test fun ownerClearRevokesAConsumerTrackedAfterUriRemoval() {
        val (owner, uri) = staged()
        val retained = ownedBytes(uri)
        val handle = provider.registerHandle(uri)
        assertEquals(8, handle.onRead(0, 8, ByteArray(8)))
        AndroidOwnerCustodyArchiveImportProvider.clear(owner)
        assertArrayEquals(ByteArray(32), retained)
        denied { handle.onRead(8, 8, ByteArray(8)) }
    }

    @Test fun authorityCallbackCancellationCannotRegisterAnOrphanHandle() {
        val owner = UUID.randomUUID().also { owners.add(it) }
        var cancel = false
        val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) {
            if (cancel) AndroidOwnerCustodyArchiveImportProvider.clear(owner)
            true
        }
        val retained = ownedBytes(uri)
        cancel = true
        denied { provider.registerHandle(uri) }
        assertArrayEquals(ByteArray(32), retained)
        denied { provider.query(uri, null, null, null, null) }
    }

    @Test fun authorityCallbackCancellationDuringStageReturnsNoUriAndWipes() {
        val owner = UUID.randomUUID().also { owners.add(it) }
        var retained: ByteArray? = null
        try {
            AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) {
                val field = AndroidOwnerCustodyArchiveImportProvider::class.java.getDeclaredField("grants").apply { isAccessible = true }
                val grant = (field.get(null) as Map<*, *>).values.single()!!
                retained = grant.javaClass.getDeclaredField("bytes").apply { isAccessible = true }.get(grant) as ByteArray
                AndroidOwnerCustodyArchiveImportProvider.clear(owner)
                true
            }
            fail("Stage published a grant after cancellation")
        } catch (_: IllegalStateException) { }
        assertNotNull(retained)
        assertArrayEquals(ByteArray(32), retained)
        for (name in listOf("entries", "grants")) {
            val field = AndroidOwnerCustodyArchiveImportProvider::class.java.getDeclaredField(name).apply { isAccessible = true }
            assertTrue((field.get(null) as Map<*, *>).isEmpty())
        }
    }

    @Test fun authorityWithdrawalBeforeOrBetweenPayloadReadsImmediatelyWipes() {
        for (alreadyRead in listOf(false, true)) {
            var live = true
            val (_, uri) = staged { live }
            val retained = ownedBytes(uri)
            val handle = provider.registerHandle(uri)
            assertEquals(32L, handle.onGetSize())
            if (alreadyRead) assertEquals(8, handle.onRead(0, 8, ByteArray(8)))
            live = false
            val output = ByteArray(24)
            denied { handle.onRead(if (alreadyRead) 8 else 0, 24, output) }
            assertArrayEquals(ByteArray(24), output)
            assertArrayEquals(ByteArray(32), retained)
        }
    }

    @Test fun invalidFirstOffsetWriteOrPayloadLengthRevokesWithoutDelivery() {
        for (operation in listOf<(AndroidOwnerCustodyArchiveImportDescriptor.Handle) -> Unit>(
            { it.onRead(1, 1, ByteArray(1)) }, { it.onRead(-1, 1, ByteArray(1)) },
            { it.onRead(0, 2, ByteArray(1)) }, { it.onWrite(0, 1, byteArrayOf(9)) })) {
            val (_, uri) = staged()
            val retained = ownedBytes(uri)
            val handle = provider.registerHandle(uri)
            denied { operation(handle) }
            assertArrayEquals(ByteArray(32), retained)
        }
    }

    @Test fun simultaneousFirstReadsChooseExactlyOnePayloadHandle() {
        val (_, uri) = staged()
        val handles = listOf(provider.registerHandle(uri), provider.registerHandle(uri))
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val futures = handles.map { handle -> executor.submit<Boolean> {
                check(start.await(2, TimeUnit.SECONDS))
                try {
                    val output = ByteArray(16)
                    assertEquals(16, handle.onRead(0, 16, output))
                    assertArrayEquals(ByteArray(16) { 7 }, output)
                    true
                } catch (_: ErrnoException) { false }
            } }
            start.countDown()
            val results = futures.map { it.get(2, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it })
            val winner = handles[results.indexOf(true)]
            val output = ByteArray(16)
            assertEquals(16, winner.onRead(16, 16, output))
            assertArrayEquals(ByteArray(16) { 7 }, output)
            winner.onRelease()
        } finally { executor.shutdownNow() }
    }

    @Test fun metadataAndPartialReadsNeverExtendOriginalDeadline() {
        val (_, uri) = staged()
        val retained = ownedBytes(uri)
        val metadata = provider.registerHandle(uri)
        metadata.onRelease()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(20_000))
        val consumer = provider.registerHandle(uri)
        assertEquals(8, consumer.onRead(0, 8, ByteArray(8)))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(10_001))
        assertArrayEquals(ByteArray(32), retained)
        denied { consumer.onRead(8, 8, ByteArray(8)) }
    }

    @Test fun activeGrantsRemainCappedAfterTheirPayloadUrisAreConsumed() {
        val selected = (1..4).map { staged() }
        val handles = selected.map { (_, uri) -> provider.registerHandle(uri).also {
            assertEquals(8, it.onRead(0, 8, ByteArray(8)))
        } }
        val rejected = UUID.randomUUID().also { owners.add(it) }
        try {
            AndroidOwnerCustodyArchiveImportProvider.stage(context, rejected, ByteArray(32) { 9 }, { true }) { true }
            fail("Active grant cap exceeded after URI removal")
        } catch (_: IllegalStateException) { }
        val owner = selected.first().first
        try {
            AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 9 }, { true }) { true }
            fail("Owner accumulated a second active grant")
        } catch (_: IllegalStateException) { }
        handles.forEach { assertEquals(32L, it.onGetSize()) }
    }

    /** Reflection reads only synthetic in-process bytes to verify actual wiping. */
    private fun ownedBytes(uri: android.net.Uri): ByteArray {
        val field = AndroidOwnerCustodyArchiveImportProvider::class.java.getDeclaredField("grants").apply { isAccessible = true }
        val grant = (field.get(null) as Map<*, *>)[uri.lastPathSegment]!!
        return grant.javaClass.getDeclaredField("bytes").apply { isAccessible = true }.get(grant) as ByteArray
    }
    private fun denied(action: () -> Unit) {
        try { action(); fail("Unavailable archive grant delivered authority") }
        catch (error: Exception) { assertTrue(error is ErrnoException || error is FileNotFoundException) }
    }
}
