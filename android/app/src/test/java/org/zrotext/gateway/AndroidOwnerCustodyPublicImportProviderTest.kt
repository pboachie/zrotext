// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.pm.ProviderInfo
import android.net.Uri
import android.os.Process
import android.provider.OpenableColumns
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBinder
import org.robolectric.shadows.ShadowContentResolver
import org.robolectric.shadows.ShadowSystemClock
import java.io.FileNotFoundException
import java.time.Duration
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AndroidOwnerCustodyProxyStorageFixture::class])
class AndroidOwnerCustodyPublicImportProviderTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private lateinit var provider: AndroidOwnerCustodyPublicImportProvider

    @Before fun installPrivateFixtureProvider() {
        ShadowBinder.setCallingUid(Process.myUid())
        provider = AndroidOwnerCustodyPublicImportProvider()
        val authority = context.packageName + ".owner-public-import"
        provider.attachInfo(context, ProviderInfo().apply { this.authority = authority; exported = false; grantUriPermissions = false })
        ShadowContentResolver.registerProviderInternal(authority, provider)
    }

    @Test fun publicImportIsFrozenAndNeverReopensTheMutableSource() {
        val owner = UUID.randomUUID()
        val source = ByteArray(64) { 7 }
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, source)
            source.fill(9)
            repeat(2) {
                val frozen = readProxyFixture(uri, 64)
                assertArrayEquals(ByteArray(64) { 7 }, frozen)
            }
            assertEquals(context.packageName + ".owner-public-import", uri.authority)
            assertEquals("content", uri.scheme)
            AndroidOwnerCustodyPublicImportProvider.clear(owner)
            try { provider.openFile(uri, "r"); fail("Cleared staged URI reopened") }
            catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    @Test fun sizeOnlyAndReorderedMetadataProjectionsRetainExactRequestedColumns() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 })
            provider.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null).use {
                assertArrayEquals(arrayOf(OpenableColumns.SIZE), it.columnNames)
                assertTrue(it.moveToFirst()); assertEquals(64L, it.getLong(0))
            }
            provider.query(uri, arrayOf(OpenableColumns.SIZE, OpenableColumns.DISPLAY_NAME), null, null, null).use {
                assertArrayEquals(arrayOf(OpenableColumns.SIZE, OpenableColumns.DISPLAY_NAME), it.columnNames)
                assertTrue(it.moveToFirst()); assertEquals(64L, it.getLong(0))
                assertEquals("public-owner-import.bin", it.getString(1))
            }
            provider.query(uri, null, null, null, null).use {
                assertArrayEquals(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), it.columnNames)
                assertTrue(it.moveToFirst()); assertEquals(64L, it.getLong(1))
            }
            assertArrayEquals(ByteArray(64) { 7 }, readProxyFixture(uri, 64))
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    @Test fun unsupportedAndUnboundedMetadataProjectionsNeverExposeOrConsumePublicInput() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 })
            for (projection in listOf(arrayOf("synthetic-unknown-column"),
                arrayOf(OpenableColumns.SIZE, OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE))) {
                try { provider.query(uri, projection, null, null, null); fail("Unsupported metadata projection accepted") }
                catch (_: IllegalArgumentException) { }
            }
            provider.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null).use {
                assertTrue(it.moveToFirst()); assertEquals(64L, it.getLong(0))
            }
            assertArrayEquals(ByteArray(64) { 7 }, readProxyFixture(uri, 64))
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    @Test fun foreignUidWritesAndExpiredPublicStagingFailClosed() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 })
            for (foreign in listOf(uri.buildUpon().authority("other.synthetic.provider").build(),
                uri.buildUpon().appendPath("extra").build(), uri.buildUpon().query("extra=1").build())) {
                try { provider.openFile(foreign, "r"); fail("Foreign staged URI opened") }
                catch (_: FileNotFoundException) { }
            }
            try { provider.openFile(uri, "w"); fail("Writable staging opened") }
            catch (_: FileNotFoundException) { }
            ShadowBinder.setCallingUid(Process.myUid() + 1)
            try { provider.openFile(uri, "r"); fail("Foreign UID read staging") }
            catch (_: FileNotFoundException) { }
            ShadowBinder.setCallingUid(Process.myUid())
            ShadowSystemClock.advanceBy(Duration.ofMillis(120_001))
            try { provider.openFile(uri, "r"); fail("Expired staging opened") }
            catch (_: FileNotFoundException) { }
        } finally {
            ShadowBinder.setCallingUid(Process.myUid())
            AndroidOwnerCustodyPublicImportProvider.clear(owner)
        }
    }

    @Test fun stageRejectsSecretLikeInputsAndExcessiveOutstandingPublicCopies() {
        val owner = UUID.randomUUID()
        try {
            for (secret in listOf(ByteArray(32) { 7 }, "1".repeat(64).toByteArray(), "ZTRK1-".toByteArray() + ByteArray(73))) {
                try { AndroidOwnerCustodyPublicImportProvider.stage(context, owner, secret); fail("Secret-like input staged") }
                catch (_: IllegalArgumentException) { }
            }
            repeat(16) { AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 }) }
            try { AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 }); fail("Unbounded staging accepted") }
            catch (_: IllegalStateException) { }
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    @Test fun largestPublicProposalRemainsExactlyFrozenAcrossRepeatedOpens() {
        val owner = UUID.randomUUID()
        val public = ByteArray(20_480).apply { "ZTCF".toByteArray().copyInto(this); this[4] = 1 }
        val expected = public.copyOf()
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, public)
            public.fill(0)
            repeat(2) { assertArrayEquals(expected, readProxyFixture(uri, expected.size)) }
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    @Test fun publicAssetDescriptorReportsExactLengthWithoutRelyingOnPipeStat() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyPublicImportProvider.stage(context, owner, ByteArray(64) { 7 })
            provider.openAssetFile(uri, "r").use { assertEquals(64L, it.declaredLength); assertEquals(0L, it.startOffset) }
            assertArrayEquals(ByteArray(64) { 7 }, readProxyFixture(uri, 64))
            try { provider.openAssetFile(uri, "w"); fail("Writable asset descriptor opened") } catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyPublicImportProvider.clear(owner) }
    }

    /** The synthetic proxy fixture must preserve finite AFD metadata and full bytes. */
    private fun readProxyFixture(uri: Uri, expectedSize: Int): ByteArray = context.contentResolver.openAssetFileDescriptor(uri, "r")!!.use { asset ->
        assertEquals(expectedSize.toLong(), asset.declaredLength)
        assertEquals(expectedSize.toLong(), asset.parcelFileDescriptor.statSize)
        asset.createInputStream().use { it.readBytes() }
    }
}
