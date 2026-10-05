// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.pm.ProviderInfo
import android.content.pm.ResolveInfo
import android.content.Intent
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.os.Process
import android.os.Looper
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBinder
import org.robolectric.shadows.ShadowContentResolver
import org.robolectric.shadows.ShadowSystemClock
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.time.Duration
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], shadows = [AndroidOwnerCustodyArchiveMetadataStorageFixture::class])
class AndroidOwnerCustodyArchiveImportProviderTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private lateinit var provider: AndroidOwnerCustodyArchiveImportProvider

    @Before fun installPrivateFixtureProvider() {
        ShadowBinder.setCallingUid(Process.myUid())
        provider = AndroidOwnerCustodyArchiveImportProvider()
        val authority = context.packageName + ".owner-archive-import"
        provider.attachInfo(context, ProviderInfo().apply { this.authority = authority; exported = false; grantUriPermissions = false })
        ShadowContentResolver.registerProviderInternal(authority, provider)
        shadowOf(context.packageManager).addResolveInfoForIntent(Intent(DocumentsContract.PROVIDER_INTERFACE),
            ResolveInfo().apply { providerInfo = ProviderInfo().apply { this.authority = authority; exported = false; grantUriPermissions = false } })
    }

    @Test fun separateArchiveInputIsFrozenReadableOnlyOnceAndNeverWrittenToDisk() {
        val owner = UUID.randomUUID()
        val source = ByteArray(32) { 7 }
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, source, { true }) { true }
            source.fill(9)
            repeat(2) { provider.query(uri, null, null, null, null).use { assertTrue(it.moveToFirst()); assertEquals(32, it.getInt(1)) } }
            assertArrayEquals(ByteArray(32) { 7 }, payload(provider.registerHandle(uri)))
            try { provider.openFile(uri, "r"); fail("One-shot archive input read again") }
            catch (_: FileNotFoundException) { }
        } finally { source.fill(0); AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun boundedSourceReadAcceptsExactlyNonzero32Bytes() {
        assertArrayEquals(ByteArray(32) { 7 }, AndroidOwnerCustodyArchiveImportProvider.readExact(ByteArrayInputStream(ByteArray(32) { 7 })))
        for (input in listOf(ByteArray(0), ByteArray(31) { 7 }, ByteArray(33) { 7 }, ByteArray(32), "ZTRK1-".toByteArray() + ByteArray(73))) {
            try { AndroidOwnerCustodyArchiveImportProvider.readExact(ByteArrayInputStream(input)); fail("Invalid archive input accepted") }
            catch (_: IllegalArgumentException) { }
        }
        assertFalse(AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(ByteArray(32) { 7 })))
    }

    @Test fun documentMetadataHasKnownSizeWithoutConsumingPrivateInput() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            assertTrue(DocumentsContract.isDocumentUri(context, uri))
            assertTrue(DocumentsContract.isTreeUri(uri))
            assertEquals(DocumentsContract.getTreeDocumentId(uri), DocumentsContract.getDocumentId(uri))
            val columns = arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, OpenableColumns.DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE, OpenableColumns.SIZE, DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            repeat(2) { provider.query(uri, columns, null, null, null).use {
                assertTrue(it.moveToFirst()); assertEquals(32, it.getInt(3)); assertEquals(uri.lastPathSegment, it.getString(0))
            } }
            assertEquals(AndroidOwnerCustodyArchiveImportProvider.MIME, provider.getType(uri))
            provider.openAssetFile(uri, "r").use { afd ->
                assertEquals(32L, afd.declaredLength)
                assertEquals(32L, afd.parcelFileDescriptor.statSize)
            }
            shadowOf(Looper.getMainLooper()).idle()
            assertArrayEquals(ByteArray(32) { 7 }, payload(provider.registerHandle(uri)))
            try { provider.openAssetFile(uri, "r"); fail("Private payload reopened") } catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun treeShapedWrapperGrantsOnlyTheSameSingleDocumentAndNeverChildren() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            val authority = checkNotNull(uri.authority)
            val id = checkNotNull(uri.lastPathSegment)
            val tree = DocumentsContract.buildTreeDocumentUri(authority, id)
            val foreign = listOf(tree, DocumentsContract.buildDocumentUri(authority, id),
                DocumentsContract.buildDocumentUriUsingTree(tree, UUID.randomUUID().toString()),
                DocumentsContract.buildChildDocumentsUriUsingTree(tree, id),
                uri.buildUpon().appendPath("children").build())
            for (target in foreign) {
                try { provider.query(target, null, null, null, null); fail("Broader document capability accepted") }
                catch (_: FileNotFoundException) { }
                try { provider.openFile(target, "r"); fail("Broader document payload accepted") }
                catch (_: FileNotFoundException) { }
            }
            assertArrayEquals(ByteArray(32) { 7 }, payload(provider.registerHandle(uri)))
            try { provider.openFile(uri, "r"); fail("Consumed document reopened") } catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun missingDocumentIntentRegistrationNeverGrantsPrivateUri() {
        val owner = UUID.randomUUID()
        shadowOf(context.packageManager).setResolveInfosForIntent(Intent(DocumentsContract.PROVIDER_INTERFACE), emptyList())
        try {
            AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            fail("Missing document metadata registration granted private URI")
        } catch (_: IllegalStateException) { }
        finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun foreignUidWritesExpiredAndRevokedArchiveInputsFailClosed() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            for (foreign in listOf(uri.buildUpon().authority("other.synthetic.provider").build(),
                uri.buildUpon().appendPath("extra").build(), uri.buildUpon().query("extra=1").build())) {
                try { provider.openFile(foreign, "r"); fail("Foreign URI opened") } catch (_: FileNotFoundException) { }
            }
            try { provider.openFile(uri, "w"); fail("Writable archive input opened") } catch (_: FileNotFoundException) { }
            ShadowBinder.setCallingUid(Process.myUid() + 1)
            try { provider.openFile(uri, "r"); fail("Foreign UID opened archive input") } catch (_: FileNotFoundException) { }
            ShadowBinder.setCallingUid(Process.myUid())
            ShadowSystemClock.advanceBy(Duration.ofMillis(30_001))
            try { provider.openFile(uri, "r"); fail("Expired archive input opened") } catch (_: FileNotFoundException) { }
            val revoked = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            AndroidOwnerCustodyArchiveImportProvider.clear(owner)
            try { provider.openFile(revoked, "r"); fail("Revoked archive input opened") } catch (_: FileNotFoundException) { }
        } finally { ShadowBinder.setCallingUid(Process.myUid()); AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun ownerCannotAccumulateMultipleOutstandingPrivateInputs() {
        val owner = UUID.randomUUID()
        try {
            AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            try { AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 9 }, { true }) { true }; fail("Duplicate pending archive input staged") }
            catch (_: IllegalStateException) { }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun privateArchiveChooserRequiresExactSingleMimeAndOpenMode() {
        val purpose = AndroidOwnerCustodyOwnerBrowser.Companion::importPurpose
        val mime = AndroidOwnerCustodyArchiveImportProvider.MIME
        assertEquals(2, purpose(0, false, arrayOf(mime)))
        assertEquals(0, purpose(0, false, arrayOf(mime, "application/octet-stream")))
        assertEquals(0, purpose(1, false, arrayOf(mime)))
        assertEquals(0, purpose(0, true, arrayOf(mime)))
        assertEquals(1, purpose(0, false, arrayOf("application/octet-stream")))
    }

    @Test fun scheduledDeadlineWipesUnreadSyntheticFixtureWithoutAnotherProviderCall() {
        val owner = UUID.randomUUID()
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { true }
            val retained = syntheticOwnedBytes(uri.lastPathSegment!!)
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(30_001))
            assertArrayEquals(ByteArray(32), retained)
            try { provider.openFile(uri, "r"); fail("Scheduled expiry did not remove input") } catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    @Test fun ownerSessionWithdrawalWipesUnopenedSyntheticFixture() {
        val owner = UUID.randomUUID()
        var live = true
        try {
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 7 }, { true }) { live }
            val retained = syntheticOwnedBytes(uri.lastPathSegment!!)
            live = false
            try { provider.query(uri, null, null, null, null); fail("Withdrawn session queried input") } catch (_: FileNotFoundException) { }
            assertArrayEquals(ByteArray(32), retained)
            try { provider.openFile(uri, "r"); fail("Withdrawn session read input") } catch (_: FileNotFoundException) { }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    /** Only synthetic in-process test entries are inspected to prove actual zeroization. */
    private fun syntheticOwnedBytes(id: String): ByteArray {
        val field = AndroidOwnerCustodyArchiveImportProvider::class.java.getDeclaredField("entries").apply { isAccessible = true }
        val entry = (field.get(null) as Map<*, *>)[id]!!
        return entry.javaClass.getDeclaredField("bytes").apply { isAccessible = true }.get(entry) as ByteArray
    }

    @Test fun exactFrozenInputRequiresSuccessfulProofAndProofCopyIsWiped() {
        val owner = UUID.randomUUID()
        var proofCopy: ByteArray? = null
        try {
            val chosen = ByteArray(32) { 7 }
            val uri = AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, chosen, { proof ->
                proofCopy = proof
                val matches = proof.contentEquals(ByteArray(32) { 7 })
                proof.fill(0) // JNI clears the checked copy before returning.
                chosen.fill(9) // The already frozen bytes must remain exactly those checked.
                matches
            }) { true }
            assertArrayEquals(ByteArray(32), proofCopy)
            assertArrayEquals(ByteArray(32) { 7 }, payload(provider.registerHandle(uri)))
            for (badProof in listOf<(ByteArray) -> Boolean>({ false }, { throw IllegalStateException("Synthetic proof failed") })) {
                try { AndroidOwnerCustodyArchiveImportProvider.stage(context, owner, ByteArray(32) { 9 }, { proof -> proofCopy = proof; badProof(proof) }) { true }; fail("Unverified private input staged") }
                catch (_: IllegalArgumentException) { }
                assertArrayEquals(ByteArray(32), proofCopy)
            }
        } finally { AndroidOwnerCustodyArchiveImportProvider.clear(owner) }
    }

    /** JVM callback proof; the metadata shadow never reads or persists recovery.
     * Actual proxy stat/pread and hardened FileReader run in device acceptance.
     */
    private fun payload(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle): ByteArray {
        try {
            assertEquals(32L, handle.onGetSize())
            val bytes = ByteArray(32)
            assertEquals(32, handle.onRead(0, 32, bytes))
            assertEquals(0, handle.onRead(32, 1, ByteArray(1)))
            return bytes
        } finally { handle.onRelease() }
    }
}
