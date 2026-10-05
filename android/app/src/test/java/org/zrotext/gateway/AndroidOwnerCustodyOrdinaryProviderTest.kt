// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Process
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBinder
import java.util.UUID

/** Resolve actual ordinary merged-manifest providers, without fixture registration. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidOwnerCustodyOrdinaryProviderTest {
    @Test fun ordinaryManifestResolvesPrivateProvidersAndStagesBothConsentedInputs() {
        val app = RuntimeEnvironment.getApplication()
        ShadowBinder.setCallingUid(Process.myUid())
        for ((suffix, expected) in listOf(
            ".owner-public-import" to AndroidOwnerCustodyPublicImportProvider::class.java.name,
            ".owner-archive-import" to AndroidOwnerCustodyArchiveImportProvider::class.java.name,
        )) {
            val provider = app.packageManager.resolveContentProvider(app.packageName + suffix, 0)
            assertNotNull("Ordinary manifest must register $suffix", provider)
            assertEquals(expected, provider!!.name)
            assertFalse(provider.exported)
            assertFalse(provider.grantUriPermissions)
        }
        val owner = UUID.randomUUID()
        try {
            val public = AndroidOwnerCustodyPublicImportProvider.stage(app, owner, ByteArray(64) { 7 })
            val archive = AndroidOwnerCustodyArchiveImportProvider.stage(app, owner, ByteArray(32) { 7 },
                verify = { it.contentEquals(ByteArray(32) { 7 }) }, available = { true })
            assertTrue("Archive provider must retain the document contract", DocumentsContract.isDocumentUri(app, archive))
            for ((uri, expectedBytes) in listOf(public to 64L, archive to 32L)) {
                app.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null).use { cursor ->
                    assertNotNull("Ordinary provider must answer its staged metadata query", cursor)
                    assertTrue(cursor!!.moveToFirst())
                    assertEquals(expectedBytes, cursor.getLong(0))
                }
            }
        } finally {
            AndroidOwnerCustodyPublicImportProvider.clear(owner)
            AndroidOwnerCustodyArchiveImportProvider.clear(owner)
        }
    }
}
