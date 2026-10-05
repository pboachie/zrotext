// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.ContextWrapper
import android.view.View
import android.view.inputmethod.EditorInfo
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidOwnerCustodyStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun context(directory: File) = object : ContextWrapper(RuntimeEnvironment.getApplication()) {
        override fun getNoBackupFilesDir() = directory
    }
    @Test fun immutableEncryptedOwnerStoreUsesOnlyIndependentNoBackupDirectory() {
        val root = temporary.newFolder("unbacked")
        val store = AndroidOwnerCustodyStore.create(context(root)); val kit = AndroidOwnerCustodyFixture.kit
        store.put(kit) { true }; store.put(kit) { true }
        val record = checkNotNull(File(root, "android-owner-custody-v1").listFiles()).single { !it.name.endsWith(".lock") }
        assertTrue(AndroidOwnerCustodyKit.decode(record.readBytes()).matches(kit))
        assertFalse(String(record.readBytes(), Charsets.US_ASCII).contains("ZTRK1-"))
        assertTrue(record.canonicalPath.startsWith(root.canonicalPath + File.separator))
    }
    @Test fun interruptedAtomicRecordRequiresIndependentRecoveryInsteadOfSilentReplacement() {
        val root = temporary.newFolder("unbacked"); val store = AndroidOwnerCustodyStore.create(context(root)); val kit = AndroidOwnerCustodyFixture.kit
        store.put(kit) { true }
        val record = checkNotNull(File(root, "android-owner-custody-v1").listFiles()).single { !it.name.endsWith(".lock") }
        File(record.path + ".new").writeBytes(byteArrayOf(1))
        assertThrows(java.io.IOException::class.java) { store.put(kit) { true } }
    }
    @Test fun cancelledBeforeStorageCreatesNoRecord() {
        val root = temporary.newFolder("unbacked"); val store = AndroidOwnerCustodyStore.create(context(root))
        assertThrows(IllegalStateException::class.java) { store.put(AndroidOwnerCustodyFixture.kit) { false } }
        assertFalse(File(root, "android-owner-custody-v1").exists())
    }
    @Test fun recoveryInputDisablesSavedStateAutofillPersonalizedLearningAndCopy() {
        val input = AndroidOwnerCustodyRecoveryInput(RuntimeEnvironment.getApplication())
        assertFalse(input.isSaveEnabled); assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, input.importantForAutofill)
        assertTrue(input.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
        assertTrue(input.imeOptions and EditorInfo.IME_FLAG_NO_EXTRACT_UI != 0)
        assertFalse(input.onTextContextMenuItem(android.R.id.copy)); assertFalse(input.onTextContextMenuItem(android.R.id.cut))
    }
}
