// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The MMS spike (#438) must not reach a release build: the radio call, the
 * callback receiver and the file provider live only in the debug source set,
 * and the release source set replaces the entry points with refusing stubs.
 * CI builds only debug variants, so these structural checks run there.
 */
class MmsSpikeReleaseBoundaryTest {
    private val src = File("src")

    @Test fun mainAndReleaseSourcesNeverCallTheMmsRadio() {
        for (sourceSet in listOf("main", "release")) {
            val offenders = File(src, "$sourceSet/java").walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filter { it.readText().contains("sendMultimediaMessage") }
                .map { it.name }.toList()
            assertTrue("$sourceSet must not call sendMultimediaMessage: $offenders", offenders.isEmpty())
        }
        assertTrue(File(src, "debug/java/org/zrotext/gateway/MmsSpikeSend.kt").readText()
            .contains("sendMultimediaMessage"))
    }

    @Test fun onlyTheDebugManifestDeclaresTheSpikeReceiverAndProvider() {
        val main = File(src, "main/AndroidManifest.xml").readText()
        assertFalse(main.contains("MmsSpikeReceiver"))
        assertFalse(main.contains("mms-spike-files"))
        assertFalse(File(src, "main/res/xml/mms_spike_file_paths.xml").exists())
        val debug = File(src, "debug/AndroidManifest.xml").readText()
        assertTrue(debug.contains("MmsSpikeReceiver"))
        assertTrue(debug.contains("mms-spike-files"))
    }

    @Test fun releaseStubsRejectGrantsAndDrawNoSection() {
        val release = File(src, "release/java/org/zrotext/gateway/MmsSpikeRelease.kt").readText()
        assertTrue(release.contains("error(\"Unexpected device frame\")"))
        assertTrue(Regex("fun MmsSpikeSection\\([^)]*\\) = Unit").containsMatchIn(release))
    }
}
