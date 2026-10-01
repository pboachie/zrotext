// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.io.File

/** Test-source-only deletion of owned synthetic metadata after a fixture ends. */
internal fun clearPayloadLifecycleFixture(context: Context, alias: String) {
    require(alias.startsWith("zrotext.test.") || alias.startsWith("zrotext.m2."))
    val file = PayloadKeyLifecycleFileStore.recordFile(context, alias)
    for (suffix in listOf("", ".new", ".bak", ".lock")) File(file.path + suffix).delete()
}
