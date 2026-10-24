// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Content-free negative crash journal, independent of Room and all protection keys. It never
 * initializes a key/counter or turns absent files into positive first-ever evidence. */
internal object InboundProtectionFaultJournal {
    private const val DIRECTORY = "inbound-protection-negative"
    private val files = InboundProtectionFiles(::syncDirectory)
    private fun root(context: Context) = File(context.noBackupFilesDir, DIRECTORY)
    fun begin(context: Context, action: String) = files.begin(root(context), action)
    fun quarantine(context: Context, action: String?) = files.quarantine(root(context), action)
    fun requireReadable(context: Context, withdrawal: Boolean) = files.requireReadable(root(context), withdrawal)
    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_DIRECTORY, 0)
        try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
    }
}

/** The filesystem operations are real in tests; only the platform directory-fsync adapter is
 * replaced. A fresh instance models process death and cannot adopt another instance's holds. */
internal class InboundProtectionFiles(private val syncDirectory: (File) -> Unit) {
    private val active = ConcurrentHashMap<String, Hold>()
    inner class Hold internal constructor(private val file: File) {
        fun completeKnownWithdrawal() {
            check(active[file.path] === this && file.isFile)
            check(file.delete()); syncDirectory(checkNotNull(file.parentFile))
            check(active.remove(file.path, this))
        }
    }
    private fun create(directory: File, name: String) {
        if (!directory.exists()) { check(directory.mkdir() || directory.isDirectory); syncDirectory(checkNotNull(directory.parentFile)) }
        check(directory.isDirectory)
        val file = File(directory, name)
        if (!file.exists()) {
            check(file.createNewFile() || file.isFile && file.length() == 0L)
            FileOutputStream(file).use { it.fd.sync() }
            syncDirectory(directory)
        }
        check(file.isFile && file.length() == 0L)
    }
    fun begin(dir: File, action: String): Hold {
        require(action in setOf(OptOutParser.OPT_OUT, OptOutParser.OPT_OUT_REVIEW))
        val name = "hold-${if (action == OptOutParser.OPT_OUT) 1 else 2}-${UUID.randomUUID()}"
        val file = File(dir, name)
        val value = Hold(file); check(active.putIfAbsent(file.path, value) == null)
        try { create(dir, name) } catch (failure: Exception) { active.remove(file.path, value); throw failure }
        return value
    }
    fun quarantine(dir: File, optAction: String?) {
        val debt = when (optAction) { OptOutParser.OPT_OUT -> "opt-out"; OptOutParser.OPT_OUT_REVIEW -> "opt-review"; OptOutParser.OPT_IN -> "opt-in"; else -> null }
        // A debt marker is itself a negative latch. Retain its action before the generic
        // marker so a later write failure cannot erase the classification already recorded.
        debt?.let { create(dir, it) }
        create(dir, "quarantined")
    }
    /** In-process known holds permit only their negative recipient-token resolution. A cold or
     * partial hold is irreversibly uncertain and cannot be adopted into a new effect lifetime. */
    fun requireReadable(dir: File, withdrawal: Boolean) {
        if (!dir.exists()) return
        check(dir.isDirectory)
        val files = checkNotNull(dir.listFiles())
        if (files.any { !it.isFile || it.length() != 0L || it.name == "quarantined" || !it.name.startsWith("hold-") || active[it.path] == null })
            throw InboundProtection.Unavailable("storage_unavailable")
        if (!withdrawal && files.isNotEmpty()) throw InboundProtectionEpochs.Withdrawn()
    }
}
