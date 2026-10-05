// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.ConcurrentHashMap

internal interface AndroidOwnerCustodyKitStore {
    fun put(kit: AndroidOwnerCustodyKit, permitted: () -> Boolean)
    fun putArchive(kit: AndroidOwnerCustodyArchiveKit, permitted: () -> Boolean) { error("Separate encrypted archive storage unavailable") }
}

/** Separate, immutable encrypted owner kits; never public-trust or device/content-key storage.
 * noBackupFilesDir excludes this store from Android automatic backup. Independent SAF copies
 * remain mandatory. An interrupted or ambiguous commit cannot establish recovery readiness.
 */
internal class AndroidOwnerCustodyStore private constructor(private val directory: File) : AndroidOwnerCustodyKitStore {
    override fun putArchive(kit: AndroidOwnerCustodyArchiveKit, permitted: () -> Boolean) {
        val archiveDirectory = File(directory, "encrypted-archives")
        val base = File(archiveDirectory, kit.identity.keyId)
        val bytes = kit.backup()
        synchronized(monitors.computeIfAbsent(base.canonicalPath) { Any() }) {
            check(permitted())
            if (!archiveDirectory.isDirectory && !archiveDirectory.mkdirs()) throw IOException("Encrypted archive storage unavailable")
            RandomAccessFile(File(archiveDirectory, "${kit.identity.keyId}.lock"), "rw").use { lock -> lock.channel.lock().use {
                if (File(base.path + ".bak").exists() || File(base.path + ".new").exists()) throw IOException("Encrypted archive storage needs independent recovery")
                val atomic = AtomicFile(base)
                if (base.exists()) {
                    require(atomic.openRead().use { readAndroidOwnerCustodyFile(it, 845) }.contentEquals(bytes))
                    check(permitted()); return
                }
                val output = atomic.startWrite()
                try {
                    output.write(bytes); output.flush(); output.fd.sync(); check(permitted()); atomic.finishWrite(output)
                    check(permitted())
                    if (File(base.path + ".bak").exists() || File(base.path + ".new").exists() || !base.isFile ||
                        !atomic.openRead().use { readAndroidOwnerCustodyFile(it, 845) }.contentEquals(bytes)) throw IOException("Encrypted archive storage commit not confirmed")
                } catch (failure: Throwable) { atomic.failWrite(output); throw failure }
            } }
        }
    }
    override fun put(kit: AndroidOwnerCustodyKit, permitted: () -> Boolean) {
        val encoded = kit.encode()
        val name = AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(
            kit.identity.accountBytes() + kit.identity.origin.toByteArray(Charsets.UTF_8)))
        val base = File(directory, name)
        val monitor = monitors.computeIfAbsent(base.canonicalPath) { Any() }
        synchronized(monitor) {
            check(permitted())
            if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Owner kit storage unavailable")
            RandomAccessFile(File(directory, "$name.lock"), "rw").use { lock ->
                lock.channel.lock().use {
                    if (File(base.path + ".bak").exists() || File(base.path + ".new").exists())
                        throw IOException("Owner kit storage needs independent recovery")
                    val atomic = AtomicFile(base)
                    if (base.exists()) {
                        check(base.isFile)
                        val prior = atomic.openRead().use { readAndroidOwnerCustodyFile(it, AndroidOwnerCustodyKit.MAX_RECORD) }
                        require(AndroidOwnerCustodyKit.decode(prior).matches(kit)) { "Existing owner kit differs" }
                        check(permitted())
                        return
                    }
                    val stream = atomic.startWrite()
                    try {
                        stream.write(encoded); stream.flush(); stream.fd.sync()
                        check(permitted())
                        atomic.finishWrite(stream)
                        check(permitted())
                        if (File(base.path + ".new").exists() || File(base.path + ".bak").exists() || !base.isFile ||
                            !atomic.openRead().use { readAndroidOwnerCustodyFile(it, AndroidOwnerCustodyKit.MAX_RECORD) }.contentEquals(encoded))
                            throw IOException("Owner kit storage commit not confirmed")
                    } catch (failure: Throwable) { atomic.failWrite(stream); throw failure }
                }
            }
        }
    }
    companion object {
        private val monitors = ConcurrentHashMap<String, Any>()
        fun create(context: Context) = AndroidOwnerCustodyStore(File(context.noBackupFilesDir, "android-owner-custody-v1").canonicalFile)
    }
}
