// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Bounded public metadata with synced atomic replacement and thread/process locks. */
internal class PayloadKeyLifecycleFileStore(context: Context, alias: String) : PayloadKeyRecordStore {
    private val base = recordFile(context.applicationContext, alias)
    private val pending = File(base.path + ".new")
    private val lockFile = File(base.path + ".lock")

    override fun <T> locked(operation: (PayloadKeyRecordAccess) -> T): T = synchronized(mutex) {
        check(base.parentFile?.let { it.isDirectory || it.mkdirs() } == true) {
            "Payload lifecycle persistence unavailable"
        }
        RandomAccessFile(lockFile, "rw").use { lock ->
            lock.channel.lock().use {
                operation(object : PayloadKeyRecordAccess {
                    override fun read(): PayloadKeyRecord {
                        val bytes = try {
                            FileInputStream(base).use { stream ->
                                val buffer = ByteArray(39)
                                var count = 0
                                while (count < buffer.size) {
                                    val read = stream.read(buffer, count, buffer.size - count)
                                    if (read < 0) break
                                    count += read
                                }
                                check(count <= 38) { "Invalid payload lifecycle record" }
                                buffer.copyOf(count)
                            }
                        } catch (_: FileNotFoundException) {
                            check(!base.exists() && !pending.exists()) {
                                "Payload lifecycle persistence unavailable"
                            }
                            return PayloadKeyRecord.Absent
                        }
                        return decode(bytes)
                    }

                    override fun write(record: PayloadKeyRecord) {
                        val bytes = encode(record)
                        FileOutputStream(pending).use { stream ->
                            stream.write(bytes)
                            stream.fd.sync()
                        }
                        // Unsupported atomic replacement is an error, never a non-atomic fallback.
                        Files.move(pending.toPath(), base.toPath(),
                            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                        check(MessageDigest.isEqual(bytes, encode(read()))) {
                            "Payload lifecycle commit failed"
                        }
                    }
                })
            }
        }
    }

    companion object {
        private val mutex = Any()
        private val magic = byteArrayOf(0x5a, 0x54, 0x4b, 0x4c, 1)

        internal fun recordFile(context: Context, alias: String): File {
            require(alias.isNotEmpty() && alias.length <= 256 && alias.all { it.code in 33..126 }) {
                "Invalid payload alias"
            }
            val digest = MessageDigest.getInstance("SHA-256").digest(alias.toByteArray(Charsets.UTF_8))
            val name = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return File(File(context.noBackupFilesDir, "sealed-payload-lifecycle"), "$name.bin")
        }

        internal fun encode(record: PayloadKeyRecord): ByteArray = when (record) {
            PayloadKeyRecord.Absent -> error("Absent custody cannot be persisted")
            PayloadKeyRecord.Pending -> magic + byteArrayOf(1)
            is PayloadKeyRecord.Bound -> magic + byteArrayOf(2) + checkedId(record.keyId())
            is PayloadKeyRecord.Revoked -> magic + byteArrayOf(3) + checkedId(record.keyId())
        }

        internal fun decode(bytes: ByteArray): PayloadKeyRecord {
            require(bytes.size in setOf(6, 38) && bytes.copyOfRange(0, 5).contentEquals(magic)) {
                "Invalid payload lifecycle record"
            }
            return when (bytes[5].toInt()) {
                1 -> { require(bytes.size == 6); PayloadKeyRecord.Pending }
                2 -> { require(bytes.size == 38); PayloadKeyRecord.Bound(checkedId(bytes.copyOfRange(6, 38))) }
                3 -> { require(bytes.size == 38); PayloadKeyRecord.Revoked(checkedId(bytes.copyOfRange(6, 38))) }
                else -> error("Invalid payload lifecycle state")
            }
        }

        private fun checkedId(id: ByteArray): ByteArray {
            require(id.size == 32 && id.any { it != 0.toByte() }) { "Invalid payload key ID" }
            return id
        }
    }
}
