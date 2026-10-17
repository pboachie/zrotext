// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.util.UUID
import org.json.JSONObject

/** Immutable PRIVATE metadata only, synced before the ACK POST. It contains no
 * selector, credential, password or root token. Presence is not success.
 * Existing records always reconcile STATUS; they never authorize another POST.
 */
internal class AndroidReviewLocatorAckJournal(
    private val directory:File,
    private val syncParent:(File)->Unit={ dir->
        val fd=android.system.Os.open(dir.path,android.system.OsConstants.O_RDONLY,0)
        try{require(android.system.OsConstants.S_ISDIR(android.system.Os.fstat(fd).st_mode));android.system.Os.fsync(fd)}finally{android.system.Os.close(fd)}
    }
) {
    data class Pending(val request:UUID,val preparation:UUID,val selectorDigest:String,val subject:String)
    private fun subject(current:AndroidReviewWorkspaceAuthority):String {
        val value=JSONObject(current.nativeSnapshot().toString(Charsets.UTF_8))
        value.remove("context_epoch") // fresh local epoch does not renew server session authority
        value.remove("idle_deadline_ms") // fresh server currentness still checks the actual idle bound
        return AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(value.toString().toByteArray(Charsets.UTF_8)))
    }
    private fun file(record:AndroidReviewLocatorRecord)=File(directory,record.preparation.toString()+".json")
    fun existing(record:AndroidReviewLocatorRecord,current:AndroidReviewWorkspaceAuthority):Pending? {
        val path=file(record)
        if(!path.exists())return null
        require(path.isFile && path.canonicalFile==path.absoluteFile && path.length() in 1..2048)
        val f=AndroidReviewJson.objectValue(path.inputStream().use{readAndroidOwnerCustodyFile(it,2048)})
        require(f.keys==setOf("version","request_id","preparation_id","selector_digest","subject")&&f["version"]==1)
        val result=Pending(AndroidReviewJson.uuid(f["request_id"] as? String?:error("Pending ACK")),
            AndroidReviewJson.uuid(f["preparation_id"] as? String?:error("Pending preparation")),
            f["selector_digest"] as? String?:error("Pending digest"),f["subject"] as? String?:error("Pending subject"))
        require(result.preparation==record.preparation && result.selectorDigest==record.selectorDigest && result.subject==subject(current))
        return result
    }
    fun begin(record:AndroidReviewLocatorRecord,current:AndroidReviewWorkspaceAuthority):Pending {
        record.requireCurrent(current)
        check(existing(record,current)==null){"Reconcile original acknowledgement"}
        val parent=checkNotNull(directory.parentFile)
        require(parent.isDirectory && parent.canonicalFile==parent.absoluteFile)
        if(!directory.isDirectory && !directory.mkdir() && !directory.isDirectory)error("Private acknowledgement storage unavailable")
        require(directory.canonicalFile==directory.absoluteFile)
        val result=Pending(UUID.randomUUID(),record.preparation,record.selectorDigest,subject(current))
        val bytes=JSONObject().put("version",1).put("request_id",result.request.toString())
            .put("preparation_id",result.preparation.toString()).put("selector_digest",result.selectorDigest)
            .put("subject",result.subject).toString().toByteArray(Charsets.UTF_8)
        // CREATE_NEW is the no-clobber boundary across concurrent callers. Any
        // interrupted/partial file remains unqualified, never automatically replaced.
        FileChannel.open(file(record).toPath(),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE).use{channel->
            val buffer=ByteBuffer.wrap(bytes)
            while(buffer.hasRemaining())check(channel.write(buffer)>0)
            channel.force(true)
        }
        syncParent(directory)
        // The app-private child may be new. Persist its entry as well as the
        // child's file entry before any acknowledgement can leave the process.
        syncParent(parent)
        require(existing(record,current)==result)
        return result
    }
    companion object {
        fun create(context:android.content.Context)=AndroidReviewLocatorAckJournal(
            File(context.noBackupFilesDir,"review-locator-ack-v1").canonicalFile)
    }
}
