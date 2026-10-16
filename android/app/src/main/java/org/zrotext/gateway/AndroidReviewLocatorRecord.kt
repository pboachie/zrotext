// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import org.json.JSONObject

/** PRIVATE selector, separate from public root files. It is not a bearer or root proof.
 * Only the server can authenticate its MAC and retained association. The local
 * parser checks framing/current metadata before the mandatory HTTPS preflight.
 * Java CookieManager/String copies cannot promise cryptographic zeroization.
 */
internal class AndroidReviewLocatorRecord private constructor(
    val origin:String,val preparation:UUID,val cookieName:String,
    private var value:String?,private var encoded:ByteArray?,
    val selectorDigest:String
):AutoCloseable {
    fun privateBytes(consented:Boolean):ByteArray {
        require(consented);return synchronized(this){checkNotNull(encoded).copyOf()}
    }
    fun requireReadback(readback:ByteArray) {
        synchronized(this){require(MessageDigest.isEqual(checkNotNull(encoded),readback))}
    }
    internal fun cookieHeader()=synchronized(this){cookieName+"="+checkNotNull(value)}
    internal fun requireHeldCookie(raw:String?) {
        val matches=raw.orEmpty().split(';').map{it.trim()}.filter{it.substringBefore('=')==cookieName}
        require(matches.size<=1 && (matches.isEmpty() || matches.single()==cookieHeader()))
    }
    internal fun requireCurrent(current:AndroidReviewWorkspaceAuthority) {
        require(current.origin==origin)
        val frame=synchronized(this){Base64.getUrlDecoder().decode(checkNotNull(value))}
        try{checkFrame(frame,current,cookieName)}finally{frame.fill(0)}
    }
    internal fun metadata(request:UUID)=JSONObject().put("version",1).put("request_id",request.toString())
        .put("preparation_id",preparation.toString()).put("selector_cookie_sha256_b64",selectorDigest)
    override fun toString()="AndroidReviewLocatorRecord([PRIVATE])"
    override fun close(){synchronized(this){encoded?.fill(0);encoded=null;value=null}}
    companion object {
        const val MAX_BYTES=2048
        private val name=Regex("__Host-ztrw-l-[0-9a-f]{32}")
        fun fromCookieHeader(raw:String,current:AndroidReviewWorkspaceAuthority):AndroidReviewLocatorRecord {
            require(raw.length in 1..8192 && raw.all{it.code in 32..126})
            val found=raw.split(';').map{it.trim().split('=',limit=2)}.filter{it[0].startsWith("__Host-ztrw-l-")}
            require(found.size==1 && found.single().size==2)
            val (cookie,value)=found.single()
            return capture(current.origin,cookie,value,current)
        }
        fun fromPrivateFile(raw:ByteArray,current:AndroidReviewWorkspaceAuthority):AndroidReviewLocatorRecord {
            require(raw.size in 1..MAX_BYTES)
            val f=AndroidReviewJson.objectValue(raw)
            require(f.keys==setOf("version","origin","cookie_name","cookie_value") && f["version"]==1)
            val origin=f["origin"] as? String?:error("Private selector origin")
            val cookie=f["cookie_name"] as? String?:error("Private selector cookie")
            val value=f["cookie_value"] as? String?:error("Private selector value")
            val record=capture(origin,cookie,value,current)
            try{record.requireReadback(raw);return record}catch(failure:Exception){record.close();throw failure}
        }
        private fun capture(origin:String,cookie:String,value:String,current:AndroidReviewWorkspaceAuthority):AndroidReviewLocatorRecord {
            require(origin==current.origin && name.matches(cookie) && value.length in 1..1024 && value.matches(Regex("[A-Za-z0-9_-]+")))
            val frame=Base64.getUrlDecoder().decode(value)
            val prep=try{
                require(Base64.getUrlEncoder().withoutPadding().encodeToString(frame)==value)
                checkFrame(frame,current,cookie)
            }finally{frame.fill(0)}
            val encoded=JSONObject().put("version",1).put("origin",origin).put("cookie_name",cookie).put("cookie_value",value)
                .toString().toByteArray(Charsets.UTF_8)
            require(encoded.size<=MAX_BYTES)
            val digest=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII)))
            return AndroidReviewLocatorRecord(origin,prep,cookie,value,encoded,digest)
        }
        private fun checkFrame(frame:ByteArray,current:AndroidReviewWorkspaceAuthority,cookie:String):UUID {
            require(frame.size in 268..522)
            val input=ByteBuffer.wrap(frame)
            fun uuid():UUID=UUID(input.long,input.long).also{require(it!=UUID(0,0))}
            fun bytes(n:Int)=ByteArray(n).also{input.get(it)}
            require(input.get()==1.toByte() && uuid()==current.realm)
            require(bytes(32).contentEquals(AndroidReviewJson.binary(current.database,32)))
            val originLength=input.short.toInt() and 65535
            require(originLength in 1..255 && frame.size==267+originLength)
            val originBytes=bytes(originLength)
            require(originBytes.all{it.toInt() in 32..126} && originBytes.toString(Charsets.US_ASCII)==current.origin)
            require(bytes(32).contentEquals(AndroidReviewJson.binary(current.config,32)) && input.long==current.configRevision)
            require(bytes(32).any{it!=0.toByte()}) // opaque current auth-key commitment; HTTPS verifies it
            require(uuid()==current.account && uuid()==current.user)
            val prep=uuid();uuid() // original request UUID, not current session authority
            require(cookie=="__Host-ztrw-l-"+prep.toString().replace("-",""))
            require(input.long>0)
            val created=input.long;require(created>0 && created<=current.serverMs)
            var nonzero=false
            repeat(32){if(input.get()!=0.toByte())nonzero=true};require(nonzero)
            input.position(input.position()+32) // MAC verified ONLY by actual server preflight
            require(!input.hasRemaining())
            return prep
        }
    }
}
