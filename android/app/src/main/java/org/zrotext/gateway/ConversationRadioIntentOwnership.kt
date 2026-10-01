// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/**
 * Process-local routing ownership, never radio authority. Register before the Room reservation,
 * and release after the synchronous consumer settles. No operation acquires Room or admission
 * while holding this monitor; journal maintenance may call owns after acquiring its transaction.
 * Permanent sealed_preparations identity independently prevents automatic intent resend on restart.
 */
internal object ConversationRadioIntentOwnership {
    private data class Entry(val session:ConversationPhoneSession,val event:String,val message:String,val attempt:String)
    private val entries=mutableMapOf<String,Entry>()
    @Synchronized fun register(session:ConversationPhoneSession,eventId:String,message:String,attempt:String):AutoCloseable {
        listOf(eventId,message,attempt).forEach { require(canonical(it)) }
        check(entries.size<1024 && eventId !in entries && entries.values.none {
            it.attempt==attempt || (it.session.account==session.account && it.message==message)
        }) { "Radio intent already owned or capacity exhausted" }
        val entry=Entry(session,eventId,message,attempt)
        entries[eventId]=entry
        return AutoCloseable {
            synchronized(this) { if(entries[eventId]===entry)entries.remove(eventId) }
        }
    }
    @Synchronized fun owns(event:AlphaRadioEvent):Boolean {
        if(event.evidence!="durable_submit_intent")return false
        val entry=entries[event.eventId]?:return false
        return event.messageId==entry.message && event.attemptId==entry.attempt &&
            event.accountId==entry.session.account.toString() && event.deviceId==entry.session.device.toString() &&
            event.originHash==entry.session.originHash
    }
    @Synchronized fun excluded(identity:EvidenceIdentity):List<String> = entries.values.filter {
        it.session.account.toString()==identity.accountId && it.session.device.toString()==identity.deviceId &&
            it.session.originHash==identity.originHash
    }.map{it.event}
    override fun toString()="ConversationRadioIntentOwnership(redacted)"
    private fun canonical(value:String)=runCatching {
        UUID.fromString(value).let { it!=UUID(0,0) && it.toString()==value }
    }.getOrDefault(false)
}
