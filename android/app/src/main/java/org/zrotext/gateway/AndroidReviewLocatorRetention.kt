// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Actual private export/ack choreography. No automatic mutation replay after
 * interruption: an existing immutable request always selects STATUS only.
 */
internal class AndroidReviewLocatorRetention(
    private val context:AndroidReviewWorkspaceOwnerContext,
    private val journal:AndroidReviewLocatorAckJournal
) {
    fun prepare(origin:String)=context.captureLocator(origin)
    fun afterReadback(record:AndroidReviewLocatorRecord,readback:ByteArray,permitted:()->Boolean={true}):Boolean {
        check(permitted())
        record.requireReadback(readback)
        val current=context.refresh(record.origin);record.requireCurrent(current)
        check(permitted())
        val prior=journal.existing(record,current)
        val pending=prior?:journal.begin(record,current) // synced BEFORE first ACK POST
        return context.locatorRequest(record,if(prior==null)AndroidReviewLocatorAction.CONFIRM else AndroidReviewLocatorAction.STATUS,pending.request,permitted)
    }
    fun reconcile(origin:String,privateFile:ByteArray,permitted:()->Boolean={true}):Boolean {
        check(permitted())
        val current=context.refresh(origin)
        AndroidReviewLocatorRecord.fromPrivateFile(privateFile,current).use{record->
            val pending=checkNotNull(journal.existing(record,current)){"Original acknowledgement metadata unavailable"}
            return context.locatorRequest(record,AndroidReviewLocatorAction.STATUS,pending.request,permitted)
        }
    }
}
