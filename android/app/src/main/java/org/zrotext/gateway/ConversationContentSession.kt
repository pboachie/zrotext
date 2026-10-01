// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Composition of existing installed authority, concrete crypto and authenticated runtime.
 * It neither creates credentials nor approves consent. The process mount remains disabled unless
 * the future feature owner explicitly installs this instance; cold start never installs it.
 * Dispatch is an existing independently fenced adapter, mandatory and without a radio default.
 */
internal class ConversationContentSession(
    private val runtime: ConversationAuthenticatedRuntime,
    private val crypto: ConversationContentCrypto,
    dispatch: ConversationSendTransport,
    private val mount: ConversationRuntimeMount = ConversationProcessMount.runtime
) : AutoCloseable {
    private val sender=runtime.confirmedSender(crypto,dispatch)
    private var mounted=false
    @Synchronized fun install(observedLine:(Int)->ConversationRuntimeMount.ObservedLine?,
                              loss:()->ConversationStopReason?, enabled:Boolean=false):Boolean {
        if(mounted || !enabled) return false
        mounted=mount.install(runtime,observedLine,loss,enabled=true,captured={token->
            runtime.uploadCapture(token,crypto::sealCapture) { accepted ->
                if(!accepted)runtime.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST)
            }
        })
        return mounted
    }
    fun receiveConfirmed(message:String,complete:(Boolean)->Unit) {
        val scope=runtime.currentScope()
        if(scope==null) {complete(false);return}
        runtime.receiveConfirmed(scope,message,sender,complete)
    }
    /** Only an already received, verified confirmation can cross the durable local claim fence. */
    fun submitConfirmed(message:String)=sender.submitConfirmed(message)
    @Synchronized override fun close() {
        if(mounted){mounted=false;mount.pauseOwned(runtime,ConversationStopReason.PHONE_SESSION_LOST)}
        else runtime.lifecycleLost(ConversationStopReason.PHONE_SESSION_LOST)
    }
}
