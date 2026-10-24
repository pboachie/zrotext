// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** A proof-only live context, captured from ONE genuine pending observation/status and a
 * NEW one-way foreground decision. It cannot yield any submit/platform-entry capability. */
internal class TypedNoSubmit03Context private constructor(private val host: TypedHistory03Connections.Host,
    private val decision: ConversationInterval03Foreground.Decision, private val original: TypedSubmit03Record,
    private val proof: TypedNoSubmit03Proof, private val sample: TypedHistory03Clock.Sample,
    private val clock: TypedHistory03Request, private val statusObservation: TypedHistory03Connections.Host.ClosureReply,
    val statusRequestId: String, private val actionCurrent: () -> Unit) {
    val epoch get() = host.epoch
    val clockRequestId get() = clock.requestId
    internal fun requireClock(retained: TypedHistory03Request?) { require(retained == clock) }
    fun requireCurrent(row: TypedSubmit03Record, actual: TypedNoSubmit03Proof) {
        actionCurrent(); check(decision.isCurrent()); host.requireOriginal(original); statusObservation.requireLiveStatus()
        require(!row.conflict && row.lastCallbackOrdinal == 0L && row.phase == "closed_no_submit")
        require(row == original && actual.copy(signatureState = proof.signatureState, signatureB64url = proof.signatureB64url,
            signatureClockId = proof.signatureClockId, signatureStatusId = proof.signatureStatusId) == proof)
        sample.proofNow(row, clock, actual)
        check(decision.isCurrent()); host.requireOriginal(row)
    }
    companion object {
        fun from(host: TypedHistory03Connections.Host, decision: ConversationInterval03Foreground.Decision,
            row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, status: TypedNoSubmit03Io,
            observation: TypedHistory03Connections.Host.ClosureReply, sample: TypedHistory03Clock.Sample,
            clock: TypedHistory03Request, actionCurrent: () -> Unit): TypedNoSubmit03Context {
            require(status.kind == "status" && status.proofRequestId == proof.requestId && status.connectionEpoch == host.epoch &&
                clock.subjectKind == "proof" && clock.subjectId == proof.requestId && clock.connectionEpoch == host.epoch)
            observation.requireLiveStatus()
            require(observation.io == status.copy(replyB64url = null) && status.replyB64url == TypedSubmit03Record.base(observation.bytes()))
            val checked = TypedNoSubmit03Wire.decodeStatus(TypedSubmit03Record.unbase(checkNotNull(status.replyB64url)), row, proof,
                status.requestId, host.epoch)
            require(checked.status == "challenged" && checked.challenge?.core?.bytes()?.contentEquals(proof.challenge().core.bytes()) == true)
            return TypedNoSubmit03Context(host, decision, row, proof, sample, clock, observation, status.requestId, actionCurrent).also { it.requireCurrent(row, proof) }
        }
    }
}
