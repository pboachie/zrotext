// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Metadata shared by the actual ACK/CAS/radio consumer; no metadata object grants an effect. */
internal sealed interface JournaledRadioScope {
    val message: String
    val attempt: String
    val accountId: String
    val deviceId: String
    val peer: String
    val originalDeadlineMs: Long
    val deadlineMs: Long
    val session: SealedDispatchExecutor.Session
    val binding: LocalLineBinding
    val segmentCeiling: Int
    fun requireGrantBinding(selected: LocalLineBinding)
}

/** Existing02 metadata semantics remain exact. A03 grant is never converted into02 fields. */
internal interface JournaledRadioContext : JournaledRadioScope {
    val grant: SealedExecutionGrantValidator.Fields
    val local: SealedDispatchExecutor.Local
    override val binding get() = local.binding
    override val segmentCeiling get() = grant.segmentCount
    override fun requireGrantBinding(selected: LocalLineBinding) {
        check(deadlineMs <= grant.expiresAtMs && grant.expiresAtMs <= originalDeadlineMs &&
            grant.attemptId.toString() == attempt && grant.messageId.toString() == message &&
            grant.accountId.toString() == accountId && grant.deviceId.toString() == deviceId &&
            grant.lineId.toString() == selected.lineId && grant.bindingGeneration == selected.generation && binding == selected)
    }
}

/** New03 identity plus the retained original v2 physical selection. The generation advance is
 * proved by the election; it never rewrites or forges a selected-SIM v2 installation.
 */
internal class Profile03RadioContext(
    val grant: SealedDispatch03Frames.Grant, override val session: SealedDispatchExecutor.Session,
    val current: Draft03OutboundPreparation.Current,
) : JournaledRadioScope {
    override val message = grant.messageId.toString()
    override val attempt = grant.attemptId.toString()
    override val accountId = grant.accountId.toString()
    override val deviceId = grant.deviceId.toString()
    override val peer = current.intent.peer().toString(Charsets.US_ASCII)
    override val originalDeadlineMs = current.intent.expiresMs
    override val deadlineMs = grant.expiresAtMs
    override val binding = current.baseBinding
    override val segmentCeiling = grant.segmentCount
    override fun requireGrantBinding(selected: LocalLineBinding) {
        current.intent.requireGrant(grant)
        val row = current.installation
        check(selected == binding && selected.protocolVersion == 2 && selected.v2Purpose == "sealed" &&
            row.state == "installed" && row.accountId == accountId && row.deviceId == deviceId &&
            row.lineId == selected.lineId && row.oldGeneration == selected.generation &&
            row.newGeneration == grant.bindingGeneration && row.originHash == session.originHash &&
            grant.accountId == session.accountId && grant.deviceId == session.deviceId &&
            grant.connectionEpoch == session.connectionEpoch && grant.deploymentEpoch == session.deploymentEpoch &&
            deadlineMs <= originalDeadlineMs && segmentCeiling == current.intent.segmentCeiling)
    }
    override fun toString() = "Profile03RadioContext(redacted)"
}
