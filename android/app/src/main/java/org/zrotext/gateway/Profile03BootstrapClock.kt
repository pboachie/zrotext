// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Current authenticated metadata clock only. Never an owner, reader or messaging capability. */
internal object Profile03BootstrapClock {
    private class Entry(val owner: Any, val account: UUID, val device: UUID, val originHash: String, val origins: Profile03Origins,
        val connectionEpoch: Long, val deploymentEpoch: Long, val sessionId: UUID, val now: () -> Long?)
    class Observation internal constructor(val origins: Profile03Origins, val connectionEpoch: Long,
        val deploymentEpoch: Long, val sessionId: UUID, private val currentNow: () -> Long) {
        fun now() = currentNow()
    }
    @Volatile private var installed: Entry? = null
    @Synchronized fun publish(owner: Any, session: SealedDispatchExecutor.Session, origins: Profile03Origins, now: () -> Long?) {
        origins.requireSession(session)
        val prior = installed
        check(prior == null || prior.owner === owner)
        if (prior != null) {
            check(prior.account == session.accountId && prior.device == session.deviceId && prior.originHash == session.originHash &&
                prior.origins.protocolOrigin == origins.protocolOrigin && prior.connectionEpoch == session.connectionEpoch &&
                prior.deploymentEpoch == session.deploymentEpoch && prior.sessionId == session.sessionId)
            return
        }
        check(now() != null)
        installed = Entry(owner, session.accountId, session.deviceId, session.originHash, origins,
            session.connectionEpoch, session.deploymentEpoch, session.sessionId, now)
    }
    fun capture(account: UUID, device: UUID, originHash: String): () -> Long {
        val observed = observation(account, device, originHash)
        return observed::now
    }
    /** Mapping and time are captured from ONE publication, with the same immutable actor,
     * connection/deployment epochs and owner withdrawal check after every actual clock read. */
    fun observation(account: UUID, device: UUID, originHash: String): Observation {
        val expected = checkNotNull(installed)
        check(expected.account == account && expected.device == device && expected.originHash == originHash)
        fun currentNow(): Long {
            check(installed === expected)
            return checkNotNull(expected.now()).also { check(it > 0 && installed === expected) }
        }
        currentNow()
        return Observation(expected.origins, expected.connectionEpoch, expected.deploymentEpoch, expected.sessionId, ::currentNow)
    }
    @Synchronized fun withdraw(owner: Any) { if (installed?.owner === owner) installed = null }
}
