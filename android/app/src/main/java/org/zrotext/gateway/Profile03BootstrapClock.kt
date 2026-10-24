// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Current authenticated metadata clock only. Never an owner, reader or messaging capability. */
internal object Profile03BootstrapClock {
    private class Entry(val owner: Any, val account: UUID, val device: UUID, val originHash: String,
        val now: () -> Long?)
    @Volatile private var installed: Entry? = null
    @Synchronized fun publish(owner: Any, session: SealedDispatchExecutor.Session, now: () -> Long?) {
        val prior = installed
        check(prior == null || prior.owner === owner)
        if (prior != null) {
            check(prior.account == session.accountId && prior.device == session.deviceId && prior.originHash == session.originHash)
            return
        }
        check(now() != null)
        installed = Entry(owner, session.accountId, session.deviceId, session.originHash, now)
    }
    fun capture(account: UUID, device: UUID, originHash: String): () -> Long {
        val expected = checkNotNull(installed)
        check(expected.account == account && expected.device == device && expected.originHash == originHash)
        return {
            check(installed === expected)
            checkNotNull(expected.now()).also { check(it > 0 && installed === expected) }
        }
    }
    @Synchronized fun withdraw(owner: Any) { if (installed?.owner === owner) installed = null }
}
