// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class EsimProfileContinuityTest {
    private val incarnation = UUID(1, 1).toString()
    private val authority = ProfileLineAuthority(UUID(2, 1).toString(), UUID(2, 2).toString(),
        UUID(2, 3).toString(), 1)
    private val one = ProfileSubscriptionObservation(10, 100, true, 0, 0)
    private val two = ProfileSubscriptionObservation(11, 100, true, 1, 0)
    private fun tracker(): EsimProfileContinuityTracker {
        var sequence = 0L
        return EsimProfileContinuityTracker(incarnation) { UUID(3, ++sequence).toString() }
    }
    private fun ready(tracker: EsimProfileContinuityTracker,
                      values: List<ProfileSubscriptionObservation> = listOf(one, two)) {
        tracker.registrationSucceeded()
        tracker.onSubscriptionsChanged()
        val epoch = checkNotNull(tracker.observationEpoch())
        assertTrue(tracker.acceptSnapshots(epoch, values, values, epoch))
    }
    private class Store : ProfileChallengePersistence {
        var ledger: ProfileChallengeLedger? = ProfileChallengeLedger()
        var writeResult = true
        var afterWrite: (() -> Unit)? = null
        override fun read() = ledger
        override fun write(ledger: ProfileChallengeLedger): Boolean {
            if (!writeResult) return false
            this.ledger = ledger
            afterWrite?.invoke()
            return true
        }
    }
    private fun key(generation: Long = 1, id: Long = 1) =
        ProfileChallengeKey(authority.copy(bindingGeneration = generation), UUID(4, id).toString())
    private fun install(tracker: EsimProfileContinuityTracker, candidate: EsimProfileCandidate,
                        fence: ProfileChallengeFence, key: ProfileChallengeKey = key()): InstalledEsimProfile {
        assertTrue(fence.reserveBeforeSigning(key, candidate))
        val permit = checkNotNull(fence.persistAcceptedAck(key, candidate))
        return checkNotNull(tracker.publishInstalled(permit))
    }

    @Test fun twoProfilesMayShareCardAndReportedSlotWhenPortsAreDistinct() {
        val tracker = tracker()
        ready(tracker)
        val selected = checkNotNull(tracker.candidate(10))
        assertEquals(0, selected.record.portIndex)
        assertNotNull(tracker.candidate(11))
        assertNotSame(selected, tracker.candidate(11))
        val epoch = checkNotNull(tracker.observationEpoch())
        assertTrue(tracker.acceptSnapshots(epoch, listOf(two, one), listOf(one, two), epoch))
        assertSame(selected, tracker.candidate(10))
    }
    @Test fun duplicateSubscriptionsOrCardPortsNeverMintCandidates() {
        for (values in listOf(listOf(one, one.copy(portIndex = 1)),
            listOf(one, two.copy(portIndex = 0)))) {
            val tracker = tracker()
            tracker.registrationSucceeded()
            tracker.onSubscriptionsChanged()
            val epoch = checkNotNull(tracker.observationEpoch())
            tracker.acceptSnapshots(epoch, values, values, epoch)
            assertNull(tracker.candidate(10))
            assertNull(tracker.candidate(11))
        }
    }
    @Test fun unknownNegativeOrNonembeddedProfileCannotMintCandidate() {
        for (value in listOf(one.copy(cardId = null), one.copy(cardId = -1),
            one.copy(portIndex = null), one.copy(portIndex = -1),
            one.copy(logicalSlotIndex = null), one.copy(logicalSlotIndex = -1),
            one.copy(embedded = false))) {
            val tracker = tracker()
            ready(tracker, listOf(value))
            assertNull(tracker.candidate(10))
        }
    }
    @Test fun callbackBarrierAndSuccessfulRegistrationAreBothRequired() {
        val tracker = tracker()
        assertNull(tracker.observationEpoch())
        tracker.onSubscriptionsChanged()
        assertNull(tracker.observationEpoch()) // callback before addListener returned
        tracker.registrationFailed()
        tracker.registrationSucceeded()
        assertNull(tracker.observationEpoch())
        assertNull(tracker.candidate(10))
    }
    @Test fun mismatchedSnapshotsOrEpochCannotExposeReadyCandidate() {
        val tracker = tracker()
        tracker.registrationSucceeded()
        tracker.onSubscriptionsChanged()
        val before = checkNotNull(tracker.observationEpoch())
        tracker.onSubscriptionsChanged()
        assertFalse(tracker.acceptSnapshots(before, listOf(one), listOf(one),
            checkNotNull(tracker.observationEpoch())))
        val now = checkNotNull(tracker.observationEpoch())
        assertFalse(tracker.acceptSnapshots(now, listOf(one), listOf(two), now))
        assertNull(tracker.candidate(10))
    }
    @Test fun everyCallbackRetiresCandidateEvenWhenSelectedTupleIsUnchanged() {
        val tracker = tracker()
        ready(tracker)
        val old = checkNotNull(tracker.candidate(10))
        tracker.onSubscriptionsChanged() // includes peer-only metadata notifications
        assertFalse(old.isCurrent())
        val epoch = checkNotNull(tracker.observationEpoch())
        assertTrue(tracker.acceptSnapshots(epoch, listOf(one, two), listOf(one, two), epoch))
        assertNotSame(old, tracker.candidate(10))
        assertFalse(old.isCurrent())
    }
    @Test fun mappingChangeWithoutCallbackAlsoRetiresOldCandidate() {
        val tracker = tracker()
        ready(tracker)
        val old = checkNotNull(tracker.candidate(10))
        val epoch = checkNotNull(tracker.observationEpoch())
        val changed = listOf(one.copy(portIndex = 2), two)
        assertFalse(tracker.acceptSnapshots(epoch, changed, changed, epoch))
        assertFalse(old.isCurrent())
    }
    @Test fun candidateAndSavedRecordCannotServeInstalledAuthority() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        assertNull(tracker.lookupInstalled(candidate.record, authority))
        val store = Store()
        val fence = ProfileChallengeFence(store)
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        assertNull(tracker.lookupInstalled(candidate.record, authority)) // signing is not installation
        val forged = ProfileInstallationPermit.afterDurableAck(candidate, authority, key().challengeId, fence)
        assertNull(tracker.publishInstalled(forged)) // issuer did not authorize this object
        val installed = checkNotNull(tracker.publishInstalled(checkNotNull(fence.persistAcceptedAck(key(), candidate))))
        assertSame(installed, tracker.lookupInstalled(candidate.record, authority))
    }
    @Test fun installedLookupChecksEveryAuthorityComponentAndExactProfileRecord() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val installed = install(tracker, candidate, ProfileChallengeFence(Store()))
        for (other in listOf(authority.copy(accountId = UUID(5, 1).toString()),
            authority.copy(deviceId = UUID(5, 2).toString()), authority.copy(lineId = UUID(5, 3).toString()),
            authority.copy(bindingGeneration = 2))) assertNull(tracker.lookupInstalled(candidate.record, other))
        assertNull(tracker.lookupInstalled(candidate.record.copy(portIndex = 2), authority))
        assertTrue(installed.isCurrent())
    }
    @Test fun equalSerializedNonceEpochAndLeaseAfterRestartDoNotRestoreAuthority() {
        val oldTracker = tracker()
        ready(oldTracker)
        val old = checkNotNull(oldTracker.candidate(10))
        val installed = install(oldTracker, old, ProfileChallengeFence(Store()))
        oldTracker.close()
        val replacement = tracker() // deliberately same nonce and deterministic lease IDs
        ready(replacement)
        val fresh = checkNotNull(replacement.candidate(10))
        assertEquals(old.record, fresh.record)
        assertFalse(old.isCurrent())
        assertFalse(installed.isCurrent())
        assertFalse(replacement.isCurrent(old))
        assertNull(replacement.lookupInstalled(old.record, authority))
    }
    @Test fun callbackBeforeOrAfterPublicationNeverLeavesLiveInstallation() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val fence = ProfileChallengeFence(Store())
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        val permit = checkNotNull(fence.persistAcceptedAck(key(), candidate))
        tracker.onSubscriptionsChanged()
        assertNull(tracker.publishInstalled(permit))

        val other = tracker()
        ready(other)
        val live = install(other, checkNotNull(other.candidate(10)), ProfileChallengeFence(Store()))
        other.onSubscriptionsChanged()
        assertFalse(live.isCurrent())
        assertNull(other.lookupInstalled(live.record, authority))
    }
    @Test fun exactRevocationCannotWithdrawNewerInstalledAuthority() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val fence = ProfileChallengeFence(Store())
        val old = install(tracker, candidate, fence)
        val newer = install(tracker, candidate, fence, key(2, 2))
        tracker.revoke(old)
        assertFalse(old.isCurrent())
        assertTrue(newer.isCurrent())
        tracker.revoke(newer)
        assertFalse(newer.isCurrent())
    }
    @Test fun persistedReservationNeverRecreatesRamLeaseAssociation() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        assertTrue(ProfileChallengeFence(store).reserveBeforeSigning(key(), candidate))
        assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key(), candidate))
        tracker.onSubscriptionsChanged()
        val epoch = checkNotNull(tracker.observationEpoch())
        assertTrue(tracker.acceptSnapshots(epoch, listOf(one, two), listOf(one, two), epoch))
        assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key(), checkNotNull(tracker.candidate(10))))
    }
    @Test fun failedWriteOrCallbackDuringReservationCannotAuthorizeSigning() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        store.writeResult = false
        val fence = ProfileChallengeFence(store)
        assertFalse(fence.reserveBeforeSigning(key(), candidate))
        store.writeResult = true
        store.afterWrite = { tracker.onSubscriptionsChanged() }
        assertFalse(fence.reserveBeforeSigning(key(), candidate))
        assertNull(fence.persistAcceptedAck(key(), candidate))
    }
    @Test fun malformedOrFullLedgerFailsClosed() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        store.ledger = null
        assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key(), candidate))
        store.ledger = ProfileChallengeLedger(installedGenerations = mapOf("malformed" to 1))
        assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key(), candidate))
        store.ledger = ProfileChallengeLedger((1L..ProfileChallengeFence.MAX_ENTRIES.toLong())
            .map { key(id = it) }.toSet())
        assertFalse(ProfileChallengeFence(store).reserveBeforeSigning(key(id = 100), candidate))
    }
    @Test fun acceptedAckDurabilityPrecedesPublicationAndFencesOldGenerations() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val fence = ProfileChallengeFence(store)
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        store.writeResult = false
        assertNull(fence.persistAcceptedAck(key(), candidate))
        assertNull(tracker.lookupInstalled(candidate.record, authority))
        store.writeResult = true
        val installed = checkNotNull(tracker.publishInstalled(checkNotNull(fence.persistAcceptedAck(key(), candidate))))
        assertTrue(installed.isCurrent())
        assertFalse(fence.reserveBeforeSigning(key(id = 2), candidate))
        assertTrue(fence.reserveBeforeSigning(key(2, 3), candidate))
    }
    @Test fun callbackDuringAcceptedGenerationWriteCannotPublishAuthority() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val fence = ProfileChallengeFence(store)
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        store.afterWrite = { tracker.onSubscriptionsChanged() }
        assertNull(fence.persistAcceptedAck(key(), candidate))
        assertNull(tracker.lookupInstalled(candidate.record, authority))
        assertEquals(1L, checkNotNull(store.ledger).installedGenerations[authority.lineKey()])
    }
    @Test fun delayedOlderPermitCannotPublishAfterHigherGenerationWasDurablyAccepted() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val fence = ProfileChallengeFence(Store())
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        val old = checkNotNull(fence.persistAcceptedAck(key(), candidate))
        assertTrue(fence.reserveBeforeSigning(key(2, 2), candidate))
        val newer = checkNotNull(fence.persistAcceptedAck(key(2, 2), candidate))
        assertNull(tracker.publishInstalled(old))
        assertNotNull(tracker.publishInstalled(newer))
    }
    @Test fun failedHigherAckWritePermanentlyRetiresEarlierInstalledAuthority() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val fence = ProfileChallengeFence(store)
        val old = install(tracker, candidate, fence)
        assertTrue(fence.reserveBeforeSigning(key(2, 2), candidate))
        store.writeResult = false
        assertNull(fence.persistAcceptedAck(key(2, 2), candidate))
        assertFalse(old.isCurrent())
        assertNull(tracker.publishInstalled(old.permit))
    }
    @Test fun twoFenceInstancesSerializeSharedPersistenceWithoutLostReservations() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val first = ProfileChallengeFence(store)
        val second = ProfileChallengeFence(store)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val completed = java.util.concurrent.CountDownLatch(1)
        store.afterWrite = {
            if (checkNotNull(store.ledger).reservations.size == 1) {
                entered.countDown()
                check(release.await(2, java.util.concurrent.TimeUnit.SECONDS))
            }
        }
        val a = java.util.concurrent.FutureTask { first.reserveBeforeSigning(key(), candidate) }
        val b = java.util.concurrent.FutureTask {
            try { second.reserveBeforeSigning(key(2, 2), candidate) } finally { completed.countDown() }
        }
        val one = Thread(a); val two = Thread(b)
        one.start()
        try {
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
            two.start()
            assertFalse(completed.await(50, java.util.concurrent.TimeUnit.MILLISECONDS))
            release.countDown()
            assertTrue(a.get(2, java.util.concurrent.TimeUnit.SECONDS))
            assertTrue(b.get(2, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(setOf(key(), key(2, 2)), checkNotNull(store.ledger).reservations)
        } finally {
            release.countDown()
            one.interrupt(); two.interrupt()
            one.join(1000); two.join(1000)
        }
    }

    @Test fun higherAckThroughSecondFenceRetiresDelayedAndInstalledOldPermit() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val first = ProfileChallengeFence(store)
        val second = ProfileChallengeFence(store)
        val old = install(tracker, candidate, first)
        assertTrue(second.reserveBeforeSigning(key(2, 2), candidate))
        val newer = checkNotNull(second.persistAcceptedAck(key(2, 2), candidate))
        assertFalse(old.isCurrent())
        assertNull(tracker.publishInstalled(old.permit))
        assertNotNull(tracker.publishInstalled(newer))
    }
    @Test fun failedHigherAckThroughSecondFenceStillRetiresOldInstalledPermit() {
        val tracker = tracker()
        ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        val store = Store()
        val first = ProfileChallengeFence(store)
        val second = ProfileChallengeFence(store)
        val old = install(tracker, candidate, first)
        assertTrue(second.reserveBeforeSigning(key(2, 2), candidate))
        store.writeResult = false
        assertNull(second.persistAcceptedAck(key(2, 2), candidate))
        assertFalse(old.isCurrent())
        assertNull(tracker.publishInstalled(old.permit))
    }

    @Test fun clockExpiryInsidePublicationLedgerReadCannotInsertAuthority() {
        val tracker = tracker(); ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10))
        var expired = false; var expireDuringRead = false
        var ledger = ProfileChallengeLedger()
        val store = object : ProfileChallengePersistence {
            override fun read(): ProfileChallengeLedger {
                if (expireDuringRead) expired = true
                return ledger
            }
            override fun write(value: ProfileChallengeLedger): Boolean { ledger = value; return true }
        }
        val fence = ProfileChallengeFence(store)
        assertTrue(fence.reserveBeforeSigning(key(), candidate))
        val permit = checkNotNull(fence.persistAcceptedAck(key(), candidate))
        expireDuringRead = true
        assertNull(tracker.publishInstalled(permit) { !expired })
        assertNull(tracker.lookupInstalled(candidate.record, authority))
    }
    @Test fun delayedUnpublishedPermitAcrossTwoFencesCannotInsertOldGeneration() {
        val tracker = tracker(); ready(tracker)
        val candidate = checkNotNull(tracker.candidate(10)); val store = Store()
        val first = ProfileChallengeFence(store); val second = ProfileChallengeFence(store)
        assertTrue(first.reserveBeforeSigning(key(), candidate))
        val old = checkNotNull(first.persistAcceptedAck(key(), candidate))
        assertTrue(second.reserveBeforeSigning(key(2, 2), candidate))
        val newer = checkNotNull(second.persistAcceptedAck(key(2, 2), candidate))
        assertNull(tracker.publishInstalled(old)); assertNotNull(tracker.publishInstalled(newer))
    }

}

/** Pure logical records and in-memory storage: no telephony, Keystore, network or radio. */
internal class EsimProfileFixture(subscription: Int = 7, card: Int = 42, singleActive: Boolean = false) : AutoCloseable {
    val tracker = EsimProfileContinuityTracker()
    private val records = listOf(ProfileSubscriptionObservation(subscription, card, true, 0, 0)) +
        if (singleActive) emptyList() else listOf(ProfileSubscriptionObservation(subscription + 1, card, true, 1, 0))
    var ledger = ProfileChallengeLedger()
    var writeResult = true
    var afterWrite: (() -> Unit)? = null
    private val store = object : ProfileChallengePersistence {
        override fun read() = ledger
        override fun write(value: ProfileChallengeLedger): Boolean {
            if (!writeResult) return false
            ledger = value; afterWrite?.invoke(); return true
        }
    }
    val fence = ProfileChallengeFence(store)
    private val source = object : ProfileObservationSource {
        override fun permissionGranted() = true
        override fun register(changed: () -> Unit): AutoCloseable { changed(); return AutoCloseable {} }
        override fun readComplete() = records
    }
    private val monitor = SimProfileMonitor(source, { it() }, java.util.concurrent.Executor { it.run() }) { tracker }
    private val restore = SimProfileContinuity.replaceForTesting(monitor, fence)
    init { monitor.start() }
    val candidate get() = checkNotNull(tracker.candidate(records.first().subscriptionId))
    fun cards() = records.map { ActiveSimCard(it.subscriptionId, it.cardId, true,
        it.portIndex, it.logicalSlotIndex).withProfile(tracker.candidate(it.subscriptionId)) }
    fun install(binding: LocalLineBinding): InstalledEsimProfile {
        val key = ProfileChallengeKey(checkNotNull(binding.profileAuthority()), UUID.randomUUID().toString())
        check(fence.reserveBeforeSigning(key, candidate))
        return checkNotNull(tracker.publishInstalled(checkNotNull(fence.persistAcceptedAck(key, candidate))))
    }
    override fun close() = restore.close()
}
