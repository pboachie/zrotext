// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway
import java.util.UUID
import org.junit.Test
import org.junit.Assert.*
class ConversationPresentationContractTest {
    private fun review()=ConversationPhoneReview(UUID.randomUUID().toString(),UUID.randomUUID().toString(),UUID.randomUUID().toString(),1,"+12",ConversationActivationCodec.DISCLOSURE,"conversation-content-v1",Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray(Charsets.UTF_8)),1000)
    @Test fun reviewCarriesExactCanonicalDisclosureOnly(){val value=review();assertThrows(IllegalArgumentException::class.java){value.copy(disclosure="different")};assertThrows(IllegalArgumentException::class.java){value.copy(disclosureDigest="00".repeat(32))};assertFalse(value.toString().contains(value.peer))}
    @Test fun routineSnapshotCannotCarryReviewPeer(){assertThrows(IllegalArgumentException::class.java){ConversationPresentationSnapshot(1,ConversationPresentationPhase.OFF,review=review())}}
    @Test fun activeCannotBeInferredWithoutFreshLeaseAndSelection(){assertThrows(IllegalArgumentException::class.java){ConversationPresentationSnapshot(1,ConversationPresentationPhase.CONFIRMED_ACTIVE)};assertThrows(IllegalArgumentException::class.java){ConversationPresentationSnapshot(1,ConversationPresentationPhase.CONFIRMED_ACTIVE,UUID.randomUUID().toString(),UUID.randomUUID().toString(),1,0,true)}}
    @Test fun closureFailureCannotBeDisplayedAsDurableClosed(){assertThrows(IllegalArgumentException::class.java){ConversationPresentationSnapshot(1,ConversationPresentationPhase.DURABLY_CLOSED,close=ConversationCloseOutcome.DISABLED_CLOSURE_FAILED)}}
    @Test fun pairedPermissionStateCannotSubstituteForPhoneReview(){assertThrows(IllegalArgumentException::class.java){ConversationPresentationSnapshot(1,ConversationPresentationPhase.AWAITING_PHONE_REVIEW)};assertThrows(IllegalArgumentException::class.java){review().copy(remainingMs=0)}}
}
