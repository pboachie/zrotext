// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn fixture() -> (Grant, Current, Action, Approval) {
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let line = Uuid::new_v4();
    let grant = Grant {
        account,
        id: Uuid::new_v4(),
        device,
        line,
        binding_generation: 1,
        recipient: [1; 32],
        permissions: Permissions {
            metadata: true,
            read_content: false,
            draft: false,
            send: true,
        },
        expires_ms: 20_000,
        revoked: false,
        taken_over: false,
        owner_self_notification: true,
        reader_identity: None,
        model_provider_identity: None,
        model_reads_content: false,
        message_limit: 2,
        turn_limit: 2,
    };
    let current = Current {
        account,
        device,
        line,
        binding_generation: 1,
        now_ms: 10_000,
        suppressed: false,
        reader_revoked: false,
        messages_reserved: 0,
        turns_consumed: 0,
    };
    let action = Action {
        account,
        grant: grant.id,
        action: Uuid::new_v4(),
        message: Uuid::new_v4(),
        line,
        device,
        binding_generation: 1,
        recipient: [1; 32],
        unsigned_envelope: [2; 32],
        not_before_ms: 9_000,
        expires_ms: 15_000,
    };
    let approval = Approval {
        action_digest: action.digest(),
        expires_ms: 15_000,
        revoked: false,
    };
    (grant, current, action, approval)
}

#[test]
fn independent_permissions_never_expand_metadata_into_content_drafts_or_send() {
    let (mut grant, current, _, _) = fixture();
    grant.permissions.send = false;
    assert_eq!(grant.authorize(&current, Operation::Metadata), Ok(()));
    for operation in [Operation::ReadContent, Operation::Draft, Operation::Send] {
        assert_eq!(
            grant.authorize(&current, operation),
            Err(Denial::MissingPermission)
        );
    }
}

#[test]
fn every_action_edit_invalidates_the_exact_owner_digest() {
    let (grant, current, action, approval) = fixture();
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Ok(())
    );
    for change in 0..11 {
        let mut edited = action.clone();
        match change {
            0 => edited.account = Uuid::new_v4(),
            1 => edited.grant = Uuid::new_v4(),
            2 => edited.action = Uuid::new_v4(),
            3 => edited.message = Uuid::new_v4(),
            4 => edited.line = Uuid::new_v4(),
            5 => edited.device = Uuid::new_v4(),
            6 => edited.binding_generation += 1,
            7 => edited.recipient[0] ^= 1,
            8 => edited.unsigned_envelope[0] ^= 1,
            9 => edited.not_before_ms += 1,
            _ => edited.expires_ms -= 1,
        }
        assert_ne!(edited.digest(), action.digest());
        assert!(
            grant
                .authorize_new_action(&current, &edited, Some(&approval))
                .is_err()
        );
    }
    assert_eq!(
        grant.authorize_new_action(&current, &action, None),
        Err(Denial::NeedsOwnerApproval)
    );
}

#[test]
fn current_line_tenant_generation_and_revocation_reject_cached_authority() {
    let (mut grant, mut current, action, approval) = fixture();
    current.account = Uuid::new_v4();
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::ForeignScope)
    );
    current.account = grant.account;
    current.binding_generation += 1;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::ForeignScope)
    );
    current.binding_generation = 1;
    grant.revoked = true;
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Err(Denial::Revoked)
    );
    grant.revoked = false;
    grant.taken_over = true;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::TakenOver)
    );
}

#[test]
fn content_requires_a_selected_live_reader_and_explicit_provider_access() {
    let (mut grant, mut current, _, _) = fixture();
    grant.permissions.read_content = true;
    assert_eq!(
        grant.authorize(&current, Operation::ReadContent),
        Err(Denial::ReaderUnavailable)
    );
    grant.reader_identity = Some(Uuid::new_v4());
    assert_eq!(grant.authorize(&current, Operation::ReadContent), Ok(()));
    current.reader_revoked = true;
    assert_eq!(
        grant.authorize(&current, Operation::ReadContent),
        Err(Denial::ReaderUnavailable)
    );
    grant.model_reads_content = true;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::InvalidPolicy)
    );
    grant.model_provider_identity = Some(Uuid::new_v4());
    grant.permissions.read_content = false;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::InvalidPolicy)
    );
}

#[test]
fn expiry_early_timing_suppression_and_consumed_budgets_stop_new_effects() {
    let (grant, mut current, action, mut approval) = fixture();
    current.now_ms = 8_000;
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Err(Denial::TooEarly)
    );
    current.now_ms = action.expires_ms;
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Err(Denial::Expired)
    );
    current.now_ms = 10_000;
    current.suppressed = true;
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Err(Denial::Suppressed)
    );
    current.suppressed = false;
    approval.revoked = true;
    assert_eq!(
        grant.authorize_new_action(&current, &action, Some(&approval)),
        Err(Denial::NeedsOwnerApproval)
    );
    approval.revoked = false;
    for (messages, turns) in [(2, 0), (0, 2), (-1, 0), (0, -1)] {
        current.messages_reserved = messages;
        current.turns_consumed = turns;
        assert_eq!(
            grant.authorize_new_action(&current, &action, Some(&approval)),
            Err(Denial::BudgetExhausted)
        );
    }
}

#[test]
fn broad_recipient_pilots_and_zero_or_unbounded_limits_are_refused() {
    let (mut grant, current, _, _) = fixture();
    grant.owner_self_notification = false;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::InvalidPolicy)
    );
    grant.owner_self_notification = true;
    for limit in [0, 101] {
        grant.message_limit = limit;
        assert_eq!(
            grant.authorize(&current, Operation::Metadata),
            Err(Denial::InvalidPolicy)
        );
    }
    grant.message_limit = 1;
    grant.turn_limit = 4;
    assert_eq!(
        grant.authorize(&current, Operation::Metadata),
        Err(Denial::InvalidPolicy)
    );
}
