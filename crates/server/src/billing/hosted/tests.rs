use super::{namespace::*, policy::*, *};

fn namespace(mode: Mode) -> Namespace {
    Namespace::new([1; 16], mode, "acct_fixture").unwrap()
}

fn marker() -> Marker {
    Marker {
        namespace: namespace(Mode::Test),
        policy_revision: 1,
        enabled: true,
    }
}

fn gate() -> Gate {
    let stored = marker();
    Gate::verify(
        true,
        &stored.namespace,
        1,
        &stored,
        &ProviderIdentity {
            mode: Mode::Test,
            provider_account: "acct_fixture".into(),
        },
    )
    .unwrap()
}

fn scope() -> Scope {
    Scope::new(namespace(Mode::Test), [2; 16], "cus_fixture", "sub_fixture").unwrap()
}

fn plan() -> Plan {
    Plan::new("price_fixture", 19, 2, 100).unwrap()
}

fn observation() -> Observation {
    Observation {
        scope: scope(),
        policy_revision: 1,
        generation: 1,
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::Active,
        price: "price_fixture".into(),
        invoice: "in_fixture".into(),
        period_start: 100,
        period_end: 1000,
        revalidate_at: 900,
        failure: None,
    }
}

fn fence(generation: u64) -> Fence {
    Fence {
        dirty_generation: generation,
        payment_hold: false,
        review_required: false,
    }
}

fn project(read: &Observation, previous: Option<&Projection>) -> Result<Projection, Refusal> {
    reconcile(Reconciliation {
        gate: &gate(),
        marker: &marker(),
        binding: &scope(),
        fence: fence(read.generation),
        previous,
        observation: read,
        plan: &plan(),
        now: 200,
    })
}

fn send(
    projection: Option<&Projection>,
    consumed: u64,
    units: u64,
    now: i64,
) -> Result<(), Refusal> {
    admit(
        &gate(),
        &marker(),
        &scope(),
        fence(1),
        projection,
        Purpose::Outbound { consumed, units },
        now,
    )
}

#[test]
fn default_hosted_gate_denies_without_configuration_or_database() {
    assert_eq!(Gate::disabled().marker(), Err(Refusal::Disabled));
    assert_eq!(
        for_deployment(Deployment::HostedPaid, || Gate::disabled()
            .marker()
            .map(|_| ())),
        Err(Refusal::Disabled)
    );
}

#[test]
fn self_hosting_never_opens_billing_or_consults_a_provider() {
    assert_eq!(
        for_deployment(Deployment::SelfHosted, || panic!(
            "billing must not be consulted"
        )),
        Ok(BillingCheck::NotRequired)
    );
    assert_eq!(
        for_deployment(Deployment::HostedPaid, || Ok(())),
        Ok(BillingCheck::Checked)
    );
}

#[test]
fn namespace_requires_nonzero_bounded_server_identity() {
    assert_eq!(
        Namespace::new([0; 16], Mode::Test, "acct_fixture"),
        Err(Refusal::InvalidConfiguration)
    );
    for value in [
        "",
        "foreign/account",
        " acct_fixture",
        "https://example.test",
    ] {
        assert_eq!(
            Namespace::new([1; 16], Mode::Live, value),
            Err(Refusal::InvalidConfiguration)
        );
    }
    let ns = namespace(Mode::Live);
    assert_eq!(ns.id(), [1; 16]);
    assert_eq!(ns.mode(), Mode::Live);
    assert_eq!(ns.provider_account(), "acct_fixture");
}

#[test]
fn test_proof_never_opens_a_live_gate_even_when_opaque_ids_collide() {
    let ns = namespace(Mode::Live);
    let stored = Marker {
        namespace: ns.clone(),
        policy_revision: 1,
        enabled: true,
    };
    assert_eq!(
        Gate::verify(
            true,
            &ns,
            1,
            &stored,
            &ProviderIdentity {
                mode: Mode::Test,
                provider_account: "acct_fixture".into(),
            }
        )
        .unwrap_err(),
        Refusal::NamespaceMismatch
    );
}

#[test]
fn wrong_provider_account_and_database_namespace_refuse_startup() {
    let stored = marker();
    assert_eq!(
        Gate::verify(
            true,
            &stored.namespace,
            1,
            &stored,
            &ProviderIdentity {
                mode: Mode::Test,
                provider_account: "acct_foreign".into(),
            }
        )
        .unwrap_err(),
        Refusal::NamespaceMismatch
    );
    assert_eq!(
        Gate::verify(
            true,
            &namespace(Mode::Live),
            1,
            &stored,
            &ProviderIdentity {
                mode: Mode::Live,
                provider_account: "acct_fixture".into(),
            }
        )
        .unwrap_err(),
        Refusal::NamespaceMismatch
    );
}

#[test]
fn disabled_or_revised_storage_invalidates_an_already_verified_process() {
    let running = gate();
    let mut stored = marker();
    stored.enabled = false;
    assert_eq!(running.check_marker(&stored), Err(Refusal::Disabled));
    stored.enabled = true;
    stored.policy_revision = 2;
    assert_eq!(running.check_marker(&stored), Err(Refusal::StalePolicy));
    stored.policy_revision = 1;
    stored.namespace = namespace(Mode::Live);
    assert_eq!(
        running.check_marker(&stored),
        Err(Refusal::NamespaceMismatch)
    );
}

#[test]
fn startup_requires_explicit_nonzero_matching_policy_revision() {
    for revision in [0, 2] {
        assert!(
            Gate::verify(
                true,
                &marker().namespace,
                revision,
                &marker(),
                &ProviderIdentity {
                    mode: Mode::Test,
                    provider_account: "acct_fixture".into(),
                }
            )
            .is_err()
        );
    }
    assert!(
        Gate::verify(
            false,
            &marker().namespace,
            1,
            &marker(),
            &ProviderIdentity {
                mode: Mode::Test,
                provider_account: "acct_fixture".into(),
            }
        )
        .is_err()
    );
}

#[test]
fn quota_mapping_has_no_commercial_defaults_and_rejects_invalid_counters() {
    for (messages, devices, grace) in [
        (0, 1, 0),
        (1, 0, 0),
        (u64::MAX, 1, 0),
        (1, u64::MAX, 0),
        (1, 1, 604801),
    ] {
        assert_eq!(
            Plan::new("price_fixture", messages, devices, grace),
            Err(Refusal::InvalidConfiguration)
        );
    }
    assert_eq!(plan().price(), "price_fixture");
    assert_eq!(plan().outbound_limit(), 19);
    assert_eq!(plan().device_limit(), 2);
    assert!(Plan::new("", 1, 1, 0).is_err());
}

#[test]
fn bound_tenant_customer_subscription_and_mode_are_all_required() {
    for wrong in [
        Scope::new(namespace(Mode::Test), [3; 16], "cus_fixture", "sub_fixture").unwrap(),
        Scope::new(namespace(Mode::Test), [2; 16], "cus_foreign", "sub_fixture").unwrap(),
        Scope::new(namespace(Mode::Test), [2; 16], "cus_fixture", "sub_foreign").unwrap(),
        Scope::new(namespace(Mode::Live), [2; 16], "cus_fixture", "sub_fixture").unwrap(),
    ] {
        let mut read = observation();
        read.scope = wrong;
        assert!(project(&read, None).is_err());
    }
    assert_eq!(scope().owner(), [2; 16]);
    assert_eq!(scope().customer(), "cus_fixture");
    assert_eq!(scope().subscription(), "sub_fixture");
    assert!(Scope::new(namespace(Mode::Test), [0; 16], "cus_fixture", "sub_fixture").is_err());
}

#[test]
fn active_complete_current_subscription_projects_exact_approved_limits() {
    let projection = project(&observation(), None).unwrap();
    assert_eq!(projection.phase(), Phase::Active);
    assert_eq!(projection.outbound_limit(), 19);
    assert_eq!(projection.device_limit(), 2);
    assert_eq!(projection.valid_until(), 900);
    assert_eq!(send(Some(&projection), 18, 1, 200), Ok(()));
    assert_eq!(
        send(Some(&projection), 19, 1, 200),
        Err(Refusal::QuotaExceeded)
    );
    assert_eq!(
        send(Some(&projection), u64::MAX, 1, 200),
        Err(Refusal::QuotaExceeded)
    );
    assert_eq!(
        send(Some(&projection), 0, 0, 200),
        Err(Refusal::QuotaExceeded)
    );
}

#[test]
fn checkout_or_paid_invoice_without_reconciled_subscription_grants_nothing() {
    assert_eq!(send(None, 0, 1, 200), Err(Refusal::Pending));
    let mut read = observation();
    read.status = SubscriptionStatus::Canceled;
    let projection = project(&read, None).unwrap();
    assert_eq!(projection.phase(), Phase::Terminal);
    assert_eq!(send(Some(&projection), 0, 1, 200), Err(Refusal::Restricted));
}

#[test]
fn incomplete_provider_lists_do_not_restore_a_prior_active_projection() {
    let active = project(&observation(), None).unwrap();
    let mut read = observation();
    read.generation = 2;
    read.complete = false;
    let pending = project(&read, Some(&active)).unwrap();
    assert_eq!(pending.phase(), Phase::Pending);
    assert_eq!(pending.outbound_limit(), 0);
    assert_eq!(send(Some(&pending), 0, 1, 200), Err(Refusal::Pending));
}

#[test]
fn unknown_price_ambiguity_risk_and_review_do_not_grant_capacity() {
    for case in 0..3 {
        let mut read = observation();
        match case {
            0 => read.price = "price_foreign".into(),
            1 => read.nonterminal_subscriptions = 2,
            _ => read.nonterminal_subscriptions = 0,
        }
        let projection = project(&read, None).unwrap();
        assert_eq!(projection.phase(), Phase::Restricted);
        assert_eq!(projection.outbound_limit(), 0);
        assert_eq!(projection.device_limit(), 0);
    }
}

#[test]
fn stale_policy_or_provider_generation_cannot_commit_a_new_projection() {
    let mut read = observation();
    read.policy_revision = 2;
    assert_eq!(project(&read, None), Err(Refusal::StalePolicy));
    read.policy_revision = 1;
    assert_eq!(
        reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: fence(2),
            previous: None,
            observation: &read,
            plan: &plan(),
            now: 200
        }),
        Err(Refusal::StaleObservation)
    );
    assert_eq!(
        reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: fence(0),
            previous: None,
            observation: &read,
            plan: &plan(),
            now: 200
        }),
        Err(Refusal::StaleObservation)
    );
}

#[test]
fn a_new_wakeup_blocks_admission_before_the_old_worker_returns() {
    let active = project(&observation(), None).unwrap();
    assert_eq!(
        admit(
            &gate(),
            &marker(),
            &scope(),
            fence(2),
            Some(&active),
            Purpose::Outbound {
                units: 1,
                consumed: 0
            },
            200
        ),
        Err(Refusal::Pending)
    );
}

#[test]
fn projection_expiry_and_policy_change_fail_closed_without_provider_fallback() {
    let active = project(&observation(), None).unwrap();
    assert_eq!(send(Some(&active), 0, 1, 900), Err(Refusal::Pending));
    let revised = Marker {
        policy_revision: 2,
        ..marker()
    };
    assert_eq!(
        admit(
            &gate(),
            &revised,
            &scope(),
            fence(1),
            Some(&active),
            Purpose::Outbound {
                units: 1,
                consumed: 0
            },
            200
        ),
        Err(Refusal::StalePolicy)
    );
}

fn past_due(failed_at: i64) -> Observation {
    let mut read = observation();
    read.status = SubscriptionStatus::PastDue;
    read.failure = Some(FailureEvidence {
        scope: scope(),
        invoice: "in_fixture".into(),
        occurred_at: failed_at,
    });
    read
}

#[test]
fn past_due_requires_signed_matching_current_invoice_failure() {
    let mut read = past_due(180);
    read.failure = None;
    assert_eq!(project(&read, None).unwrap().phase(), Phase::Pending);
    read = past_due(180);
    read.failure.as_mut().unwrap().invoice = "in_old".into();
    assert_eq!(project(&read, None).unwrap().phase(), Phase::Pending);
    read = past_due(180);
    read.failure.as_mut().unwrap().scope =
        Scope::new(namespace(Mode::Test), [3; 16], "cus_fixture", "sub_fixture").unwrap();
    assert_eq!(project(&read, None), Err(Refusal::TenantMismatch));
}

#[test]
fn past_due_grace_is_bounded_and_future_failure_time_cannot_extend_it() {
    let grace = project(&past_due(180), None).unwrap();
    assert_eq!(grace.phase(), Phase::Grace);
    assert_eq!(grace.valid_until(), 280);
    assert_eq!(send(Some(&grace), 0, 1, 279), Ok(()));
    assert_eq!(send(Some(&grace), 0, 1, 280), Err(Refusal::Pending));
    let future = project(&past_due(500), None).unwrap();
    assert_eq!(future.first_failure_at(), Some(200));
    assert_eq!(future.valid_until(), 300);
}

#[test]
fn duplicate_failure_new_invoice_and_restart_never_extend_continuous_grace() {
    let first = project(&past_due(150), None).unwrap();
    let mut later = past_due(195);
    later.generation = 2;
    later.invoice = "in_next".into();
    later.failure.as_mut().unwrap().invoice = "in_next".into();
    let replayed = project(&later, Some(&first)).unwrap();
    assert_eq!(replayed.first_failure_at(), Some(150));
    assert_eq!(replayed.valid_until(), 250);
    later.generation = 3;
    let restarted = project(&later, Some(&replayed)).unwrap();
    assert_eq!(
        restarted,
        Projection {
            generation: 3,
            ..replayed
        }
    );
}

#[test]
fn temporary_incomplete_read_or_hold_never_erases_delinquency_deadline() {
    let first = project(&past_due(150), None).unwrap();
    let mut partial = past_due(195);
    partial.generation = 2;
    partial.complete = false;
    let pending = project(&partial, Some(&first)).unwrap();
    assert_eq!(pending.first_failure_at(), Some(150));
    let mut recovered = past_due(195);
    recovered.generation = 3;
    let recovered_read = project(&recovered, Some(&pending)).unwrap();
    assert_eq!(recovered_read.valid_until(), 250);
    let mut held_read = past_due(195);
    held_read.generation = 4;
    let held = reconcile(Reconciliation {
        gate: &gate(),
        marker: &marker(),
        binding: &scope(),
        fence: Fence {
            payment_hold: true,
            ..fence(4)
        },
        previous: Some(&recovered_read),
        observation: &held_read,
        plan: &plan(),
        now: 200,
    })
    .unwrap();
    assert_eq!(held.first_failure_at(), Some(150));
}

#[test]
fn initial_hold_or_review_records_grace_start_without_granting_capacity() {
    for restriction in [
        Fence {
            payment_hold: true,
            ..fence(1)
        },
        Fence {
            review_required: true,
            ..fence(1)
        },
    ] {
        let held = reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: restriction,
            previous: None,
            observation: &past_due(150),
            plan: &plan(),
            now: 200,
        })
        .unwrap();
        assert_eq!(held.phase(), Phase::Restricted);
        assert_eq!(held.first_failure_at(), Some(150));
        assert_eq!(held.outbound_limit(), 0);
        assert_eq!(held.device_limit(), 0);
        assert_eq!(send(Some(&held), 0, 1, 200), Err(Refusal::Restricted));

        let mut later = past_due(195);
        later.generation = 2;
        later.invoice = "in_next".into();
        later.failure.as_mut().unwrap().invoice = "in_next".into();
        let resumed = project(&later, Some(&held)).unwrap();
        assert_eq!(resumed.first_failure_at(), Some(150));
        assert_eq!(resumed.valid_until(), 250);
        assert_eq!(
            admit(
                &gate(),
                &marker(),
                &scope(),
                fence(2),
                Some(&resumed),
                Purpose::Outbound {
                    units: 1,
                    consumed: 0
                },
                250
            ),
            Err(Refusal::Pending)
        );
    }
}

#[test]
fn initial_restriction_latches_only_complete_valid_current_failure_evidence() {
    for case in 0..7 {
        let mut read = past_due(150);
        match case {
            0 => read.complete = false,
            1 => read.period_start = 300,
            2 => read.period_end = 200,
            3 => read.revalidate_at = 200,
            4 => read.price = "price_foreign".into(),
            5 => read.failure.as_mut().unwrap().invoice = "in_old".into(),
            _ => read.failure.as_mut().unwrap().occurred_at = -1,
        }
        let held = reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: Fence {
                payment_hold: true,
                ..fence(1)
            },
            previous: None,
            observation: &read,
            plan: &plan(),
            now: 200,
        })
        .unwrap();
        assert_eq!(held.first_failure_at(), None);
        assert_eq!(held.outbound_limit(), 0);
        assert_eq!(held.device_limit(), 0);
    }
    let mut foreign = past_due(150);
    foreign.failure.as_mut().unwrap().scope =
        Scope::new(namespace(Mode::Test), [3; 16], "cus_fixture", "sub_fixture").unwrap();
    assert_eq!(
        reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: Fence {
                payment_hold: true,
                ..fence(1)
            },
            previous: None,
            observation: &foreign,
            plan: &plan(),
            now: 200,
        }),
        Err(Refusal::TenantMismatch)
    );
}

#[test]
fn successful_current_subscription_recovery_resets_grace_only_after_reconciliation() {
    let grace = project(&past_due(150), None).unwrap();
    let mut current = observation();
    current.generation = 2;
    let active = project(&current, Some(&grace)).unwrap();
    assert_eq!(active.first_failure_at(), None);
    assert_eq!(active.phase(), Phase::Active);
    let mut failed = past_due(195);
    failed.generation = 3;
    let new_cycle = project(&failed, Some(&active)).unwrap();
    assert_eq!(new_cycle.first_failure_at(), Some(195));
}

#[test]
fn unpaid_paused_incomplete_canceled_and_deleted_do_not_grant_capacity() {
    for status in [
        SubscriptionStatus::Unpaid,
        SubscriptionStatus::Paused,
        SubscriptionStatus::Incomplete,
        SubscriptionStatus::Canceled,
        SubscriptionStatus::Deleted,
    ] {
        let mut read = observation();
        read.status = status;
        let projection = project(&read, None).unwrap();
        assert_eq!(projection.outbound_limit(), 0);
        assert_eq!(send(Some(&projection), 0, 1, 200), Err(Refusal::Restricted));
    }
}

#[test]
fn malformed_expired_or_future_invoice_period_cannot_project_an_active_grant() {
    for (start, end, lease) in [
        (300, 1000, 900),
        (-1, 1000, 900),
        (100, 200, 900),
        (100, 1000, 200),
    ] {
        let mut read = observation();
        read.period_start = start;
        read.period_end = end;
        read.revalidate_at = lease;
        assert_eq!(project(&read, None).unwrap().phase(), Phase::Restricted);
    }
}

#[test]
fn device_cap_blocks_new_enrollment_without_revoking_existing_outbound_authority() {
    let active = project(&observation(), None).unwrap();
    assert_eq!(
        admit(
            &gate(),
            &marker(),
            &scope(),
            fence(1),
            Some(&active),
            Purpose::EnrollDevice { active_devices: 1 },
            200
        ),
        Ok(())
    );
    assert_eq!(
        admit(
            &gate(),
            &marker(),
            &scope(),
            fence(1),
            Some(&active),
            Purpose::EnrollDevice { active_devices: 2 },
            200
        ),
        Err(Refusal::DeviceCapExceeded)
    );
    assert_eq!(send(Some(&active), 0, 1, 200), Ok(()));
}

#[test]
fn exact_same_replay_digest_is_a_noop_and_changed_bytes_conflict() {
    assert_eq!(check_replay(&[1; 32], &[1; 32]), Ok(()));
    assert_eq!(
        check_replay(&[1; 32], &[2; 32]),
        Err(Refusal::ReplayConflict)
    );
}

#[test]
fn provider_activity_cannot_clear_a_local_hold_or_review_before_admission() {
    let active = project(&observation(), None).unwrap();
    for restriction in [
        Fence {
            payment_hold: true,
            ..fence(1)
        },
        Fence {
            review_required: true,
            ..fence(1)
        },
    ] {
        assert_eq!(
            admit(
                &gate(),
                &marker(),
                &scope(),
                restriction,
                Some(&active),
                Purpose::Outbound {
                    units: 1,
                    consumed: 0
                },
                200
            ),
            Err(Refusal::Restricted)
        );
        let mut current = observation();
        current.generation = 2;
        let projection = reconcile(Reconciliation {
            gate: &gate(),
            marker: &marker(),
            binding: &scope(),
            fence: Fence {
                dirty_generation: 2,
                ..restriction
            },
            previous: Some(&active),
            observation: &current,
            plan: &plan(),
            now: 200,
        })
        .unwrap();
        assert_eq!(projection.phase(), Phase::Restricted);
        assert_eq!(projection.outbound_limit(), 0);
    }
}

#[test]
fn same_or_older_generation_active_read_cannot_erase_delinquency() {
    let mut failed = past_due(150);
    failed.generation = 2;
    let grace = project(&failed, None).unwrap();
    for generation in [1, 2] {
        let mut old_active = observation();
        old_active.generation = generation;
        assert_eq!(
            project(&old_active, Some(&grace)),
            Err(Refusal::StaleObservation)
        );
    }
    assert_eq!(grace.first_failure_at(), Some(150));
    assert_eq!(grace.valid_until(), 250);
}

#[test]
fn admission_clock_rollback_before_projection_issue_time_fails_closed() {
    for read in [observation(), past_due(180)] {
        let projection = project(&read, None).unwrap();
        assert_eq!(projection.issued_at(), 200);
        for now in [-1, 50, 199] {
            assert_eq!(send(Some(&projection), 0, 1, now), Err(Refusal::Pending));
            assert_eq!(
                admit(
                    &gate(),
                    &marker(),
                    &scope(),
                    fence(1),
                    Some(&projection),
                    Purpose::EnrollDevice { active_devices: 0 },
                    now
                ),
                Err(Refusal::Pending)
            );
        }
        assert_eq!(send(Some(&projection), 0, 1, 200), Ok(()));
    }
}

#[test]
fn newer_generation_cannot_rewind_the_stored_projection_issue_time() {
    for mut read in [observation(), past_due(180)] {
        let prior = project(&read, None).unwrap();
        read.generation = 2;
        for now in [150, 199] {
            assert_eq!(
                reconcile(Reconciliation {
                    gate: &gate(),
                    marker: &marker(),
                    binding: &scope(),
                    fence: fence(2),
                    previous: Some(&prior),
                    observation: &read,
                    plan: &plan(),
                    now,
                }),
                Err(Refusal::StaleObservation)
            );
        }
        let current = project(&read, Some(&prior)).unwrap();
        assert_eq!(current.issued_at(), prior.issued_at());
        assert_eq!(current.phase(), prior.phase());
        assert_eq!(current.valid_until(), prior.valid_until());
        assert_eq!(current.first_failure_at(), prior.first_failure_at());
    }
}
