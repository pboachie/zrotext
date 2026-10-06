// SPDX-License-Identifier: AGPL-3.0-only
use super::finish_prepared;

#[derive(Default)]
struct Cleanup {
    events: Vec<&'static str>,
    failures: [bool; 2],
    input_panic: Option<usize>,
    output_failure: bool,
    output_panic: bool,
    recovery: [u8; 32],
}

struct Prepared {
    slots: [u8; 5],
    secret: bool,
}

fn output(secret: bool) -> Prepared {
    Prepared {
        slots: [1, 2, 3, 4, 5],
        secret,
    }
}

fn clear_input(state: &mut Cleanup, index: usize) -> Result<(), ()> {
    state
        .events
        .push(if index == 0 { "root" } else { "archive" });
    if state.input_panic == Some(index) {
        panic!("synthetic cleanup unwind");
    }
    if state.failures[index] {
        Err(())
    } else {
        Ok(())
    }
}

fn discard(state: &mut Cleanup, prepared: Prepared) -> Result<(), ()> {
    state.events.push("discard");
    if prepared.secret {
        state.events.push("secret");
        if state.output_panic {
            panic!("synthetic output cleanup unwind");
        }
        if state.output_failure {
            return Err(());
        }
        state.recovery.fill(0);
    }
    Ok(())
}

fn rejected_input(failures: [bool; 2]) {
    let mut state = Cleanup {
        failures,
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) = finish_prepared(
        &mut state,
        2,
        |state| {
            state.events.push("prepared");
            Ok(output(true))
        },
        clear_input,
        discard,
    );
    assert!(result.is_err(), "prepared output must not be returned");
    assert!(!panicked);
    assert_eq!(
        state.events,
        ["prepared", "root", "archive", "discard", "secret"]
    );
    assert_eq!(state.recovery, [0; 32]);
}

#[test]
fn first_input_failure_attempts_second_input_and_secret_before_rejection() {
    rejected_input([true, false]);
}

#[test]
fn second_input_failure_discards_prepared_secret_before_rejection() {
    rejected_input([false, true]);
}

#[test]
fn both_input_failures_attempt_both_inputs_and_secret_before_rejection() {
    rejected_input([true, true]);
}

#[test]
fn successful_input_cleanup_retains_original_prepared_output_and_secret() {
    let mut state = Cleanup {
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) = finish_prepared(
        &mut state,
        2,
        |state| {
            state.events.push("prepared");
            Ok(output(true))
        },
        clear_input,
        discard,
    );
    assert!(!panicked);
    let prepared = result.unwrap_or_else(|_| panic!("success rejected"));
    assert_eq!(prepared.slots, [1, 2, 3, 4, 5]);
    assert!(prepared.secret);
    assert_eq!(state.events, ["prepared", "root", "archive"]);
    assert_eq!(state.recovery, [7; 32]);
}

#[test]
fn public_output_failure_refuses_without_inventing_secret_cleanup() {
    let mut state = Cleanup {
        failures: [true, false],
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) =
        finish_prepared(&mut state, 2, |_| Ok(output(false)), clear_input, discard);
    assert!(result.is_err());
    assert!(!panicked);
    assert_eq!(state.events, ["root", "archive", "discard"]);
    assert_eq!(state.recovery, [7; 32]);
}

#[test]
fn operation_rejection_attempts_inputs_without_double_output_discard() {
    let mut state = Cleanup {
        failures: [true, false],
        ..Cleanup::default()
    };
    let (result, panicked) =
        finish_prepared::<_, Prepared>(&mut state, 2, |_| Err(()), clear_input, discard);
    assert!(result.is_err());
    assert!(!panicked);
    assert_eq!(state.events, ["root", "archive"]);
}

#[test]
fn operation_unwind_attempts_inputs_and_marks_service_closure() {
    let mut state = Cleanup::default();
    let (result, panicked) = finish_prepared::<_, Prepared>(
        &mut state,
        2,
        |_| panic!("synthetic operation unwind"),
        clear_input,
        discard,
    );
    assert!(result.is_err());
    assert!(panicked);
    assert_eq!(state.events, ["root", "archive"]);
}

#[test]
fn first_input_unwind_still_attempts_second_input_and_secret() {
    let mut state = Cleanup {
        input_panic: Some(0),
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) =
        finish_prepared(&mut state, 2, |_| Ok(output(true)), clear_input, discard);
    assert!(result.is_err());
    assert!(panicked);
    assert_eq!(state.events, ["root", "archive", "discard", "secret"]);
    assert_eq!(state.recovery, [0; 32]);
}

#[test]
fn output_wipe_error_still_refuses_prepared_result() {
    let mut state = Cleanup {
        failures: [false, true],
        output_failure: true,
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) =
        finish_prepared(&mut state, 2, |_| Ok(output(true)), clear_input, discard);
    assert!(result.is_err());
    assert!(!panicked);
    assert_eq!(state.events, ["root", "archive", "discard", "secret"]);
    assert_eq!(
        state.recovery, [7; 32],
        "failed wipe is not an erasure claim"
    );
}

#[test]
fn output_wipe_unwind_is_contained_and_marks_service_closure() {
    let mut state = Cleanup {
        failures: [true, false],
        output_panic: true,
        recovery: [7; 32],
        ..Cleanup::default()
    };
    let (result, panicked) =
        finish_prepared(&mut state, 2, |_| Ok(output(true)), clear_input, discard);
    assert!(result.is_err());
    assert!(panicked);
    assert_eq!(state.events, ["root", "archive", "discard", "secret"]);
    assert_eq!(state.recovery, [7; 32]);
}
