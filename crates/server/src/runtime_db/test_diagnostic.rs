// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in fixed-category/numeric receipts for isolated Rust test builds.

pub(crate) fn enabled() -> bool {
    std::env::var("ZT_RUNTIME_DB_TEST_DIAGNOSTIC").as_deref() == Ok("1")
}
