-- SPDX-License-Identifier: AGPL-3.0-only
-- ADR 0004 step 2: owner-visible line labels and the per-line not-ready
-- policy. A label is mutable presentation; authority stays bound to the
-- account-scoped line identity and its current approved binding. No SIM slot,
-- subscription identifier or card identifier is stored or exposed here.

ALTER TABLE phone_lines
    ADD COLUMN label text,
    ADD COLUMN not_ready_mode text NOT NULL DEFAULT 'ignore'
        CHECK (not_ready_mode IN ('ignore', 'queue', 'fallback')),
    ADD COLUMN fallback_line_id uuid,
    ADD COLUMN offline_not_ready_after_seconds integer NOT NULL DEFAULT 300
        CHECK (offline_not_ready_after_seconds >= 0
           AND offline_not_ready_after_seconds <= 86400),
    ADD COLUMN policy_version bigint NOT NULL DEFAULT 1
        CHECK (policy_version > 0),
    ADD COLUMN policy_updated_at timestamptz NOT NULL DEFAULT now();

-- A label addresses a line; within an account it must resolve to exactly one
-- line regardless of state, so dropped lines release their text only on
-- explicit rename. Existing rows keep NULL labels until the owner names them;
-- addressing by label therefore never matches an unnamed line.
CREATE UNIQUE INDEX phone_lines_account_label_key
    ON phone_lines (account_id, label)
    WHERE label IS NOT NULL;

-- A fallback target must live in the same account and must itself be an
-- activated, sealed line (checked here structurally; the routing decision
-- additionally requires its current binding to be active and approved).
ALTER TABLE phone_lines
    ADD CONSTRAINT phone_lines_fallback_same_account
        FOREIGN KEY (account_id, fallback_line_id)
        REFERENCES phone_lines (account_id, id);

-- A line may not nominate itself as its own fallback.
ALTER TABLE phone_lines
    ADD CONSTRAINT phone_lines_no_self_fallback
        CHECK (fallback_line_id IS NULL OR fallback_line_id <> id);

-- Mode changes are owner selections, not execution permission: bumping the
-- policy version only records the revision. Queue and fallback remain opt-in
-- per line; the server-side default refusal for a not-ready line with no
-- selection is implemented by not_ready_mode's 'ignore' default above.
