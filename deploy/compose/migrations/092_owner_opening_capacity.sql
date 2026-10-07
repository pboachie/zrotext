-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-confirmed single-opening capacity tables, promoted from the
-- migration-candidates draft (092 is the next free number after 091;
-- renumber before merge if another migration lands first). Installed by
-- the production migrator and disposable test fixtures alike.

CREATE TABLE workflow_openings (
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
  definition_version bigint NOT NULL CHECK (definition_version > 0),
  state_version bigint NOT NULL CHECK (state_version > 0),
  capacity smallint NOT NULL CHECK (capacity BETWEEN 1 AND 100),
  phase text NOT NULL CHECK (phase IN ('open','closed','cancelled')),
  description_context_id uuid,
  description_revision bigint CHECK (description_revision BETWEEN 1 AND 128),
  description_digest bytea CHECK (octet_length(description_digest) = 32),
  decision_deadline_ms bigint CHECK (decision_deadline_ms > 0),
  created_by_user uuid,
  created_session uuid,
  created_ms bigint CHECK (created_ms > 0),
  PRIMARY KEY (account_id,id),
  FOREIGN KEY (account_id,description_context_id)
    REFERENCES workflow_contexts(account_id,id),
  CHECK ((description_context_id IS NULL) = (description_revision IS NULL)),
  CHECK ((description_context_id IS NULL) = (description_digest IS NULL)),
  CHECK ((description_context_id IS NULL) = (decision_deadline_ms IS NULL)),
  CHECK (phase <> 'open' OR (description_context_id IS NOT NULL AND decision_deadline_ms IS NOT NULL)),
  CHECK ((description_context_id IS NULL) = (created_by_user IS NULL)),
  CHECK ((description_context_id IS NULL) = (created_session IS NULL)),
  CHECK ((description_context_id IS NULL) = (created_ms IS NULL)),
  CHECK (decision_deadline_ms IS NULL OR created_ms < decision_deadline_ms)
);

CREATE TABLE workflow_opening_offers (
  account_id uuid NOT NULL,
  id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
  opening_id uuid NOT NULL,
  opening_definition_version bigint NOT NULL CHECK (opening_definition_version > 0),
  state_version bigint NOT NULL CHECK (state_version > 0),
  phase text NOT NULL CHECK (phase IN ('active','closed','withdrawn','cancelled','expired')),
  binding_scrubbed boolean NOT NULL DEFAULT false,
  contact_identity uuid,
  current_contact_id uuid,
  purpose text CHECK (purpose IN ('transactional','operational','marketing')),
  consent_episode_id uuid,
  context_id uuid,
  context_revision bigint CHECK (context_revision BETWEEN 1 AND 128),
  context_digest bytea CHECK (octet_length(context_digest) = 32),
  issued_ms bigint CHECK (issued_ms > 0),
  expires_ms bigint CHECK (expires_ms > issued_ms),
  created_by_user uuid,
  created_session uuid,
  PRIMARY KEY (account_id,id),
  UNIQUE (account_id,opening_id,id),
  FOREIGN KEY (account_id,opening_id) REFERENCES workflow_openings(account_id,id)
    ON DELETE CASCADE,
  FOREIGN KEY (account_id,current_contact_id) REFERENCES contacts(account_id,id),
  FOREIGN KEY (account_id,context_id) REFERENCES workflow_contexts(account_id,id),
  CHECK (current_contact_id IS NULL OR current_contact_id = contact_identity),
  CHECK (
    (NOT binding_scrubbed AND contact_identity IS NOT NULL AND current_contact_id IS NOT NULL
      AND purpose IS NOT NULL AND consent_episode_id IS NOT NULL AND context_id IS NOT NULL
      AND context_revision IS NOT NULL AND context_digest IS NOT NULL
      AND issued_ms IS NOT NULL AND expires_ms IS NOT NULL
      AND created_by_user IS NOT NULL AND created_session IS NOT NULL)
    OR
    (binding_scrubbed AND phase <> 'active' AND contact_identity IS NULL AND current_contact_id IS NULL
      AND purpose IS NULL AND consent_episode_id IS NULL AND context_id IS NULL
      AND context_revision IS NULL AND context_digest IS NULL
      AND issued_ms IS NULL AND expires_ms IS NULL
      AND created_by_user IS NULL AND created_session IS NULL)
  )
);

CREATE TABLE workflow_opening_allocations (
  account_id uuid NOT NULL,
  id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
  opening_id uuid NOT NULL,
  binding_scrubbed boolean NOT NULL DEFAULT false,
  offer_id uuid,
  offer_state_version bigint CHECK (offer_state_version > 0),
  contact_identity uuid,
  event_id uuid,
  event_digest bytea CHECK (octet_length(event_digest) = 32),
  response_use_digest bytea NOT NULL CHECK (octet_length(response_use_digest) = 32),
  observed_ms bigint CHECK (observed_ms > 0),
  accepted_ms bigint CHECK (accepted_ms >= observed_ms),
  decision_deadline_ms bigint CHECK (decision_deadline_ms > accepted_ms),
  phase text NOT NULL CHECK (phase IN ('pending','confirmed','released','cancelled','expired')),
  state_version bigint NOT NULL CHECK (state_version > 0),
  reserved_by_user uuid,
  reserved_session uuid,
  confirmed_by_user uuid,
  confirmed_session uuid,
  confirmed_ms bigint,
  PRIMARY KEY (account_id,id),
  UNIQUE (account_id,response_use_digest),
  FOREIGN KEY (account_id,opening_id,offer_id)
    REFERENCES workflow_opening_offers(account_id,opening_id,id),
  FOREIGN KEY (account_id,opening_id) REFERENCES workflow_openings(account_id,id)
    ON DELETE CASCADE,
  CHECK ((confirmed_by_user IS NULL) = (confirmed_session IS NULL)),
  CHECK ((confirmed_by_user IS NULL) = (confirmed_ms IS NULL)),
  CHECK (
    (NOT binding_scrubbed AND offer_id IS NOT NULL AND offer_state_version IS NOT NULL
      AND contact_identity IS NOT NULL AND event_id IS NOT NULL AND event_digest IS NOT NULL
      AND observed_ms IS NOT NULL AND accepted_ms IS NOT NULL AND decision_deadline_ms IS NOT NULL
      AND reserved_by_user IS NOT NULL AND reserved_session IS NOT NULL
      AND (phase <> 'confirmed' OR confirmed_ms IS NOT NULL))
    OR
    (binding_scrubbed AND phase <> 'pending' AND offer_id IS NULL AND offer_state_version IS NULL
      AND contact_identity IS NULL AND event_id IS NULL AND event_digest IS NULL
      AND observed_ms IS NULL AND accepted_ms IS NULL AND decision_deadline_ms IS NULL
      AND reserved_by_user IS NULL AND reserved_session IS NULL
      AND confirmed_by_user IS NULL AND confirmed_session IS NULL AND confirmed_ms IS NULL)
  )
);

CREATE INDEX workflow_opening_capacity_count
  ON workflow_opening_allocations(account_id,opening_id,phase);
CREATE INDEX workflow_opening_contact_lifecycle
  ON workflow_opening_offers(account_id,contact_identity,purpose,opening_id);
CREATE INDEX workflow_opening_source_lifecycle
  ON workflow_opening_offers(account_id,context_id,opening_id);

CREATE TABLE workflow_opening_requests (
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  request_id uuid NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
  opening_id uuid NOT NULL,
  redacted boolean NOT NULL DEFAULT false,
  admission_charged boolean NOT NULL DEFAULT true,
  subject_kind smallint CHECK (subject_kind BETWEEN 1 AND 3),
  subject_id uuid,
  operation smallint CHECK (operation BETWEEN 1 AND 9),
  request_digest bytea CHECK (octet_length(request_digest) = 32),
  result bytea CHECK (octet_length(result) BETWEEN 1 AND 32768),
  actor_user_id uuid,
  actor_session_id uuid,
  committed_ms bigint CHECK (committed_ms > 0),
  PRIMARY KEY (account_id,request_id),
  FOREIGN KEY (account_id,opening_id) REFERENCES workflow_openings(account_id,id)
    ON DELETE CASCADE,
  CHECK (
    (NOT redacted AND subject_kind IS NOT NULL AND subject_id IS NOT NULL
      AND operation IS NOT NULL AND request_digest IS NOT NULL AND result IS NOT NULL
      AND actor_user_id IS NOT NULL AND actor_session_id IS NOT NULL AND committed_ms IS NOT NULL)
    OR
    (redacted AND subject_kind IS NULL AND subject_id IS NULL
      AND operation IS NULL AND request_digest IS NULL AND result IS NULL
      AND actor_user_id IS NULL AND actor_session_id IS NULL AND committed_ms IS NULL)
  )
);

CREATE INDEX workflow_opening_request_subject
  ON workflow_opening_requests(account_id,subject_kind,subject_id);

-- Active count ceilings belong in the same account/opening-locked transaction.
-- No trigger asserts opaque text meaning or invents current owner authority.
-- Hook obligations before deleting parents:
-- contact: scrub related offer/allocation bindings + request receipts fully;
--          pending becomes terminal, confirmed phase still occupies one unit.
-- context: close new admission and fully scrub exact affected bindings;
--          description tuple=NULL if it is that exact erased context.
-- account: delete requests, allocations, offers, openings child-first.
-- No physical opening-ID purge endpoint in the first slice; minimal opaque
-- creation/response-use/occupied-unit fences prevent stale identity reuse.
-- Same-transaction lifecycle hooks scrub all authority bindings and receipt payloads.
-- Only increasing requests are checked against the 8192 lifetime admitted
-- receipt ceiling. Retained redacted receipts keep admission_charged unchanged.
-- Release/cancel/privacy erase never check that ceiling. A source-created
-- opening, offer or allocation each consumes one charged creation receipt.
-- Opening open->closed preserves confirmed occupancy; an explicit owner
-- closed->cancelled can subsequently release it. Allow at most TWO monotone
-- reductions per created object; allocation release/cancel from already-free
-- states returns status, never reopens or inserts another receipt. Internal lifecycle/erasure/expiry
-- hooks do not insert a per-object request receipt. Already-terminal owner
-- requests return explicit current-status/no-mutation/no-receipt outcomes;
-- arbitrary new UUIDs do not append rows or reserve a global request identity.
-- Total charged+uncharged request rows <= 3*8192 = 24576 through this API.
-- Ordinary checked increments refuse MAX. Irreversible terminal reductions
-- use CASE WHEN version=9223372036854775807 THEN version ELSE version+1 END;
-- never evaluate version+1 at MAX and never use saturation to reopen authority.
