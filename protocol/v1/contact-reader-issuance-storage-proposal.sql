-- SPDX-License-Identifier: AGPL-3.0-only
-- UNNUMBERED / UNINSTALLED proposal. There is deliberately no aggregate seed.
-- An extant row alone is not independent genesis or rollback/restore admission.
CREATE FUNCTION contact_reader_state_bounds_valid(account_id uuid,root_pin bytea,root_fingerprint bytea,trust_generation bigint,allocation_generation bigint,mutation_revision bigint,last_mutation_ms bigint,receipt_next_slot smallint,phase text,current_authorization uuid,current_generation bigint,current_statement_digest bytea,current_statement bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_state_bounds_body$
 SELECT COALESCE((
  account_id <> '00000000-0000-0000-0000-000000000000'::uuid
  AND octet_length(root_pin)=94 AND octet_length(root_fingerprint)=32
  AND root_fingerprint<>decode(repeat('00',32),'hex') AND trust_generation=1
  AND allocation_generation>=0 AND mutation_revision>=0 AND last_mutation_ms>0
  AND receipt_next_slot BETWEEN 0 AND 31
 ),false)
$contact_reader_state_bounds_body$;
CREATE FUNCTION contact_reader_state_shape_valid(account_id uuid,root_pin bytea,root_fingerprint bytea,trust_generation bigint,allocation_generation bigint,mutation_revision bigint,last_mutation_ms bigint,receipt_next_slot smallint,phase text,current_authorization uuid,current_generation bigint,current_statement_digest bytea,current_statement bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_state_shape_body$
 SELECT COALESCE((
  (phase='EMPTY' AND current_authorization IS NULL AND current_generation IS NULL
   AND current_statement_digest IS NULL AND current_statement IS NULL)
  OR (phase IN ('ACTIVE','WITHDRAWN') AND current_authorization IS NOT NULL
   AND current_authorization<>'00000000-0000-0000-0000-000000000000'::uuid
   AND current_generation IS NOT NULL AND current_generation>0 AND current_generation<=allocation_generation
   AND current_statement_digest IS NOT NULL AND octet_length(current_statement_digest)=32
   AND current_statement_digest<>decode(repeat('00',32),'hex')
   AND ((phase='ACTIVE' AND current_statement IS NOT NULL AND octet_length(current_statement) BETWEEN 314 AND 817)
    OR (phase='WITHDRAWN' AND current_statement IS NULL)))
 ),false)
$contact_reader_state_shape_body$;
CREATE FUNCTION contact_reader_pending_bounds_valid(account_id uuid,slot smallint,authorization uuid,generation bigint,create_request uuid,created_by_user uuid,created_session uuid,origin text,create_input_digest bytea,creation_expected_revision bigint,allocated_revision bigint,prior_phase text,prior_authorization uuid,prior_generation bigint,prior_digest bytea,requested_until_ms bigint,unsigned bytea,unsigned_digest bytea,manifest bytea,manifest_version bigint,manifest_digest bytea,reader_id bytea,root_writer_id bytea,reader_point bytea,root_point bytea,reader_from bigint,root_from bigint,reader_until bigint,root_until bigint,manifest_issued bigint,manifest_until bigint,creation_observed_ms bigint,issued bigint,expires bigint,until_ms bigint) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_pending_bounds_body$
 SELECT COALESCE((
  slot BETWEEN 0 AND 3 AND authorization<>'00000000-0000-0000-0000-000000000000'::uuid
  AND create_request<>'00000000-0000-0000-0000-000000000000'::uuid
  AND created_by_user<>'00000000-0000-0000-0000-000000000000'::uuid
  AND created_session<>'00000000-0000-0000-0000-000000000000'::uuid
  AND generation>0 AND creation_expected_revision>=0 AND allocated_revision>0
  AND creation_expected_revision<9223372036854775807 AND allocated_revision::numeric=creation_expected_revision::numeric+1
  AND octet_length(origin) BETWEEN 9 AND 512 AND origin !~ '[^!-~]'
  AND octet_length(unsigned)=241+octet_length(origin)
  AND octet_length(manifest) BETWEEN 364 AND 9751 AND manifest_version>0
  AND octet_length(create_input_digest)=32 AND create_input_digest<>decode(repeat('00',32),'hex')
  AND octet_length(unsigned_digest)=32 AND unsigned_digest<>decode(repeat('00',32),'hex')
  AND octet_length(manifest_digest)=32 AND manifest_digest<>decode(repeat('00',32),'hex')
  AND octet_length(reader_id)=32 AND reader_id<>decode(repeat('00',32),'hex')
  AND octet_length(root_writer_id)=32 AND root_writer_id<>decode(repeat('00',32),'hex')
  AND octet_length(reader_point)=65 AND get_byte(reader_point,0)=4
  AND octet_length(root_point)=65 AND get_byte(root_point,0)=4
  AND reader_from>=0 AND root_from>=0 AND reader_until>0 AND root_until>0
  AND manifest_issued>0 AND manifest_until>manifest_issued AND creation_observed_ms>0
  AND creation_observed_ms>=manifest_issued AND issued>=creation_observed_ms
  AND issued>=reader_from AND issued>=root_from
  AND issued<expires AND expires-issued<=300000
  AND issued<until_ms AND until_ms-issued<=86400000
  AND until_ms=requested_until_ms AND until_ms<=manifest_until AND until_ms<=reader_until AND until_ms<=root_until
 ),false)
$contact_reader_pending_bounds_body$;
CREATE FUNCTION contact_reader_pending_prior_valid(account_id uuid,slot smallint,authorization uuid,generation bigint,create_request uuid,created_by_user uuid,created_session uuid,origin text,create_input_digest bytea,creation_expected_revision bigint,allocated_revision bigint,prior_phase text,prior_authorization uuid,prior_generation bigint,prior_digest bytea,requested_until_ms bigint,unsigned bytea,unsigned_digest bytea,manifest bytea,manifest_version bigint,manifest_digest bytea,reader_id bytea,root_writer_id bytea,reader_point bytea,root_point bytea,reader_from bigint,root_from bigint,reader_until bigint,root_until bigint,manifest_issued bigint,manifest_until bigint,creation_observed_ms bigint,issued bigint,expires bigint,until_ms bigint) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_pending_prior_body$
 SELECT COALESCE((
  (prior_phase='EMPTY' AND prior_authorization IS NULL AND prior_generation IS NULL AND prior_digest IS NULL)
  OR (prior_phase IN ('ACTIVE','WITHDRAWN') AND prior_authorization IS NOT NULL
   AND prior_authorization<>'00000000-0000-0000-0000-000000000000'::uuid
   AND prior_generation IS NOT NULL AND prior_generation>0
   AND prior_digest IS NOT NULL AND octet_length(prior_digest)=32 AND prior_digest<>decode(repeat('00',32),'hex'))
 ),false)
$contact_reader_pending_prior_body$;
CREATE FUNCTION contact_reader_receipts_bounds_valid(account_id uuid,slot smallint,authorization uuid,generation bigint,create_request uuid,create_input_digest bytea,creation_expected_revision bigint,unsigned_digest bytea,terminal_kind text,terminal_ms bigint,signed_statement bytea,statement_digest bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_receipts_bounds_body$
 SELECT COALESCE((
  slot BETWEEN 0 AND 31 AND authorization<>'00000000-0000-0000-0000-000000000000'::uuid
  AND create_request<>'00000000-0000-0000-0000-000000000000'::uuid
  AND generation>0 AND creation_expected_revision>=0 AND terminal_ms>0
  AND octet_length(create_input_digest)=32 AND create_input_digest<>decode(repeat('00',32),'hex')
  AND octet_length(unsigned_digest)=32 AND unsigned_digest<>decode(repeat('00',32),'hex')
 ),false)
$contact_reader_receipts_bounds_body$;
CREATE FUNCTION contact_reader_receipts_shape_valid(account_id uuid,slot smallint,authorization uuid,generation bigint,create_request uuid,create_input_digest bytea,creation_expected_revision bigint,unsigned_digest bytea,terminal_kind text,terminal_ms bigint,signed_statement bytea,statement_digest bytea) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $contact_reader_receipts_shape_body$
 SELECT COALESCE((
  (terminal_kind='COMPLETED' AND signed_statement IS NOT NULL AND octet_length(signed_statement) BETWEEN 314 AND 817
   AND statement_digest IS NOT NULL AND octet_length(statement_digest)=32 AND statement_digest<>decode(repeat('00',32),'hex'))
  OR (terminal_kind IN ('CANCELLED','EXPIRED') AND signed_statement IS NULL AND statement_digest IS NULL)
 ),false)
$contact_reader_receipts_shape_body$;

CREATE TABLE contact_reader_state (
 account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 root_pin bytea NOT NULL,
 root_fingerprint bytea NOT NULL,
 trust_generation bigint NOT NULL,
 allocation_generation bigint NOT NULL,
 mutation_revision bigint NOT NULL,
 last_mutation_ms bigint NOT NULL,
 receipt_next_slot smallint NOT NULL,
 phase text NOT NULL,
 current_authorization uuid,
 current_generation bigint,
 current_statement_digest bytea,
 current_statement bytea,
 CONSTRAINT contact_reader_state_bounds CHECK (contact_reader_state_bounds_valid(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase,current_authorization,current_generation,current_statement_digest,current_statement)),
 CONSTRAINT contact_reader_state_shape CHECK (contact_reader_state_shape_valid(account_id,root_pin,root_fingerprint,trust_generation,allocation_generation,mutation_revision,last_mutation_ms,receipt_next_slot,phase,current_authorization,current_generation,current_statement_digest,current_statement))
);
CREATE TABLE contact_reader_pending (
 account_id uuid NOT NULL REFERENCES contact_reader_state(account_id) ON DELETE CASCADE,
 slot smallint NOT NULL,
 authorization uuid NOT NULL,
 generation bigint NOT NULL,
 create_request uuid NOT NULL,
 created_by_user uuid NOT NULL,
 created_session uuid NOT NULL,
 origin text NOT NULL,
 create_input_digest bytea NOT NULL,
 creation_expected_revision bigint NOT NULL,
 allocated_revision bigint NOT NULL,
 prior_phase text NOT NULL,
 prior_authorization uuid,
 prior_generation bigint,
 prior_digest bytea,
 requested_until_ms bigint NOT NULL,
 unsigned bytea NOT NULL,
 unsigned_digest bytea NOT NULL,
 manifest bytea NOT NULL,
 manifest_version bigint NOT NULL,
 manifest_digest bytea NOT NULL,
 reader_id bytea NOT NULL,
 root_writer_id bytea NOT NULL,
 reader_point bytea NOT NULL,
 root_point bytea NOT NULL,
 reader_from bigint NOT NULL,
 root_from bigint NOT NULL,
 reader_until bigint NOT NULL,
 root_until bigint NOT NULL,
 manifest_issued bigint NOT NULL,
 manifest_until bigint NOT NULL,
 creation_observed_ms bigint NOT NULL,
 issued bigint NOT NULL,
 expires bigint NOT NULL,
 until_ms bigint NOT NULL,
 PRIMARY KEY(account_id,slot),
 UNIQUE(account_id,authorization), UNIQUE(account_id,generation), UNIQUE(account_id,create_request),
 CONSTRAINT contact_reader_pending_bounds CHECK (contact_reader_pending_bounds_valid(account_id,slot,authorization,generation,create_request,created_by_user,created_session,origin,create_input_digest,creation_expected_revision,allocated_revision,prior_phase,prior_authorization,prior_generation,prior_digest,requested_until_ms,unsigned,unsigned_digest,manifest,manifest_version,manifest_digest,reader_id,root_writer_id,reader_point,root_point,reader_from,root_from,reader_until,root_until,manifest_issued,manifest_until,creation_observed_ms,issued,expires,until_ms)),
 CONSTRAINT contact_reader_pending_prior CHECK (contact_reader_pending_prior_valid(account_id,slot,authorization,generation,create_request,created_by_user,created_session,origin,create_input_digest,creation_expected_revision,allocated_revision,prior_phase,prior_authorization,prior_generation,prior_digest,requested_until_ms,unsigned,unsigned_digest,manifest,manifest_version,manifest_digest,reader_id,root_writer_id,reader_point,root_point,reader_from,root_from,reader_until,root_until,manifest_issued,manifest_until,creation_observed_ms,issued,expires,until_ms))
);
CREATE TABLE contact_reader_receipts (
 account_id uuid NOT NULL REFERENCES contact_reader_state(account_id) ON DELETE CASCADE,
 slot smallint NOT NULL,
 authorization uuid NOT NULL,
 generation bigint NOT NULL,
 create_request uuid NOT NULL,
 create_input_digest bytea NOT NULL,
 creation_expected_revision bigint NOT NULL,
 unsigned_digest bytea NOT NULL,
 terminal_kind text NOT NULL,
 terminal_ms bigint NOT NULL,
 signed_statement bytea,
 statement_digest bytea,
 PRIMARY KEY(account_id,slot),
 UNIQUE(account_id,authorization), UNIQUE(account_id,generation), UNIQUE(account_id,create_request),
 CONSTRAINT contact_reader_receipts_bounds CHECK (contact_reader_receipts_bounds_valid(account_id,slot,authorization,generation,create_request,create_input_digest,creation_expected_revision,unsigned_digest,terminal_kind,terminal_ms,signed_statement,statement_digest)),
 CONSTRAINT contact_reader_receipts_shape CHECK (contact_reader_receipts_shape_valid(account_id,slot,authorization,generation,create_request,create_input_digest,creation_expected_revision,unsigned_digest,terminal_kind,terminal_ms,signed_statement,statement_digest))
);

CREATE FUNCTION contact_reader_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $state_guard$
DECLARE same_current boolean; withdrawing boolean; advancing boolean; reducing boolean;
BEGIN
 IF ROW(NEW.account_id,NEW.root_pin,NEW.root_fingerprint,NEW.trust_generation)
   IS DISTINCT FROM ROW(OLD.account_id,OLD.root_pin,OLD.root_fingerprint,OLD.trust_generation)
   OR NEW.last_mutation_ms<OLD.last_mutation_ms THEN RAISE EXCEPTION 'contact state identity'; END IF;
 same_current:=ROW(NEW.phase,NEW.current_authorization,NEW.current_generation,NEW.current_statement_digest,NEW.current_statement)
   IS NOT DISTINCT FROM ROW(OLD.phase,OLD.current_authorization,OLD.current_generation,OLD.current_statement_digest,OLD.current_statement);
 withdrawing:=OLD.phase='ACTIVE' AND NEW.phase='WITHDRAWN'
   AND ROW(NEW.current_authorization,NEW.current_generation,NEW.current_statement_digest)
   IS NOT DISTINCT FROM ROW(OLD.current_authorization,OLD.current_generation,OLD.current_statement_digest)
   AND NEW.current_statement IS NULL AND NEW.receipt_next_slot=OLD.receipt_next_slot;
 advancing:=OLD.mutation_revision<9223372036854775807 AND NEW.mutation_revision::numeric=OLD.mutation_revision::numeric+1;
 reducing:=withdrawing OR (same_current AND NEW.receipt_next_slot=(OLD.receipt_next_slot+1)%32);
 IF NEW.allocation_generation=OLD.allocation_generation THEN
  IF (advancing OR (OLD.mutation_revision=9223372036854775807 AND NEW.mutation_revision=OLD.mutation_revision AND reducing))
   AND (reducing OR (advancing AND NEW.phase='ACTIVE'
     AND NEW.current_generation>COALESCE(OLD.current_generation,0)
     AND NEW.receipt_next_slot=(OLD.receipt_next_slot+1)%32)) THEN RETURN NEW; END IF;
 ELSIF OLD.allocation_generation<9223372036854775807
   AND NEW.allocation_generation::numeric=OLD.allocation_generation::numeric+1 AND advancing
   AND same_current AND NEW.receipt_next_slot=OLD.receipt_next_slot THEN RETURN NEW;
 END IF;
 RAISE EXCEPTION 'contact state transition';
END
$state_guard$;
CREATE TRIGGER contact_reader_state_transition BEFORE UPDATE ON contact_reader_state
FOR EACH ROW EXECUTE FUNCTION contact_reader_state_guard();

CREATE FUNCTION contact_reader_pending_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $pending_guard$
BEGIN
 RAISE EXCEPTION 'contact pending is immutable';
END
$pending_guard$;
CREATE TRIGGER contact_reader_pending_immutable BEFORE UPDATE ON contact_reader_pending
FOR EACH ROW EXECUTE FUNCTION contact_reader_pending_guard();

-- Deferred checks permit state->pending insert and terminal state->pending
-- delete->receipt replacement within the same transaction. They also inspect
-- surviving children after a parent update. Deletion itself remains erasable.
CREATE FUNCTION contact_reader_closure_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $closure_guard$
DECLARE a uuid; s contact_reader_state%ROWTYPE;
BEGIN
 a:=COALESCE(NEW.account_id,OLD.account_id);
 SELECT * INTO s FROM contact_reader_state WHERE account_id=a;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM contact_reader_pending p WHERE p.account_id=a
   AND (p.generation>s.allocation_generation OR p.allocated_revision>s.mutation_revision
    OR p.creation_observed_ms>s.last_mutation_ms OR p.prior_generation>=p.generation
    OR p.reader_id=decode(repeat('00',32),'hex')))
  OR EXISTS(SELECT 1 FROM contact_reader_receipts r WHERE r.account_id=a
   AND (r.generation>s.allocation_generation OR r.terminal_ms>s.last_mutation_ms))
  OR EXISTS(SELECT 1 FROM contact_reader_pending p JOIN contact_reader_receipts r ON r.account_id=p.account_id
   WHERE p.account_id=a AND (p.authorization=r.authorization OR p.generation=r.generation OR p.create_request=r.create_request))
  OR EXISTS(SELECT 1 FROM contact_reader_pending p WHERE p.account_id=a
   AND (p.authorization=s.current_authorization OR p.generation=s.current_generation))
  THEN RAISE EXCEPTION 'contact cross-row closure'; END IF;
 RETURN NULL;
END
$closure_guard$;
CREATE CONSTRAINT TRIGGER contact_reader_state_closure AFTER INSERT OR UPDATE ON contact_reader_state
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contact_reader_closure_guard();
CREATE CONSTRAINT TRIGGER contact_reader_pending_closure AFTER INSERT OR DELETE ON contact_reader_pending
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contact_reader_closure_guard();
CREATE CONSTRAINT TRIGGER contact_reader_receipts_closure AFTER INSERT OR UPDATE OR DELETE ON contact_reader_receipts
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contact_reader_closure_guard();
