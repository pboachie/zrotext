-- SPDX-License-Identifier: AGPL-3.0-only
-- Default-disabled original-session typed proposal issuance prerequisite.
-- Public packets never grant signing, phone consent, capture or dispatch.
CREATE TABLE owner_android_proposals (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind smallint NOT NULL CHECK(kind IN (3,4,5)),
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    proposal_sha256 bytea NOT NULL CHECK(octet_length(proposal_sha256)=32),
    proposal bytea NOT NULL CHECK(octet_length(proposal) BETWEEN 1 AND 20480),
    expected_context jsonb NOT NULL CHECK(jsonb_typeof(expected_context)='object' AND pg_column_size(expected_context)<=8192),
    origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 512),
    root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
    checkpoint_version bigint NOT NULL CHECK(checkpoint_version>=0),
    checkpoint_digest bytea CHECK(octet_length(checkpoint_digest)=32),
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK(binding_generation>0),
    peer text NOT NULL CHECK(peer ~ '^\+[1-9][0-9]{1,14}$'),
    paired_fingerprint bytea NOT NULL CHECK(octet_length(paired_fingerprint)=32),
    connection_epoch bigint NOT NULL CHECK(connection_epoch>0),
    deployment_epoch bigint NOT NULL CHECK(deployment_epoch>0),
    site_id text NOT NULL CHECK(octet_length(site_id) BETWEEN 1 AND 64),
    instance_id text NOT NULL CHECK(octet_length(instance_id) BETWEEN 1 AND 64),
    interval_id uuid,
    issued_ms bigint NOT NULL CHECK(issued_ms>0),
    expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
    PRIMARY KEY(account_id,kind),
    FOREIGN KEY(account_id,session_id) REFERENCES sessions(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,user_id) REFERENCES memberships(account_id,user_id),
    FOREIGN KEY(account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation),
    CHECK((kind=3 AND checkpoint_version=0 AND checkpoint_digest IS NULL AND interval_id IS NULL)
       OR (kind=4 AND checkpoint_version>0 AND checkpoint_digest IS NOT NULL AND interval_id IS NULL)
       OR (kind=5 AND checkpoint_version>0 AND checkpoint_digest IS NOT NULL AND interval_id IS NOT NULL))
);
CREATE INDEX owner_android_proposals_expiry ON owner_android_proposals(expires_ms);
CREATE INDEX owner_android_proposals_session ON owner_android_proposals(account_id,session_id);
CREATE INDEX owner_android_proposals_owner ON owner_android_proposals(account_id,user_id);
CREATE INDEX owner_android_proposals_binding
    ON owner_android_proposals(account_id,line_id,device_id,binding_generation);

-- A pending intent is immutable. Explicit expiry/cancellation removes it; no
-- UPDATE can rewrite an old packet, expected selection, checkpoint or deadline.
CREATE FUNCTION reject_owner_android_proposal_update() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owner proposal is immutable'; END; $$;
CREATE TRIGGER owner_android_proposals_immutable BEFORE UPDATE ON owner_android_proposals
FOR EACH ROW EXECUTE FUNCTION reject_owner_android_proposal_update();
