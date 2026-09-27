-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant candidate-02 storage. No route or runtime gate is enabled here.
-- Retain profile after content purge, so legacy metadata constraints stay exact.
ALTER TABLE sealed_inbound_events ADD COLUMN envelope_profile smallint NOT NULL DEFAULT 1
    CHECK (envelope_profile IN (1,2));
ALTER TABLE sealed_inbound_events ALTER COLUMN part_count DROP NOT NULL;
ALTER TABLE sealed_inbound_events DROP CONSTRAINT sealed_inbound_events_part_count_check;
ALTER TABLE sealed_inbound_events ADD CONSTRAINT sealed_inbound_events_part_count_check CHECK (
    (envelope_profile=1 AND part_count IS NOT NULL AND part_count BETWEEN 1 AND 6) OR
    (envelope_profile=2 AND part_count IS NULL)
);
ALTER TABLE sealed_inbound_events DROP CONSTRAINT sealed_inbound_events_envelope_check;
ALTER TABLE sealed_inbound_events ADD CONSTRAINT sealed_inbound_events_envelope_check CHECK (
    envelope IS NULL OR (octet_length(envelope) BETWEEN 426 AND 34082 AND
      ((envelope_profile=1 AND substring(envelope from 1 for 6)=decode('5a5453450102','hex')) OR
       (envelope_profile=2 AND substring(envelope from 1 for 6)=decode('5a5453450202','hex'))))
);
-- Candidate02 has no signed part-count field. NULL means unknown; it is never
-- inferred from ciphertext length or replaced with a fabricated segment count.
-- Existing immutable/purge-only triggers compare the complete row, including
-- this new profile. Preserve event/sequence/digest tombstones on ciphertext purge.
