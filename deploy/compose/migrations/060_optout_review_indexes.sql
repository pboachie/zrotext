-- SPDX-License-Identifier: AGPL-3.0-only
-- The migrator prepares these changes outside its per-file transaction:
-- CREATE INDEX CONCURRENTLY for the review-queue and review-event indexes and
-- DROP INDEX CONCURRENTLY for the redundant active index. Keep this numbered
-- file as the durable, checksummed validation gate; it must not take a write
-- lock on live suppressions.
-- The owner opt-out review list, its cursor lookup and review decisions all
-- filter on review sources; the new partial indexes serve those pages without
-- reading the account's non-review suppressions. recipient_suppressions_active
-- repeated the primary key's columns and served no query the primary key
-- cannot, while adding a second index write to every suppression upsert.
CREATE FUNCTION optout_review_indexes_ready(expected_schema text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT
        EXISTS (
            SELECT 1 FROM pg_class idx
            JOIN pg_namespace ns ON ns.oid = idx.relnamespace
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_review_queue'
              AND pg_get_indexdef(idx.oid) =
                  'CREATE INDEX recipient_suppressions_review_queue ON ' || expected_schema ||
                  '.recipient_suppressions USING btree (account_id, changed_at DESC, recipient_e164 DESC)' ||
                  ' WHERE (active AND (source = ANY (ARRAY[''sms_review''::text, ''sms_unsolicited_review''::text])))'
        )
        AND EXISTS (
            SELECT 1 FROM pg_class idx
            JOIN pg_namespace ns ON ns.oid = idx.relnamespace
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_review_event'
              AND pg_get_indexdef(idx.oid) =
                  'CREATE INDEX recipient_suppressions_review_event ON ' || expected_schema ||
                  '.recipient_suppressions USING btree (account_id, COALESCE(source_event_id, source_unsolicited_event_id))' ||
                  ' WHERE (source = ANY (ARRAY[''sms_review''::text, ''sms_unsolicited_review''::text]))'
        )
        AND NOT EXISTS (
            SELECT 1 FROM pg_class idx
            JOIN pg_namespace ns ON ns.oid = idx.relnamespace
            WHERE ns.nspname = expected_schema
              AND idx.relname = 'recipient_suppressions_active'
        );
$$;

DO $$
BEGIN
    IF NOT optout_review_indexes_ready(current_schema()) THEN
        RAISE EXCEPTION 'opt-out review indexes are absent, invalid, or the redundant active index remains';
    END IF;
END;
$$;
