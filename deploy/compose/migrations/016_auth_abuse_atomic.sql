-- SPDX-License-Identifier: AGPL-3.0-only
-- Charge subject and route budgets as one database operation. A rejected
-- global charge rolls back its subject increment before returning to HTTP.
CREATE FUNCTION auth_abuse_consume(
    p_scope text,
    p_global_hash bytea,
    p_subject_hash bytea,
    p_global_max integer,
    p_global_seconds integer,
    p_subject_max integer,
    p_subject_seconds integer
) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_started timestamptz;
    v_attempts integer;
    v_allowed boolean;
BEGIN
    -- This read avoids inserting a new subject row for every request after a
    -- route is exhausted. The guarded global UPSERT below remains authoritative
    -- when requests race near the limit.
    SELECT window_started_at, attempts INTO v_started, v_attempts
    FROM auth_abuse_counters
    WHERE scope = p_scope AND subject_hash = p_global_hash;
    IF FOUND AND v_started > clock_timestamp() - make_interval(secs => p_global_seconds)
             AND v_attempts >= p_global_max THEN
        RETURN false;
    END IF;

    BEGIN
        IF p_subject_hash IS NOT NULL THEN
            v_allowed := false;
            INSERT INTO auth_abuse_counters(scope, subject_hash, window_started_at, attempts, updated_at)
            VALUES (p_scope, p_subject_hash, clock_timestamp(), 1, clock_timestamp())
            ON CONFLICT(scope, subject_hash) DO UPDATE SET
                window_started_at = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
                    THEN clock_timestamp() ELSE auth_abuse_counters.window_started_at END,
                attempts = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
                    THEN 1 ELSE auth_abuse_counters.attempts + 1 END,
                updated_at = clock_timestamp()
            WHERE auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
               OR auth_abuse_counters.attempts < p_subject_max
            RETURNING true INTO v_allowed;
            IF NOT COALESCE(v_allowed, false) THEN
                RETURN false;
            END IF;
        END IF;

        v_allowed := false;
        INSERT INTO auth_abuse_counters(scope, subject_hash, window_started_at, attempts, updated_at)
        VALUES (p_scope, p_global_hash, clock_timestamp(), 1, clock_timestamp())
        ON CONFLICT(scope, subject_hash) DO UPDATE SET
            window_started_at = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
                THEN clock_timestamp() ELSE auth_abuse_counters.window_started_at END,
            attempts = CASE WHEN auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
                THEN 1 ELSE auth_abuse_counters.attempts + 1 END,
            updated_at = clock_timestamp()
        WHERE auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
           OR auth_abuse_counters.attempts < p_global_max
        RETURNING true INTO v_allowed;
        IF NOT COALESCE(v_allowed, false) THEN
            IF p_subject_hash IS NOT NULL THEN
                RAISE EXCEPTION 'global budget exhausted' USING ERRCODE = 'ZX001';
            END IF;
            RETURN false;
        END IF;
        RETURN true;
    EXCEPTION WHEN SQLSTATE 'ZX001' THEN
        -- PostgreSQL rolls back this block's subject and global writes.
        RETURN false;
    END;
END;
$$;
