-- SPDX-License-Identifier: AGPL-3.0-only
-- Fresh disposable test cluster only. Run as its provisioning role, never as
-- an application role or against a service database. Existing objects refuse.
-- These controls previously used CI's privileged postgres fixture role. The
-- separate login below narrows their privileges; it receives no CREATEDB grant.
CREATE ROLE zt_registered_control LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
CREATE DATABASE zt_registered_empty OWNER zt_registered_control;
CREATE DATABASE zt_registered_mfa OWNER zt_registered_control;
-- No DROP, FORCE, backend termination or automatic unknown-outcome recovery.
