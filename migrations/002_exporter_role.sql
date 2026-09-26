-- Read-only login role for the Prometheus exporter (exporter/).
--
-- The exporter only ever reads scans and findings, so it connects as this
-- role rather than as the database owner: a bug or compromise in the
-- exporter cannot modify or delete scan history.
--
-- This file uses psql meta-commands (\getenv, \if) to read the password
-- from the environment, so it must be run with psql 15+ (the postgres:16
-- entrypoint does this automatically on an empty volume). By hand:
--
--   EXPORTER_DB_PASSWORD=... psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
--       -f migrations/002_exporter_role.sql

\getenv exporter_password EXPORTER_DB_PASSWORD
\if :{?exporter_password}
\else
    -- Fail loudly (psql exits non-zero under ON_ERROR_STOP) rather than
    -- create a login role with no password.
    DO $$ BEGIN RAISE EXCEPTION 'EXPORTER_DB_PASSWORD is not set'; END $$;
\endif

-- CREATE ROLE has no IF NOT EXISTS; roles are cluster-wide, so re-running
-- this migration (or running it against a second database) must not fail.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudsentinel_exporter') THEN
        CREATE ROLE cloudsentinel_exporter LOGIN;
    END IF;
END
$$;

ALTER ROLE cloudsentinel_exporter PASSWORD :'exporter_password';

-- The database name is not known statically; format(%I) quotes it safely.
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO cloudsentinel_exporter', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO cloudsentinel_exporter;
GRANT SELECT ON TABLE public.scans, public.findings TO cloudsentinel_exporter;
