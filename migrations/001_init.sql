-- CloudSentinel schema, v1.
--
-- Applied automatically by the postgres container on first startup (mounted
-- into /docker-entrypoint-initdb.d). That hook only runs against an empty
-- data volume, so later migrations must be applied by hand.

CREATE TABLE IF NOT EXISTS scans (
    id          BIGSERIAL   PRIMARY KEY,
    provider    TEXT        NOT NULL CHECK (provider IN ('aws', 'azure')),
    account_id  TEXT        NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only FAIL findings are persisted (the aggregator drops PASS results), so
-- there is no status column. cis_control is nullable because some checks
-- intentionally have no CIS mapping (see CIS_MAPPING in scanner/reporter.py).
CREATE TABLE IF NOT EXISTS findings (
    id             BIGSERIAL PRIMARY KEY,
    scan_id        BIGINT    NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    check_id       TEXT      NOT NULL,
    check_name     TEXT      NOT NULL,
    cis_control    TEXT,
    severity       TEXT      NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    resource_id    TEXT      NOT NULL,
    resource_type  TEXT      NOT NULL,
    region         TEXT      NOT NULL,
    details        JSONB     NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (scan_id, check_id, resource_id)
);

-- Cross-scan history of one finding ("since when has this SG had SSH open?").
-- The UNIQUE index above leads with scan_id, so it cannot serve that lookup.
CREATE INDEX IF NOT EXISTS findings_check_resource_idx ON findings (check_id, resource_id);

CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);

-- Finding the latest / previous scan for a provider + account (--diff).
CREATE INDEX IF NOT EXISTS scans_provider_account_idx ON scans (provider, account_id, started_at DESC);
