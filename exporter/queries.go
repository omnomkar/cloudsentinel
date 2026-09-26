package main

// All SQL here is static: nothing from the environment or the HTTP request
// is ever interpolated. Table names are unqualified so they resolve through
// search_path (the integration test relies on this to use its own schema).

// rankedScansCTE numbers each (provider, account_id)'s scans newest-first.
// rn = 1 is the latest scan and rn = 2 the one before it. The ordering
// (started_at, then id as a tie-breaker) matches _LATEST_TWO_SCANS_SQL in
// scanner/db.py, so the exporter and `--diff` always compare the same scans.
const rankedScansCTE = `
WITH ranked AS (
    SELECT id, provider, account_id, started_at,
           row_number() OVER (PARTITION BY provider, account_id
                              ORDER BY started_at DESC, id DESC) AS rn
    FROM scans
)
`

const latestScansSQL = rankedScansCTE + `
SELECT provider, account_id, started_at
FROM ranked
WHERE rn = 1
`

const severityCountsSQL = rankedScansCTE + `
SELECT s.provider, s.account_id, f.severity, count(*)
FROM ranked s
JOIN findings f ON f.scan_id = s.id
WHERE s.rn = 1
GROUP BY s.provider, s.account_id, f.severity
`

// driftSQL counts findings that appeared or disappeared between the latest
// and previous scan. Like `--diff`, findings are matched on
// (check_id, resource_id) only, so a severity change on the same resource is
// not drift. Accounts with a single scan produce no row.
const driftSQL = rankedScansCTE + `
SELECT latest.provider, latest.account_id,
       (SELECT count(*) FROM (
            SELECT check_id, resource_id FROM findings WHERE scan_id = latest.id
            EXCEPT
            SELECT check_id, resource_id FROM findings WHERE scan_id = previous.id
        ) AS added) AS new,
       (SELECT count(*) FROM (
            SELECT check_id, resource_id FROM findings WHERE scan_id = previous.id
            EXCEPT
            SELECT check_id, resource_id FROM findings WHERE scan_id = latest.id
        ) AS removed) AS resolved
FROM ranked latest
JOIN ranked previous
  ON previous.provider = latest.provider
 AND previous.account_id = latest.account_id
 AND previous.rn = 2
WHERE latest.rn = 1
`
