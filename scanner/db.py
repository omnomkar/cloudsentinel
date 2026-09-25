import json
from functools import partial
from typing import Dict, List, Optional

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from scanner import Finding
from scanner.reporter import CIS_MAPPING


# Finding.details can hold values json.dumps can't serialize natively
# (e.g. datetimes); stringify them the same way the JSON reporter does.
_dumps = partial(json.dumps, default=str)

_INSERT_SCAN_SQL = """
    INSERT INTO scans (provider, account_id)
    VALUES (%s, %s)
    RETURNING id
"""

_INSERT_FINDING_SQL = """
    INSERT INTO findings
        (scan_id, check_id, check_name, cis_control, severity,
         resource_id, resource_type, region, details)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

_LATEST_TWO_SCANS_SQL = """
    SELECT id
    FROM scans
    WHERE provider = %(provider)s AND account_id = %(account_id)s
    ORDER BY started_at DESC, id DESC
    LIMIT 2
"""

# Drift is keyed on (check_id, resource_id) only: a severity change on the
# same resource is still the same open finding. Each set operation yields
# the matching keys, which are joined back to one scan's rows for display.
_DIFF_SQL = {
    "new": """
        SELECT f.check_id, f.resource_id, f.severity, f.cis_control
        FROM findings f
        JOIN (
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(latest)s
            EXCEPT
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(previous)s
        ) k USING (check_id, resource_id)
        WHERE f.scan_id = %(latest)s
        ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], f.severity),
                 f.check_id, f.resource_id
    """,
    "resolved": """
        SELECT f.check_id, f.resource_id, f.severity, f.cis_control
        FROM findings f
        JOIN (
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(previous)s
            EXCEPT
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(latest)s
        ) k USING (check_id, resource_id)
        WHERE f.scan_id = %(previous)s
        ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], f.severity),
                 f.check_id, f.resource_id
    """,
    "still_open": """
        SELECT f.check_id, f.resource_id, f.severity, f.cis_control
        FROM findings f
        JOIN (
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(latest)s
            INTERSECT
            SELECT check_id, resource_id FROM findings WHERE scan_id = %(previous)s
        ) k USING (check_id, resource_id)
        WHERE f.scan_id = %(latest)s
        ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low'], f.severity),
                 f.check_id, f.resource_id
    """,
}


class DatabaseConnectionError(Exception):
    pass


def _safe_target(db_url: str) -> str:
    # Describe the connection target without echoing the URL itself, which
    # may carry a password. Only host and dbname are ever surfaced.
    try:
        params = conninfo_to_dict(db_url)
    except Exception:
        return "host=? dbname=?"
    return f"host={params.get('host') or 'localhost'} dbname={params.get('dbname') or '?'}"


def connect(db_url: str) -> psycopg.Connection:
    try:
        return psycopg.connect(db_url, autocommit=True)
    except Exception:
        # "from None" drops the original exception from the traceback chain:
        # libpq error text can quote parts of the connection string.
        raise DatabaseConnectionError(
            f"could not connect to database ({_safe_target(db_url)})"
        ) from None


def save_scan(conn: psycopg.Connection, provider: str, account_id: str, findings: List[Finding]) -> int:
    rows = [
        (
            f.check_id,
            f.check_name,
            CIS_MAPPING.get(f.check_id),
            f.severity,
            f.resource_id,
            f.resource_type,
            f.region,
            Jsonb(f.details, dumps=_dumps),
        )
        for f in findings
        if f.cloud == provider
    ]

    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(_INSERT_SCAN_SQL, (provider, account_id))
            scan_id = cur.fetchone()[0]
            cur.executemany(_INSERT_FINDING_SQL, [(scan_id, *row) for row in rows])

    return scan_id


def diff_latest(conn: psycopg.Connection, provider: str, account_id: str) -> Optional[Dict]:
    """Compare the latest scan for provider/account_id with the one before it.

    Returns None when fewer than two scans exist, otherwise a dict with the
    two scan ids and "new", "resolved" and "still_open" lists of rows.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_LATEST_TWO_SCANS_SQL, {"provider": provider, "account_id": account_id})
        scan_ids = [row["id"] for row in cur.fetchall()]
        if len(scan_ids) < 2:
            return None

        params = {"latest": scan_ids[0], "previous": scan_ids[1]}
        diff: Dict = {"latest_scan_id": scan_ids[0], "previous_scan_id": scan_ids[1]}
        for bucket, sql in _DIFF_SQL.items():
            cur.execute(sql, params)
            diff[bucket] = cur.fetchall()

    return diff
