import os
import sys
import traceback
import uuid
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest

psycopg = pytest.importorskip("psycopg")

import main
from scanner import Finding
from scanner import console, db


# Database-backed tests run only when TEST_DATABASE_URL points at a Postgres
# server; each test gets its own throwaway schema. DATABASE_URL is
# deliberately not used here so the suite can never write to a real database.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
MIGRATION = Path(__file__).resolve().parent.parent / "migrations" / "001_init.sql"
ACCOUNT = "123456789012"


def _make_finding(resource_id="sg-1", check_id="SG_SSH_OPEN_TO_WORLD", severity="critical", cloud="aws"):
    return Finding(
        resource_id=resource_id,
        resource_type="AWS::EC2::SecurityGroup",
        check_id=check_id,
        check_name="Test check",
        severity=severity,
        status="FAIL",
        region="us-east-1",
        cloud=cloud,
        remediation="Fix it.",
        details={"note": "test"},
    )


@pytest.fixture
def schema_url():
    """Yield a TEST_DATABASE_URL variant pinned to a fresh, migrated schema."""
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set; skipping PostgreSQL tests")
    try:
        admin = psycopg.connect(TEST_DATABASE_URL, autocommit=True, connect_timeout=3)
    except psycopg.OperationalError:
        if os.environ.get("CI"):
            pytest.fail("TEST_DATABASE_URL is set in CI but the database is unreachable")
        pytest.skip("PostgreSQL at TEST_DATABASE_URL is unreachable")

    schema = f"test_{uuid.uuid4().hex[:12]}"
    admin.execute(f'CREATE SCHEMA "{schema}"')
    admin.execute(f'SET search_path TO "{schema}"')
    admin.execute(MIGRATION.read_text())

    sep = "&" if "?" in TEST_DATABASE_URL else "?"
    yield f"{TEST_DATABASE_URL}{sep}options={quote(f'-csearch_path={schema}')}"

    admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
    admin.close()


@pytest.fixture
def conn(schema_url):
    connection = db.connect(schema_url)
    yield connection
    connection.close()


def _run_cli(monkeypatch, argv, findings):
    """Run main.main() with the AWS scan and STS lookup stubbed out."""
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": ACCOUNT}
    monkeypatch.setattr(main.boto3, "Session", lambda: session)
    monkeypatch.setattr(main, "run_all_aws_checks", lambda *a, **kw: list(findings))
    monkeypatch.setattr(sys, "argv", ["main.py", "--no-color", *argv])
    # The renderers default to the sys.stdout that existed at import time;
    # point them at the current one so capsys can see their output.
    monkeypatch.setattr(main, "render_report", lambda **kw: console.render_report(**kw, stream=sys.stdout))
    monkeypatch.setattr(main, "render_diff", lambda **kw: console.render_diff(**kw, stream=sys.stdout))
    with pytest.raises(SystemExit) as exc:
        main.main()
    return exc.value.code, session


# ---------------------------------------------------------------------------
# PostgreSQL-backed tests
# ---------------------------------------------------------------------------

class TestSaveScan:
    def test_insert_persists_scan_and_findings(self, conn):
        findings = [
            _make_finding("sg-1", "SG_SSH_OPEN_TO_WORLD", "critical"),
            _make_finding("bucket-1", "S3_PUBLIC_ACL", "high"),
            _make_finding("sa-1", "AZURE_STORAGE_SECURE_TRANSFER", "high", cloud="azure"),
        ]
        scan_id = db.save_scan(conn, "aws", ACCOUNT, findings)

        scan = conn.execute("SELECT provider, account_id FROM scans WHERE id = %s", (scan_id,)).fetchone()
        assert scan == ("aws", ACCOUNT)

        rows = conn.execute(
            "SELECT check_id, resource_id, severity, cis_control, details FROM findings "
            "WHERE scan_id = %s ORDER BY check_id",
            (scan_id,),
        ).fetchall()
        # Only this provider's findings are stored; cis_control comes from CIS_MAPPING.
        assert rows == [
            ("S3_PUBLIC_ACL", "bucket-1", "high", "2.1.5", {"note": "test"}),
            ("SG_SSH_OPEN_TO_WORLD", "sg-1", "critical", "5.2", {"note": "test"}),
        ]

    def test_unique_constraint_rejects_duplicate_finding(self, conn):
        duplicate = [_make_finding("sg-1"), _make_finding("sg-1")]
        with pytest.raises(psycopg.errors.UniqueViolation):
            db.save_scan(conn, "aws", ACCOUNT, duplicate)
        # The whole scan is rolled back, not just the second row.
        assert conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 0


class TestDiff:
    def test_diff_detects_new_finding(self, conn):
        db.save_scan(conn, "aws", ACCOUNT, [_make_finding("sg-1")])
        db.save_scan(conn, "aws", ACCOUNT, [_make_finding("sg-1"), _make_finding("sg-2")])

        diff = db.diff_latest(conn, "aws", ACCOUNT)
        assert [r["resource_id"] for r in diff["new"]] == ["sg-2"]
        assert diff["resolved"] == []
        assert [r["resource_id"] for r in diff["still_open"]] == ["sg-1"]

    def test_diff_detects_resolved_finding(self, conn):
        db.save_scan(conn, "aws", ACCOUNT, [_make_finding("sg-1"), _make_finding("sg-2", severity="high")])
        # sg-2 is fixed; sg-1 changes severity, which is still the same open finding.
        db.save_scan(conn, "aws", ACCOUNT, [_make_finding("sg-1", severity="medium")])

        diff = db.diff_latest(conn, "aws", ACCOUNT)
        assert diff["new"] == []
        assert [r["resource_id"] for r in diff["resolved"]] == ["sg-2"]
        assert [(r["resource_id"], r["severity"]) for r in diff["still_open"]] == [("sg-1", "medium")]

    def test_diff_scoped_to_provider_and_account(self, conn):
        db.save_scan(conn, "aws", "other-account", [_make_finding("sg-9")])
        db.save_scan(conn, "aws", ACCOUNT, [_make_finding("sg-1")])
        assert db.diff_latest(conn, "aws", ACCOUNT) is None

    def test_cli_diff_first_run_then_new_finding(self, schema_url, monkeypatch, tmp_path, capsys):
        argv = ["--db-url", schema_url, "--diff", "--output-dir", str(tmp_path)]

        code, _ = _run_cli(monkeypatch, argv, [_make_finding("sg-1", severity="low")])
        assert code == 0
        assert "No previous scan to compare" in capsys.readouterr().out

        code, _ = _run_cli(monkeypatch, argv, [_make_finding("sg-1", severity="low"), _make_finding("sg-2", severity="low")])
        out = capsys.readouterr().out
        assert code == 0
        assert "NEW (1):" in out and "sg-2" in out
        assert "STILL OPEN (1):" in out
        assert "RESOLVED (" not in out


# ---------------------------------------------------------------------------
# Tests that need no database
# ---------------------------------------------------------------------------

class TestPersistenceOptIn:
    def test_no_db_configured_writes_nothing(self, monkeypatch, tmp_path):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        connect_calls = []
        monkeypatch.setattr(psycopg, "connect", lambda *a, **kw: connect_calls.append(a))

        code, session = _run_cli(monkeypatch, ["--output-dir", str(tmp_path)], [_make_finding(severity="low")])

        assert code == 0
        assert connect_calls == []
        # No STS lookup either: the scanner makes no extra API calls when persistence is off.
        session.client.assert_not_called()

    def test_diff_without_db_exits_2(self, monkeypatch, tmp_path, capsys):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        code, _ = _run_cli(monkeypatch, ["--diff", "--output-dir", str(tmp_path)], [])
        assert code == 2
        assert "--diff requires" in capsys.readouterr().err

    def test_azure_persistence_requires_subscription_id_before_scanning(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("DATABASE_URL", "postgresql://u:pw@127.0.0.1:1/cloudsentinel")
        code, session = _run_cli(monkeypatch, ["--cloud", "all", "--output-dir", str(tmp_path)], [])
        assert code == 2
        assert "--subscription-id is required" in capsys.readouterr().err
        session.client.assert_not_called()


class TestCredentialHygiene:
    PASSWORD = "S3cr3t-Hunter2-pw"
    URL = f"postgresql://scanner:{PASSWORD}@127.0.0.1:1/cloudsentinel?connect_timeout=2"

    def test_connection_error_hides_password(self):
        with pytest.raises(db.DatabaseConnectionError) as exc:
            db.connect(self.URL)

        rendered = "".join(traceback.format_exception(exc.value))
        assert "host=127.0.0.1 dbname=cloudsentinel" in str(exc.value)
        assert self.PASSWORD not in rendered
        assert exc.value.__cause__ is None and exc.value.__suppress_context__

    def test_cli_connection_error_hides_password(self, monkeypatch, tmp_path, capsys):
        code, _ = _run_cli(monkeypatch, ["--db-url", self.URL, "--output-dir", str(tmp_path)], [])
        captured = capsys.readouterr()
        assert code == 2
        assert "host=127.0.0.1 dbname=cloudsentinel" in captured.err
        assert self.PASSWORD not in captured.out + captured.err
