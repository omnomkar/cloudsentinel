package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Like tests/test_db.py, these tests run only when TEST_DATABASE_URL is set
// (never DATABASE_URL, so they can't touch a real database), and fail rather
// than skip in CI so they can't silently drop out.

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL tests")
	}
	return url
}

func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// newSchemaPool creates a throwaway schema with migrations/001_init.sql
// applied and returns a pool whose connections use it via search_path.
func newSchemaPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	url := testDatabaseURL(t)

	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		skipOrFail(t, "PostgreSQL at TEST_DATABASE_URL is unreachable: %v", err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })

	suffix := make([]byte, 6)
	rand.Read(suffix)
	schema := "test_" + hex.EncodeToString(suffix)
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+ident+" CASCADE") })

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migration, err := os.ReadFile("../migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	// With no arguments pgx uses the simple protocol, which allows the
	// multiple statements in the migration file.
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	return pool
}

type seedFinding struct{ checkID, resourceID, severity string }

func seedScan(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider, accountID string, startedAt time.Time, findings []seedFinding) {
	t.Helper()
	var scanID int64
	err := pool.QueryRow(ctx,
		"INSERT INTO scans (provider, account_id, started_at) VALUES ($1, $2, $3) RETURNING id",
		provider, accountID, startedAt).Scan(&scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		_, err := pool.Exec(ctx, `
			INSERT INTO findings (scan_id, check_id, check_name, severity, resource_id, resource_type, region)
			VALUES ($1, $2, 'Test check', $3, $4, 'Test::Resource', 'us-east-1')`,
			scanID, f.checkID, f.severity, f.resourceID)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollectorAgainstPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := newSchemaPool(t, ctx)

	t1 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	// AWS: two scans. Between them SG_1/sg-3 is resolved, two findings are
	// new, and IAM_1/user-2 changes severity, which (like --diff) is not drift.
	seedScan(t, ctx, pool, "aws", "111111111111", t1, []seedFinding{
		{"SG_1", "sg-1", "critical"},
		{"SG_1", "sg-3", "low"},
		{"IAM_1", "user-2", "high"},
	})
	seedScan(t, ctx, pool, "aws", "111111111111", t2, []seedFinding{
		{"SG_1", "sg-1", "critical"},
		{"IAM_1", "user-2", "medium"},
		{"S3_1", "bucket-a", "high"},
		{"S3_1", "bucket-b", "medium"},
	})
	// Timestamps: t2 = 1788343200 and t1 = 1788256800 (date -u -d ... +%s).
	// Azure: a single clean scan, so zero findings and no drift series.
	seedScan(t, ctx, pool, "azure", "sub-1", t1, nil)

	c := newCollector(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")

	want := `
# HELP cloudsentinel_drift_findings Findings new in, or resolved by, the latest scan compared with the previous one.
# TYPE cloudsentinel_drift_findings gauge
cloudsentinel_drift_findings{account_id="111111111111",provider="aws",status="new"} 2
cloudsentinel_drift_findings{account_id="111111111111",provider="aws",status="resolved"} 1
# HELP cloudsentinel_exporter_up 1 if the last database query succeeded, 0 otherwise.
# TYPE cloudsentinel_exporter_up gauge
cloudsentinel_exporter_up 1
# HELP cloudsentinel_findings Number of FAIL findings in the latest scan, by severity.
# TYPE cloudsentinel_findings gauge
cloudsentinel_findings{account_id="111111111111",provider="aws",severity="critical"} 1
cloudsentinel_findings{account_id="111111111111",provider="aws",severity="high"} 1
cloudsentinel_findings{account_id="111111111111",provider="aws",severity="medium"} 2
cloudsentinel_findings{account_id="111111111111",provider="aws",severity="low"} 0
cloudsentinel_findings{account_id="sub-1",provider="azure",severity="critical"} 0
cloudsentinel_findings{account_id="sub-1",provider="azure",severity="high"} 0
cloudsentinel_findings{account_id="sub-1",provider="azure",severity="medium"} 0
cloudsentinel_findings{account_id="sub-1",provider="azure",severity="low"} 0
# HELP cloudsentinel_last_scan_timestamp_seconds Unix time at which the latest scan started.
# TYPE cloudsentinel_last_scan_timestamp_seconds gauge
cloudsentinel_last_scan_timestamp_seconds{account_id="111111111111",provider="aws"} 1.7883432e+09
cloudsentinel_last_scan_timestamp_seconds{account_id="sub-1",provider="azure"} 1.7882568e+09
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

// TestExporterRoleIsReadOnly checks the grants made by
// migrations/002_exporter_role.sql, which must already have been applied
// (with 001) to the public schema of TEST_DATABASE_URL; CI does this with
// psql. Each statement runs as the exporter role via SET LOCAL ROLE in its
// own transaction, which is rolled back.
func TestExporterRoleIsReadOnly(t *testing.T) {
	url := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		skipOrFail(t, "PostgreSQL at TEST_DATABASE_URL is unreachable: %v", err)
	}
	defer conn.Close(context.Background())

	var ready bool
	err = conn.QueryRow(ctx, `
		SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudsentinel_exporter')
		   AND to_regclass('public.findings') IS NOT NULL`).Scan(&ready)
	if err != nil {
		t.Fatal(err)
	}
	if !ready {
		skipOrFail(t, "apply migrations/001_init.sql and 002_exporter_role.sql to TEST_DATABASE_URL first")
	}

	tests := []struct {
		name    string
		sql     string
		allowed bool
	}{
		{"select scans", "SELECT count(*) FROM public.scans", true},
		{"select findings", "SELECT count(*) FROM public.findings", true},
		{"insert findings", `INSERT INTO public.findings
			(scan_id, check_id, check_name, severity, resource_id, resource_type, region)
			VALUES (1, 'X', 'X', 'low', 'r', 't', 'us-east-1')`, false},
		{"update findings", "UPDATE public.findings SET severity = 'low'", false},
		{"delete findings", "DELETE FROM public.findings", false},
		{"insert scans", "INSERT INTO public.scans (provider, account_id) VALUES ('aws', 'x')", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)

			if _, err := tx.Exec(ctx, "SET LOCAL ROLE cloudsentinel_exporter"); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, tt.sql)

			if tt.allowed {
				if err != nil {
					t.Errorf("expected success, got %v", err)
				}
				return
			}
			// 42501 is insufficient_privilege; any other error (or none)
			// would mean the grant isn't what we think it is.
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("expected permission denied (42501), got %v", err)
			}
		})
	}
}
