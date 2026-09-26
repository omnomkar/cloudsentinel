package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// severities lists the values allowed by the findings.severity CHECK
// constraint, most severe first. Every one is reported for every account,
// with 0 when absent, so PromQL queries don't see series appear and vanish.
var severities = []string{"critical", "high", "medium", "low"}

var (
	findingsDesc = prometheus.NewDesc(
		"cloudsentinel_findings",
		"Number of FAIL findings in the latest scan, by severity.",
		[]string{"provider", "account_id", "severity"}, nil,
	)
	lastScanDesc = prometheus.NewDesc(
		"cloudsentinel_last_scan_timestamp_seconds",
		"Unix time at which the latest scan started.",
		[]string{"provider", "account_id"}, nil,
	)
	driftDesc = prometheus.NewDesc(
		"cloudsentinel_drift_findings",
		"Findings new in, or resolved by, the latest scan compared with the previous one.",
		[]string{"provider", "account_id", "status"}, nil,
	)
	upDesc = prometheus.NewDesc(
		"cloudsentinel_exporter_up",
		"1 if the last database query succeeded, 0 otherwise.",
		nil, nil,
	)
)

// account identifies one scanned cloud account; it is the key for every
// per-account metric.
type account struct {
	Provider  string
	AccountID string
}

type drift struct {
	New      int64
	Resolved int64
}

// snapshot is everything one scrape reads from the database.
type snapshot struct {
	lastScan map[account]time.Time
	findings map[account]map[string]int64 // severity -> count
	drift    map[account]drift
}

// severityCount is one (severity, count) pair, in reporting order.
type severityCount struct {
	Severity string
	Count    int64
}

// withAllSeverities returns a count for every known severity (0 if missing),
// most severe first, followed by any unexpected severities in sorted order
// so a future schema change can't silently drop findings.
func withAllSeverities(counts map[string]int64) []severityCount {
	out := make([]severityCount, 0, len(severities))
	for _, sev := range severities {
		out = append(out, severityCount{sev, counts[sev]})
	}

	var extra []string
	for sev := range counts {
		if !slices.Contains(severities, sev) {
			extra = append(extra, sev)
		}
	}
	slices.Sort(extra)
	for _, sev := range extra {
		out = append(out, severityCount{sev, counts[sev]})
	}
	return out
}

// collector implements prometheus.Collector. Instead of keeping metric
// values in memory, it queries PostgreSQL every time Prometheus scrapes.
type collector struct {
	pool    *pgxpool.Pool
	timeout time.Duration
	logger  *slog.Logger
	target  string // "host=... dbname=..." for logs; never the full URL
}

func newCollector(pool *pgxpool.Pool, logger *slog.Logger, target string) *collector {
	return &collector{pool: pool, timeout: 5 * time.Second, logger: logger, target: target}
}

// Describe sends the descriptors of every metric Collect can produce.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- findingsDesc
	ch <- lastScanDesc
	ch <- driftDesc
	ch <- upDesc
}

// Collect runs on every scrape. On a database error it reports only
// cloudsentinel_exporter_up 0 rather than partial or stale data.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	snap, err := loadSnapshot(ctx, c.pool)
	if err != nil {
		// pgx error text includes the host, user and database at most,
		// never the password.
		c.logger.Error("database query failed", "db", c.target, "err", err)
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1)

	for acct, startedAt := range snap.lastScan {
		ch <- prometheus.MustNewConstMetric(lastScanDesc, prometheus.GaugeValue,
			float64(startedAt.UnixMilli())/1000, acct.Provider, acct.AccountID)

		for _, sc := range withAllSeverities(snap.findings[acct]) {
			ch <- prometheus.MustNewConstMetric(findingsDesc, prometheus.GaugeValue,
				float64(sc.Count), acct.Provider, acct.AccountID, sc.Severity)
		}
	}

	for acct, d := range snap.drift {
		ch <- prometheus.MustNewConstMetric(driftDesc, prometheus.GaugeValue,
			float64(d.New), acct.Provider, acct.AccountID, "new")
		ch <- prometheus.MustNewConstMetric(driftDesc, prometheus.GaugeValue,
			float64(d.Resolved), acct.Provider, acct.AccountID, "resolved")
	}
}

// loadSnapshot runs all queries in one read-only REPEATABLE READ transaction,
// so a scan committed mid-scrape can't make the metrics disagree with each
// other (e.g. a new timestamp next to the previous scan's counts).
func loadSnapshot(ctx context.Context, pool *pgxpool.Pool) (snapshot, error) {
	snap := snapshot{
		lastScan: make(map[account]time.Time),
		findings: make(map[account]map[string]int64),
		drift:    make(map[account]drift),
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return snapshot{}, fmt.Errorf("begin transaction: %w", err)
	}
	// Nothing to commit in a read-only transaction; Rollback just ends it.
	defer tx.Rollback(ctx)

	// ForEachRow scans each row into the variables listed, calls the function,
	// and always closes rows. The account and value variables are reused for
	// every row; storing them in a map copies them, so that is safe.
	var acct account
	var startedAt time.Time
	rows, _ := tx.Query(ctx, latestScansSQL) // a Query error surfaces from ForEachRow
	_, err = pgx.ForEachRow(rows, []any{&acct.Provider, &acct.AccountID, &startedAt}, func() error {
		snap.lastScan[acct] = startedAt
		return nil
	})
	if err != nil {
		return snapshot{}, fmt.Errorf("latest scans: %w", err)
	}

	var severity string
	var count int64
	rows, _ = tx.Query(ctx, severityCountsSQL)
	_, err = pgx.ForEachRow(rows, []any{&acct.Provider, &acct.AccountID, &severity, &count}, func() error {
		if snap.findings[acct] == nil {
			snap.findings[acct] = make(map[string]int64)
		}
		snap.findings[acct][severity] = count
		return nil
	})
	if err != nil {
		return snapshot{}, fmt.Errorf("severity counts: %w", err)
	}

	var d drift
	rows, _ = tx.Query(ctx, driftSQL)
	_, err = pgx.ForEachRow(rows, []any{&acct.Provider, &acct.AccountID, &d.New, &d.Resolved}, func() error {
		snap.drift[acct] = d
		return nil
	})
	if err != nil {
		return snapshot{}, fmt.Errorf("drift: %w", err)
	}

	return snap, nil
}
