package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestWithAllSeverities(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int64
		want   []severityCount
	}{
		{
			name:   "no findings reports every severity as zero",
			counts: nil,
			want:   []severityCount{{"critical", 0}, {"high", 0}, {"medium", 0}, {"low", 0}},
		},
		{
			name:   "missing severities are filled with zero",
			counts: map[string]int64{"high": 3, "low": 1},
			want:   []severityCount{{"critical", 0}, {"high", 3}, {"medium", 0}, {"low", 1}},
		},
		{
			name:   "all severities present",
			counts: map[string]int64{"low": 4, "medium": 3, "high": 2, "critical": 1},
			want:   []severityCount{{"critical", 1}, {"high", 2}, {"medium", 3}, {"low", 4}},
		},
		{
			name:   "unknown severities are kept, sorted, after known ones",
			counts: map[string]int64{"info": 2, "critical": 1, "extreme": 5},
			want: []severityCount{
				{"critical", 1}, {"high", 0}, {"medium", 0}, {"low", 0},
				{"extreme", 5}, {"info", 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := withAllSeverities(tt.counts)
			if !slices.Equal(got, tt.want) {
				t.Errorf("withAllSeverities(%v) = %v, want %v", tt.counts, got, tt.want)
			}
		})
	}
}

// With the database unreachable, a scrape must report exporter_up 0 and
// nothing else. This needs no database: nothing listens on port 1.
func TestCollectReportsDownWhenDatabaseUnreachable(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	c := newCollector(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), "host=127.0.0.1 dbname=none")
	c.timeout = 2 * time.Second

	want := `
# HELP cloudsentinel_exporter_up 1 if the last database query succeeded, 0 otherwise.
# TYPE cloudsentinel_exporter_up gauge
cloudsentinel_exporter_up 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}
