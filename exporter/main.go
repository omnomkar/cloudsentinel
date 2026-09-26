// Command exporter exposes CloudSentinel scan results from PostgreSQL as
// Prometheus metrics.
//
// Configuration (environment):
//
//	DATABASE_URL  connection URL, without a password (required)
//	PGPASSWORD    database password (read by pgx, never logged)
//	LISTEN_ADDR   HTTP listen address (default ":9187")
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("exporter stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is not set")
	}
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9187"
	}
	target := safeTarget(dbURL)

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		// Deliberately not wrapping err: parse errors can quote the URL.
		return fmt.Errorf("invalid DATABASE_URL (%s)", target)
	}
	// Scrapes are serialised by Prometheus, so a couple of connections is plenty.
	cfg.MaxConns = 2

	// ctx is cancelled on SIGINT (Ctrl-C) or SIGTERM (docker stop).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The pool connects lazily, so the exporter starts even if the database
	// is down; scrapes then report cloudsentinel_exporter_up 0.
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create connection pool (%s): %w", target, err)
	}
	defer pool.Close()

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		newCollector(pool, logger, target),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	// Liveness only: database health is reported by cloudsentinel_exporter_up,
	// so a Postgres outage doesn't get the exporter restarted.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// ListenAndServe blocks, so it runs in its own goroutine while this one
	// waits for either a server error or a shutdown signal. The channel is
	// buffered so the goroutine can always send and exit.
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", listenAddr, "db", target)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	// Give in-flight scrapes up to 10s to finish, then stop regardless.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// safeTarget describes a connection string by host and dbname only, for log
// messages. The URL itself is never logged because it may carry a password.
func safeTarget(connString string) string {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return "host=? dbname=?"
	}
	return fmt.Sprintf("host=%s dbname=%s", cfg.ConnConfig.Host, cfg.ConnConfig.Database)
}
