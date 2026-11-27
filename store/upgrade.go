package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// Upgrade brings verdict tables made from an older schema.sql up to this
// one. The verdict schema keeps no ledger of migrations: each step looks at
// the tables to see whether it is needed, so on tables this schema.sql made,
// or ones Upgrade has seen before, it changes nothing and takes no lock
// beyond a read. It runs before hopper serves, because the remap rewrites
// every queued row and hopper is the queue's only writer.
//
// A read-only session is left alone: a replica's tables take the
// publisher's upgrade by replication, and a replica hands out no work.
func (st *Store) Upgrade(ctx context.Context) error {
	var readOnly bool
	if err := st.pool.QueryRow(ctx, `SELECT current_setting('transaction_read_only') = 'on'`).Scan(&readOnly); err != nil {
		return fmt.Errorf("store: upgrade: %w", err)
	}
	if readOnly {
		slog.InfoContext(ctx, "store: upgrade skipped: the session is read-only")
		return nil
	}
	if err := st.respace(ctx); err != nil {
		return fmt.Errorf("store: upgrade: %w", err)
	}
	if err := st.admissions(ctx); err != nil {
		return fmt.Errorf("store: upgrade: %w", err)
	}
	// 2026-11-27: the queue read from its newest end, what QueueDescribe
	// remembers, the LLM inputs it hands out, and the scans its sweep walks.
	for _, step := range []struct{ name, ddl string }{
		{"queue_newest", `CREATE INDEX queue_newest ON queue (priority, retry_at NULLS FIRST, sample_id DESC) WHERE attempts < 8`},
		{"llm_attempts", `CREATE UNLOGGED TABLE llm_attempts (sample_id bigint PRIMARY KEY, at timestamptz NOT NULL DEFAULT now())`},
		{"llm_inputs", `CREATE TABLE llm_inputs (sample_id bigint PRIMARY KEY, stored_at timestamptz NOT NULL DEFAULT now(),
			input bytea COMPRESSION lz4 NOT NULL)`},
		{"scans_describable", `CREATE INDEX scans_describable ON scans (scanned_at, sample_id) WHERE ` + describable},
	} {
		var missing bool
		if err := st.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NULL`, step.name).Scan(&missing); err != nil {
			return fmt.Errorf("store: upgrade: %s: %w", step.name, err)
		}
		if !missing {
			continue
		}
		start := time.Now()
		if _, err := st.pool.Exec(ctx, step.ddl); err != nil {
			return fmt.Errorf("store: upgrade: %s: %w", step.name, err)
		}
		slog.InfoContext(ctx, "store: upgrade: created", "relation", step.name, "took", time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// admissions adds scans.llm_admission (2026-11-27). The column is new and
// so NULL in every row, and its check is added NOT VALID: nothing needs
// checking, and validating would read the whole table under the lock ALTER
// TABLE takes. A logical replica's copy of scans gains the column from
// scripts/replica/replica-heal.sh.
func (st *Store) admissions(ctx context.Context) error {
	var missing bool
	if err := st.pool.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM pg_attribute
		WHERE attrelid = to_regclass('scans') AND attname = 'llm_admission' AND NOT attisdropped)`).Scan(&missing); err != nil {
		return fmt.Errorf("scans.llm_admission: %w", err)
	}
	if !missing {
		return nil
	}
	start := time.Now()
	if _, err := st.pool.Exec(ctx, `ALTER TABLE scans ADD COLUMN llm_admission text,
		ADD CONSTRAINT scans_llm_admission_check CHECK (llm_admission IN ('none', 'optional', 'required')) NOT VALID`); err != nil {
		return fmt.Errorf("scans.llm_admission: %w", err)
	}
	slog.InfoContext(ctx, "store: upgrade: added", "column", "scans.llm_admission", "took", time.Since(start).Round(time.Millisecond))
	return nil
}

// respace remaps queue rows written while priorities were 0 to 6 to the
// spaced values that replaced them (2026-11-27), ten times the old, which
// keeps their order and so their meaning: a stored 0 to 6 is never one of
// the new values, so a row is remapped once and only once. In the same
// transaction the first scans of compromised packages already queued are
// raised to QueueCompromised, as ingest would now have queued them.
func (st *Store) respace(ctx context.Context) error {
	start := time.Now()
	var remapped, raised int64
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE queue SET priority = priority * 10 WHERE priority BETWEEN 1 AND 6`)
		if err != nil {
			return err
		}
		if remapped = tag.RowsAffected(); remapped == 0 {
			return nil
		}
		tag, err = tx.Exec(ctx, `UPDATE queue q SET priority = $1 FROM samples s
			WHERE s.id = q.sample_id AND q.priority IN ($2, $3) AND `+compromised,
			int16(QueueCompromised), int16(QueueBigArchive), int16(QueueNew))
		if err != nil {
			return err
		}
		raised = tag.RowsAffected()
		// The planner's statistics still hold the old values.
		_, err = tx.Exec(ctx, `ANALYZE queue`)
		return err
	})
	if err != nil {
		return fmt.Errorf("respace priorities: %w", err)
	}
	if remapped > 0 {
		slog.InfoContext(ctx, "store: upgrade: queue priorities respaced", "rows", remapped,
			"compromised", raised, "took", time.Since(start).Round(time.Millisecond))
	}
	return nil
}
