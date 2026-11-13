package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/atomdrift-project/hopper"
)

func cmdIngestGauntlet(ctx context.Context) error {
	f := flag.NewFlagSet("ingest-gauntlet", flag.ContinueOnError)
	dsn := f.String("dsn", os.Getenv("HOPPER_DSN"), "destination SQLite path or Postgres DSN")
	input := f.String("input", "-", "run envelopes as NDJSON; - reads stdin")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("--dsn is required")
	}
	db, err := hopper.Open(ctx, *dsn, "gauntlet-import")
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	var reader io.Reader = os.Stdin
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck // read-only input
		reader = file
	}
	dec := json.NewDecoder(reader)
	inserted, duplicate := 0, 0
	for {
		var run hopper.GauntletRun
		if err := dec.Decode(&run); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		fresh, err := db.StoreGauntletRun(ctx, run)
		if err != nil {
			return fmt.Errorf("run %s: %w", run.ID, err)
		}
		if fresh {
			inserted++
		} else {
			duplicate++
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]int{"inserted_runs": inserted, "duplicate_runs": duplicate})
}
