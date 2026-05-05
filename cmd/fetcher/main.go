// Command fetcher pulls binaries from upstream vendor websites, hashes them,
// and writes them to <out>/<hostname>/<sha256>-<filename> with a sidecar
// JSON capturing provenance. Discovery logic for each vendor lives in the
// codeberg.org/atomdrift/hopper/website package.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"codeberg.org/atomdrift/hopper/website"
)

type cli struct {
	out             string
	only            string
	vendorInterval  time.Duration
	defaultInterval time.Duration
	listOnly        bool
	discoverOnly    bool
	verbose         bool
}

func main() {
	var c cli
	flag.StringVar(&c.out, "out", "fetched", "output directory (created if missing)")
	flag.StringVar(&c.only, "only", "", "comma-separated source names; empty = all registered")
	flag.BoolVar(&c.listOnly, "list", false, "print registered sources and exit")
	flag.BoolVar(&c.discoverOnly, "discover-only", false, "run Discover() for each source but do not fetch bytes")
	flag.DurationVar(&c.vendorInterval, "vendor-interval", 20*time.Hour, "min interval between polls of a vendor-website source (in-memory only)")
	flag.DurationVar(&c.defaultInterval, "default-interval", time.Hour, "min interval between polls of a large-infra source (GitHub etc.)")
	flag.BoolVar(&c.verbose, "v", false, "debug logging")
	flag.Parse()
	os.Exit(run(c))
}

func run(c cli) int {
	level := slog.LevelInfo
	if c.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if c.listOnly {
		for _, s := range website.Default() {
			fmt.Printf("%-24s %-14s %s\t%s\n", s.Name(), website.KindOf(s), s.Hostname(), s.MonitorPage())
		}
		return 0
	}

	if !c.discoverOnly {
		if err := os.MkdirAll(c.out, 0o750); err != nil {
			log.Error("mkdir out", "err", err)
			return 2
		}
	}

	sources, err := pickSources(c.only)
	if err != nil {
		log.Error("source selection", "err", err)
		return 2
	}
	if len(sources) == 0 {
		log.Error("no sources registered")
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	hc := newHTTPClient()
	tracker := newPollTracker(c.vendorInterval, c.defaultInterval)
	start := time.Now()
	var ok, fail, skipped int
	for _, s := range sources {
		if !tracker.shouldPoll(s) {
			log.Info("skipped", "source", s.Name(), "reason", "polled within min-interval")
			skipped++
			continue
		}
		err := runSource(ctx, log, hc, s, c.out, c.discoverOnly)
		tracker.markPolled(s)
		if err != nil {
			log.Error("source", "name", s.Name(), "err", err)
			fail++
			continue
		}
		ok++
	}
	log.Info("done",
		"ok", ok, "fail", fail, "skipped", skipped,
		"took", time.Since(start).Round(time.Millisecond))
	if fail > 0 {
		return 1
	}
	return 0
}

func pickSources(only string) ([]website.Source, error) {
	all := website.Default()
	if only == "" {
		return all, nil
	}
	wanted := map[string]bool{}
	for name := range strings.SplitSeq(only, ",") {
		if name = strings.TrimSpace(name); name != "" {
			wanted[name] = true
		}
	}
	var out []website.Source
	for _, s := range all {
		if wanted[s.Name()] {
			out = append(out, s)
			delete(wanted, s.Name())
		}
	}
	if len(wanted) > 0 {
		var unknown []string
		for n := range wanted {
			unknown = append(unknown, n)
		}
		return nil, fmt.Errorf("unknown source(s): %s", strings.Join(unknown, ","))
	}
	return out, nil
}
