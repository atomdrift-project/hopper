// Package main is the hopper CLI for managing the sample registry.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: pprof bound to a dedicated loopback listener (pprofAddr), never the public mux
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/atomdrift-project/obs"
)

const usageText = `usage: hopper <command>

commands:
  serve              start a local postgres server with hopper schema
  init               create/migrate a hopper database (sqlite or postgres)
  load               load sample files from directories
  ingest-reports     ingest cyclotron Markdown reports from a directory
  reset              delete all samples and reports (preserves schema)
  import             transfer samples between hopper databases (sqlite↔postgres)
  false-positives    list known-good files that still score bad
  false-negatives    list known-bad files that still score benign
  benign-review      list marker-benign files cleave still flags as suspicious
  bad-review         list marker-bad files cleave still considers benign
  conflict-review    list samples asserted both good and bad across pools
  backfill           re-derive columns from cleave_result/litmus_result blobs
  reheal-crit        repair max_crit/suspicious_count zeroed by the pre-v8 cleave trigger (postgres)
  backfill-purl      derive missing samples.purl_base from ecosystem+package (never overwrites; postgres)
  canonicalize-purls rewrite stored purl_base spellings onto the current canonical form (batched; -dry-run; postgres)
  purge-unsupported  delete analyzed rows cleave could not classify
  normalize-ecosystems  re-canonicalize stored ecosystem labels (dry-run)
  cleanup            delete wonky samples by skip category (interactive)
  prune              drop location rows for files gone from disk, mark orphaned samples missing (run on the full mirror)
  rescan             queue files for repair-tier re-analysis (--missing-members or SHA-256 args)
  triage             fetch mislabeled samples to /var/tmp/hopper-triage
  post-triage        apply triage verdicts: re-scan, move + flip mislabeled samples
  demote-sighted     move uncorroborated feed-claimed samples from bad/ to sighted/ (dry-run; -apply)
  cascade-backfill   propagate good/bad archive labels to their members (dry-run)
  stats              show sample counts
`

func writeStderrf(format string, args ...any) {
	if _, err := fmt.Fprintf(os.Stderr, format, args...); err != nil {
		slog.Debug("stderr write failed", "error", err)
	}
}

func writeStdoutf(format string, args ...any) {
	if _, err := fmt.Printf(format, args...); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func writeStdout(s string) {
	if _, err := fmt.Print(s); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func writeStdoutLine(s string) {
	if _, err := fmt.Println(s); err != nil {
		slog.Debug("stdout write failed", "error", err)
	}
}

func runtimeIdentityAttrs() []any {
	attrs := []any{
		"pid", os.Getpid(),
		"go", runtime.Version(),
	}
	if exe, err := os.Executable(); err == nil {
		attrs = append(attrs, "executable", exe)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			attrs = append(attrs, "module_version", info.Main.Version)
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if len(setting.Value) > 12 {
					attrs = append(attrs, "vcs_revision", setting.Value[:12])
				} else {
					attrs = append(attrs, "vcs_revision", setting.Value)
				}
			case "vcs.time":
				attrs = append(attrs, "vcs_time", setting.Value)
			case "vcs.modified":
				attrs = append(attrs, "vcs_modified", setting.Value)
			default:
			}
		}
	}
	return attrs
}

func parseFlags(f *flag.FlagSet, args []string) {
	if err := f.Parse(args); err != nil {
		panic(err)
	}
}

func flagWasSet(f *flag.FlagSet, name string) bool {
	seen := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == name {
			seen = true
		}
	})
	return seen
}

type stringListFlag []string

func (s *stringListFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(v string) error {
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// uploadTokenKVKey names the hopper_kv row that holds the upload bearer
// token. Prism reads this same key to discover the token without operator
// coordination.
const uploadTokenKVKey = "upload_token"

// uploadOpenRequested reports whether HOPPER_UPLOAD_OPEN asks for an
// unauthenticated /api/upload — a "1"/"true"/"yes"/"on" value (case-insensitive).
func uploadOpenRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HOPPER_UPLOAD_OPEN"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// bootstrapUploadToken resolves the /api/upload bearer token in this
// priority order:
//  0. HOPPER_UPLOAD_OPEN truthy → open: /api/upload is left unauthenticated
//     (the CSRF guard still blocks browser forms). A token is still provisioned
//     in the KV (steps 2–3) so prism and other token-sending clients keep
//     working, but it is not enforced — a tokenless scan/forager push is
//     accepted. The frictionless choice for an internal deployment.
//  1. HOPPER_UPLOAD_TOKEN env var (operator override; never written to DB).
//  2. The persisted hopper_kv row (set by a previous run or peer instance).
//  3. A freshly-generated 32-byte random token, persisted via INSERT…
//     ON CONFLICT DO NOTHING so concurrent first-starters converge on
//     whichever value won the race.
//
// On any failure the route stays disabled (setUploadToken never called),
// and /api/upload returns 503. The plaintext token is scoped to this
// function; only the SHA-256 digest survives in apiServer.
func bootstrapUploadToken(ctx context.Context, api *apiServer, db *hopper.DB) {
	open := uploadOpenRequested()
	if open {
		// Loud: this disables auth on a content-ingest path. A token is still
		// provisioned below (so prism and other token-sending clients keep
		// working), but setUploadToken is never called, so checkUploadAuth leaves
		// the endpoint open — a tokenless scan/forager push is accepted too.
		slog.Warn("upload endpoint OPEN: /api/upload requires no token (HOPPER_UPLOAD_OPEN set)")
	} else if env := strings.TrimSpace(os.Getenv("HOPPER_UPLOAD_TOKEN")); env != "" {
		if err := api.setUploadToken(env); err != nil {
			slog.Error("HOPPER_UPLOAD_TOKEN rejected; /api/upload disabled", "error", err)
			return
		}
		//nolint:gosec // logging integer length only; token bytes never logged
		slog.Info("upload endpoint enabled", "source", "env", "token_len", len(env))
		return
	}

	// Bound the DB-touching paths so a wedged database surfaces as a
	// fail-closed disabled endpoint instead of an indefinite startup hang.
	// retryDBAccess retries inside this budget with full-jitter backoff.
	ctx, cancel := context.WithTimeout(ctx, kvBootstrapTimeout)
	defer cancel()

	readToken := func(op string) (string, error) {
		return retryDBAccess(ctx, op, uploadTokenKVKey, func(ctx context.Context) (string, error) {
			return db.KVGet(ctx, uploadTokenKVKey)
		})
	}

	token, err := readToken("kv get upload token")
	source := "db"
	switch {
	case err == nil:
		// Use the stored value as-is.
	case errors.Is(err, hopper.ErrNotFound):
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			slog.Error("upload token generation failed; /api/upload disabled", "error", err)
			return
		}
		candidate := hex.EncodeToString(buf[:])
		if err := retryDBAccessNoValue(ctx, "kv set upload token", uploadTokenKVKey, func(ctx context.Context) error {
			return db.KVSetIfAbsent(ctx, uploadTokenKVKey, candidate)
		}); err != nil {
			slog.Error("upload token persistence failed; /api/upload disabled", "error", err)
			return
		}
		// A peer instance may have raced us and won. Read whichever value
		// actually landed.
		token, err = readToken("kv reread upload token")
		if err != nil {
			slog.Error("upload token re-read failed; /api/upload disabled", "error", err)
			return
		}
		source = "generated"
	default:
		slog.Error("upload token DB lookup failed; /api/upload disabled", "error", err)
		return
	}

	if open {
		// Token is now in the KV for clients that send one, but the endpoint
		// stays open (setUploadToken not called). Dropping HOPPER_UPLOAD_OPEN on
		// the next start re-enforces this same provisioned token.
		slog.Info("upload token provisioned but not enforced (open mode)", "source", source, "token_len", len(token))
		return
	}

	if err := api.setUploadToken(token); err != nil {
		slog.Error("upload token rejected; /api/upload disabled", "source", source, "error", err)
		return
	}
	slog.Info("upload endpoint enabled", "source", source, "token_len", len(token))
}

// kvBootstrapTimeout caps every KV call made during /api/upload token
// bootstrap. retryDBAccess backs off with full jitter inside this deadline;
// the operator sees a fail-closed disabled endpoint rather than an
// indefinite startup hang if the DB never recovers.
const kvBootstrapTimeout = 2 * time.Minute

// isLoopbackAddr reports whether addr (host:port or ":port") binds only to
// the loopback interface. Empty addr / unresolvable host count as non-
// loopback so the caller emits the safer warning.
func isLoopbackAddr(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func localListenAddr(addr string) string {
	if addr == "" {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return "127.0.0.1" + addr
		}
		return addr
	}
	ip := net.ParseIP(host)
	if host == "" || host == "localhost" || ip != nil && ip.IsLoopback() {
		if host == "" {
			return net.JoinHostPort("127.0.0.1", port)
		}
		return addr
	}
	if host == "0.0.0.0" || host == "::" || host == "[::]" || ip == nil || !ip.IsLoopback() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// Extract-cache disk budget defaults. The total is a soft ceiling on cached
// decompressed tars across all parents; perEntry caps a single one so one giant
// image can't consume the whole budget (it falls back to direct streaming).
// Operators override both with HOPPER_EXTRACT_CACHE_BYTES /
// HOPPER_EXTRACT_CACHE_MAX_ENTRY_BYTES; setting the total to 0 disables caching.
const (
	defaultExtractCacheBytes      = 16 << 30 // 16 GiB total
	defaultExtractCacheEntryBytes = 4 << 30  // 4 GiB per archive
)

// envBytes reads a non-negative byte count from env, falling back to def when
// unset, empty, or unparseable. A negative value also falls back to def, so the
// only way to disable a budget is an explicit 0.
func envBytes(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		//nolint:gosec // name/v are operator-supplied env config, not request data
		slog.Warn("ignoring invalid byte-count env var; using default", "var", name, "value", v, "default", def)
		return def
	}
	return n
}

func relativeSamplePath(dataRoot, path string) string {
	if dataRoot == "" || path == "" || !filepath.IsAbs(path) {
		return path
	}
	if rel, err := filepath.Rel(dataRoot, path); err == nil && rel != "." &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel
	}
	return path
}

func sampleDiskPath(dataRoot, path string) string {
	if path == "" || filepath.IsAbs(path) || dataRoot == "" {
		return path
	}
	return filepath.Join(dataRoot, path)
}

func normalizeForceRescanDirs(dataRoot string, dirs []string) ([]string, error) {
	out := make([]string, 0, len(dirs))
	seen := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if filepath.IsAbs(dir) {
			rel, err := filepath.Rel(dataRoot, dir)
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("force-rescan path %q is outside data directory %s", dir, dataRoot)
			}
			dir = rel
		}
		dir = filepath.Clean(dir)
		if dir == "." || dir == ".." || strings.HasPrefix(dir, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("invalid force-rescan path %q", dir)
		}
		dir = filepath.ToSlash(dir)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out, nil
}

func closeFileBestEffort(name string, f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("close file failed", "path", name, "error", err)
	}
}

func killProcessBestEffort(reason string, proc *os.Process) {
	if proc == nil {
		return
	}
	if err := proc.Kill(); err != nil {
		slog.Warn(reason, "error", err)
	}
}

func waitCmdBestEffort(reason string, cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if err := cmd.Wait(); err != nil {
		slog.Debug(reason, "error", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		writeStderrf("%s", usageText)
		os.Exit(1)
	}

	logPath, cleanup, err := setupLogging()
	if err != nil {
		writeStderrf("failed to setup logging: %v\n", err)
	} else if logPath != "" {
		fmt.Fprintf(os.Stderr, "log: %s\n", logPath) //nolint:forbidigo // startup info before slog is configured
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	// Init OTel. DisableSlog so we keep the stderr+file fan-out built by
	// setupLogging and just add the OTLP sink as one more handler.
	obsShutdown, err := obs.Init(ctx, obs.Config{ServiceName: "hopper", DisableSlog: true})
	if err != nil {
		writeStderrf("obs init: %v\n", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(obs.TeeSlog(slog.Default().Handler(), "hopper")))

	// Force-exit on a second interrupt so cleanup can't hang forever.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh // first is handled by NotifyContext
		<-sigCh // second means "exit now"
		slog.Warn("forced exit on second interrupt")
		os.Exit(1)
	}()

	// Dump all goroutine stacks on SIGUSR1 (Linux equivalent of BSD SIGINFO / Ctrl-T).
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGUSR1)
		for range sigCh {
			buf := make([]byte, 1<<20) // 1 MB
			n := runtime.Stack(buf, true)
			_, _ = os.Stderr.Write(buf[:n]) //nolint:errcheck // best-effort debug dump
		}
	}()

	err = run(ctx)
	stop()
	// Flush exporters before file/log cleanup so the last spans/metrics
	// have a chance to ship.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if shutdownErr := obsShutdown(shutdownCtx); shutdownErr != nil {
		slog.Warn("obs shutdown", "error", shutdownErr)
	}
	shutdownCancel()
	if cleanup != nil {
		cleanup()
	}
	if err != nil {
		// The command name (os.Args[1], validated by run's dispatch) pins which
		// subcommand failed; the wrapped err carries the operation-level context.
		cmd := ""
		if len(os.Args) > 1 {
			cmd = os.Args[1]
		}
		slog.Error("command failed", "command", cmd, "error", err) //nolint:gosec // cmd is os.Args[1]; slog escapes structured values
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	switch os.Args[1] {
	case "serve":
		return cmdServe(ctx)
	case "init":
		return cmdInit(ctx)
	case "import":
		return cmdImport(ctx)
	case "load":
		return cmdLoad(ctx)
	case "ingest-reports":
		return cmdIngestReports(ctx)
	case "reset":
		return cmdReset(ctx)
	case "false-positives":
		return cmdFalsePositives(ctx)
	case "false-negatives":
		return cmdFalseNegatives(ctx)
	case "benign-review":
		return cmdBenignReview(ctx)
	case "bad-review":
		return cmdBadReview(ctx)
	case "conflict-review":
		return cmdConflictReview(ctx)
	case "backfill":
		return cmdBackfill(ctx)
	case "reheal-crit":
		return cmdRehealCrit(ctx)
	case "backfill-purl":
		return cmdBackfillPURL(ctx)
	case "canonicalize-purls":
		return cmdCanonicalizePURLs(ctx)
	case "purge-unsupported":
		return cmdPurgeUnsupported(ctx)
	case "normalize-ecosystems":
		return cmdNormalizeEcosystems(ctx)
	case "cleanup":
		return cmdCleanup(ctx)
	case "prune":
		return cmdPrune(ctx)
	case "rescan":
		return cmdRescan(ctx)
	case "triage":
		return cmdTriage(ctx)
	case "post-triage":
		return cmdPostTriage(ctx)
	case "demote-sighted":
		return cmdDemoteSighted(ctx)
	case "cascade-backfill":
		return cmdCascadeBackfill(ctx)
	case "stats":
		return cmdStats(ctx)
	default:
		writeStderrf("%s", usageText)
		return errors.New("unknown command: " + os.Args[1])
	}
}

func xdgLogDir() string {
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Logs", "hopper")
		}
	case "windows":
		if appdata := os.Getenv("LOCALAPPDATA"); appdata != "" {
			return filepath.Join(appdata, "hopper", "Logs")
		}
	default:
	}
	// Default to XDG_STATE_HOME on Linux/Unix.
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return filepath.Join(s, "hopper")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "hopper")
	}
	return ".hopper" // Fallback
}

// xdgCacheDir returns the OS-appropriate per-user cache directory for
// hopper. Regenerable state only (hash cache) — anything we can't rebuild
// from the DB belongs in state (xdgLogDir), not here.
func xdgCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Caches", "hopper")
		}
	case "windows":
		if appdata := os.Getenv("LOCALAPPDATA"); appdata != "" {
			return filepath.Join(appdata, "hopper", "Cache")
		}
	default:
	}
	if c := os.Getenv("XDG_CACHE_HOME"); c != "" {
		return filepath.Join(c, "hopper")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "hopper")
	}
	return ".hopper" // Fallback
}

// hashCachePath returns the current-convention location of the hash cache
// and, as a side effect, migrates an old ~/.hopper/hashcache.db into it
// the first time we run on a system that had the legacy layout. Keeping
// the migration here (rather than a separate tool) means users upgrading
// the binary transparently carry their hash cache forward.
func hashCachePath() string {
	dir := xdgCacheDir()
	_ = os.MkdirAll(dir, 0o750) //nolint:errcheck // mkdirAllBestEffort idiom
	newPath := filepath.Join(dir, "hashcache.db")

	if _, err := os.Stat(newPath); err == nil {
		return newPath
	}
	if home, err := os.UserHomeDir(); err == nil {
		legacy := filepath.Join(home, ".hopper", "hashcache.db")
		if _, err := os.Stat(legacy); err == nil {
			// Move the cache + its WAL/SHM companions. Best effort: a
			// rename failure (cross-device, permissions) just leaves the
			// legacy file in place and we start fresh in the new spot.
			if err := os.Rename(legacy, newPath); err == nil {
				slog.Info("migrated hash cache", "from", legacy, "to", newPath)
				for _, ext := range []string{"-wal", "-shm"} {
					_ = os.Rename(legacy+ext, newPath+ext) //nolint:errcheck // best-effort cleanup
				}
			}
		}
	}
	return newPath
}

func setupLogging() (logPath string, cleanup func(), err error) {
	if runningUnderSystemd() {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
		return "", func() {}, nil
	}

	dir := xdgLogDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, err
	}

	logPath = filepath.Join(dir, "hopper.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}

	// Use a handler that writes to both stderr and the log file.
	// Console gets Warn+ only; Info/Debug go to the log file.
	stderrLevel := &slog.LevelVar{}
	stderrLevel.Set(slog.LevelWarn)
	fileLevel := &slog.LevelVar{}
	h := &multiHandler{
		h1: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: stderrLevel}),
		h2: slog.NewJSONHandler(f, &slog.HandlerOptions{Level: fileLevel}),
	}
	slog.SetDefault(slog.New(h))

	return logPath, func() { closeFileBestEffort(logPath, f) }, nil
}

func runningUnderSystemd() bool {
	return os.Getenv("INVOCATION_ID") != "" || os.Getenv("JOURNAL_STREAM") != ""
}

type multiHandler struct {
	h1, h2 slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return m.h1.Enabled(ctx, l) || m.h2.Enabled(ctx, l)
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // matches slog.Handler interface
	var err1, err2 error
	if m.h1.Enabled(ctx, r.Level) {
		err1 = m.h1.Handle(ctx, r)
	}
	if m.h2.Enabled(ctx, r.Level) {
		err2 = m.h2.Handle(ctx, r)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{h1: m.h1.WithAttrs(attrs), h2: m.h2.WithAttrs(attrs)}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{h1: m.h1.WithGroup(name), h2: m.h2.WithGroup(name)}
}

// redactDSN strips the password from a DSN for safe logging.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	return u.Redacted()
}

func openDB(ctx context.Context, dsn string) (*hopper.DB, error) {
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		dsn = "postgres://hopper@hopper-db:5432/hopper"
	}
	slog.Info("connecting to database", "dsn", redactDSN(dsn)) //nolint:gosec // dsn is redacted before logging
	return hopper.Open(ctx, dsn)
}

func cmdServe(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	f := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := f.String("dir", filepath.Join(home, ".hopper"), "data directory")
	port := f.Int("port", 5433, "listen port")
	parseFlags(f, os.Args[2:])

	pgdata := filepath.Join(*dir, "pgdata")
	p := strconv.Itoa(*port)

	// Initialize data directory if needed.
	if _, err := os.Stat(filepath.Join(pgdata, "PG_VERSION")); err != nil {
		slog.Info("initializing postgres")
		out, err := exec.CommandContext(ctx, "initdb",
			"-D", pgdata,
			"--auth=trust",
			"--no-locale",
			"-E", "UTF8",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("initdb: %w\n%s", err, out)
		}
	}

	// Start postgres in foreground. Ctrl-c sends SIGINT to the process
	// group, which postgres handles as a graceful shutdown.
	pg := exec.CommandContext(ctx, "postgres", "-D", pgdata, "-p", p)
	pg.Stdout = os.Stdout
	pg.Stderr = os.Stderr
	if err := pg.Start(); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}

	// Wait for readiness.
	ready := false
	for range 30 {
		if exec.CommandContext(ctx, "pg_isready", "-p", p, "-h", "localhost", "-q").Run() == nil {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		killProcessBestEffort("failed to kill postgres after readiness timeout", pg.Process)
		return errors.New("postgres did not become ready within 15s")
	}

	// Create database (ignore "already exists" error).
	createdb := exec.CommandContext(ctx, "createdb", "-p", p, "-h", "localhost", "hopper")
	if err := createdb.Run(); err != nil {
		slog.Debug("createdb returned non-fatal error", "error", err)
	}

	// Run migrations.
	dsn := fmt.Sprintf("postgres://localhost:%s/hopper", p)
	db, err := hopper.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return fmt.Errorf("migrate: %w", err)
	}
	db.Close()

	slog.Info("hopper ready", "dsn", dsn)

	waitCmdBestEffort("postgres exited", pg)
	return nil
}

func cmdInit(ctx context.Context) error {
	f := flag.NewFlagSet("init", flag.ExitOnError)
	dsn := f.String("db", "", "database (postgres:// DSN or sqlite file path)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("schema up to date")
	return nil
}

func cmdImport(ctx context.Context) error {
	f := flag.NewFlagSet("import", flag.ExitOnError)
	dstDSN := f.String("db", "", "destination database")
	srcDSN := f.String("from", "", "source database")
	afterSample := f.Int64("after", 0, "resume after this source sample ID (from progress logs)")
	afterReport := f.Int64("after-report", 0, "resume after this source report ID (from progress logs)")
	parseFlags(f, os.Args[2:])

	if *srcDSN == "" {
		return errors.New("pass --from (source database)")
	}

	dst, err := openDB(ctx, *dstDSN)
	if err != nil {
		return err
	}
	defer dst.Close()
	slog.Info("running schema migrations on destination")
	if err := dst.Migrate(ctx); err != nil {
		return err
	}

	slog.Info("opening source database", "dsn", *srcDSN)
	src, err := hopper.Open(ctx, *srcDSN)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	slog.Info("starting transfer", "resume_after_sample", *afterSample, "resume_after_report", *afterReport)
	samples, reports, err := hopper.TransferSamples(ctx, dst, src, *afterSample, *afterReport)
	if err != nil {
		return err
	}
	slog.Info("transfer complete", "samples", samples, "reports", reports)
	return nil
}

func cmdIngestReports(ctx context.Context) error {
	f := flag.NewFlagSet("ingest-reports", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dir := f.String("dir", "reports", "directory containing cyclotron reports named <sha256>.md")
	reportType := f.String("type", "re", "report type to store")
	provider := f.String("provider", "cyclotron", "report provider name")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	stats, err := db.IngestReportsDir(ctx, *dir, *reportType, *provider)
	if err != nil {
		return err
	}
	slog.Info("report ingest complete",
		"dir", *dir,
		"type", *reportType,
		"scanned", stats.Scanned,
		"inserted", stats.Inserted,
		"skipped_existing", stats.SkippedExisting,
		"skipped_missing_sample", stats.SkippedMissingSample,
		"skipped_invalid", stats.SkippedInvalid)
	return nil
}

func cmdReset(ctx context.Context) error {
	f := flag.NewFlagSet("reset", flag.ExitOnError)
	dsn := f.String("db", "", "database (postgres:// DSN or sqlite file path)")
	keepCache := f.Bool("keep-cache", false, "keep the local hash cache (default: deleted so next load re-hashes every file)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	slog.Info("deleting all samples, sample_locations, and reports")
	if err := db.DeleteAll(ctx); err != nil {
		return err
	}

	// The hash cache maps (dev,inode,size,mtime) → (sha256, inserted).
	// After a DB reset, every entry still says "inserted=true", so the
	// walker would skip inserting any file it's hashed before. Drop the
	// cache — both the current XDG-compliant location and the legacy
	// ~/.hopper/hashcache.db (in case the migration hasn't happened yet
	// on this machine).
	if !*keepCache {
		paths := []string{filepath.Join(xdgCacheDir(), "hashcache.db")}
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".hopper", "hashcache.db"))
		}
		for _, p := range paths {
			if err := os.Remove(p); err == nil {
				slog.Info("cleared hash cache", "path", p)
			} else if !errors.Is(err, os.ErrNotExist) {
				slog.Warn("could not remove hash cache", "path", p, "error", err)
			}
			for _, ext := range []string{"-wal", "-shm"} {
				_ = os.Remove(p + ext) //nolint:errcheck // best-effort cleanup
			}
		}
	}

	slog.Info("reset complete")
	return nil
}

func cmdLoad(ctx context.Context) error { //nolint:nolintlint,revive,maintidx,gocognit // complex command setup function.
	f := flag.NewFlagSet("load", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dataDir := f.String("data", "", "data directory containing bad/, good/, unknown/ subdirectories")
	source := f.String("source", hopper.SourceFilesystem,
		"source tag for top-level rows this walk inserts that no collector already recorded "+
			"(default \"fs\"; forager direct-inserts its own rows as \"forager\")")
	// Deprecated: serving no longer prunes. Pruning location rows for gone files
	// moved to the `hopper prune` subcommand so the ingest loop is never
	// destructive and a partial mirror can't mark present-in-corpus files missing.
	// Accepted (and ignored) so older unit files that still pass it keep booting.
	_ = f.Bool("prune-missing-paths", false, "deprecated no-op; run `hopper prune` instead")
	// Set when this host's data root deliberately does not hold the full corpus
	// (e.g. the historical samples are unavailable). Treats local disk as non-
	// authoritative: locally-absent files are never marked skip='missing', so they
	// stay trainable and the marking never replicates. Reconcile still relabels
	// pool moves among the present files. New/present files still ingest normally.
	datasetIncomplete := f.Bool("dataset-incomplete", false,
		"data root does not hold the full sample set; do not mark locally-absent "+
			"files missing (reconcile still relabels local pool moves)")
	hashWorkers := f.Int("hash-workers", 8, "concurrent hash/insert workers for file walking")
	cleaveBinFlag := f.String("cleave", "cleave", "path to cleave binary (used for file enumeration)")
	litmusBin := f.String("litmus", "atomscan", "path to the Atomdrift Scan binary (atomscan; codename litmus; pass empty to disable)")
	litmusWorkers := f.Int("workers", 56, "concurrent analysis workers for the local atomscan worker (0 = auto: min(2, cores/2))")
	// Remote litmus workers self-register via the pull API; no --litmus-nodes flag needed.
	maxRSSGB := f.Int("max-memory-gb", 48,
		"local atomscan worker RSS limit in GB, forwarded as --max-rss-gb (0 = auto: let atomscan self-throttle, -1 = disable in-process throttling)")
	rescan := f.Bool("rescan", false, "re-analyze samples that already have litmus results")
	rescanAge := f.Duration("rescan-age", 120*time.Hour, "minimum age before a stale-traits sample is eligible for rescan")
	noCache := f.Bool("no-cache", false, "disable hash cache (re-read every file)")
	maxAnalyzed := f.Int("max-analyzed", 0, "stop after N successful analyses (0 = unlimited)")
	experimentTag := f.String("experiment-tag", "", "label for experiment comparison")
	// Off by default: --verbose makes the worker log a DEBUG line per analyzed
	// file, which runs 0.5-1.3 GB per spawn. That buries the crash tail hopper
	// attaches to its own logs (large enough that Grafana Cloud rejected the
	// push outright: "structured metadata too large") and filled the state dir
	// with 14 GB on 2026-08-10. Turn it on deliberately when debugging a worker.
	litmusVerbose := f.Bool("litmus-verbose", false, "enable debug logging in litmus server")
	dashAddr := f.String("dashboard-addr", "0.0.0.0:8081", "web dashboard listen address (empty to disable)")
	pprofAddr := f.String("pprof-addr", "127.0.0.1:6060", "net/http/pprof listen address; loopback-only by default (empty to disable)")
	localOnly := f.Bool("local", false, "listen only on loopback for dashboard and worker API")
	maxFileMB := f.Int64("max-file-size", defaultMaxFileSize/(1024*1024), "skip files larger than this many MiB")
	reportsDir := f.String("reports-dir", "", "cyclotron reports directory to ingest (<sha>.md, optional)")
	var forceRescanDirs stringListFlag
	f.Var(&forceRescanDirs, "force-rescan", "directory prefix to force re-analysis for; may be repeated or comma-separated")
	parseFlags(f, os.Args[2:])
	explicitLitmusBin := flagWasSet(f, "litmus")
	explicitCleaveBin := flagWasSet(f, "cleave")
	if flagWasSet(f, "prune-missing-paths") {
		slog.Warn("--prune-missing-paths is deprecated and ignored; serving no longer prunes — run `hopper prune` instead")
	}

	if *maxFileMB > 0 {
		maxFileSize = *maxFileMB * 1024 * 1024
	}
	if *localOnly && *dashAddr != "" {
		*dashAddr = localListenAddr(*dashAddr)
	}

	if *dataDir == "" {
		return errors.New("pass --data <directory> (expects bad/, good/, unknown/ subdirectories)")
	}

	// Resolve symlinks and make absolute early so that all paths derived
	// from dataDir (loadDirs, DB rows, API prefix stripping) are consistent.
	if resolved, err := filepath.EvalSymlinks(*dataDir); err == nil {
		*dataDir = resolved
	}
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
	}

	cleaveBinary = *cleaveBinFlag

	// Start the web dashboard first so it's reachable while everything
	// else is still initializing. configure() is called inside loadAll
	// once the session state is ready.
	// Create shared HTTP mux for dashboard + work API.
	// API handlers are registered immediately so workers connecting during
	// startup get a clean 503 instead of the dashboard's HTML.
	// pprof on a dedicated loopback listener — never the public dashboard mux.
	// net/http/pprof registers on http.DefaultServeMux, which nothing else
	// serves, so the profiles are reachable only from the host (or an SSH
	// tunnel). Critical for diagnosing heap/goroutine growth without a redeploy.
	if *pprofAddr != "" {
		pprofSrv := &http.Server{Addr: *pprofAddr, Handler: http.DefaultServeMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := pprofSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Warn("pprof listener stopped", "addr", *pprofAddr, "error", err)
			}
		}()
		go func() { <-ctx.Done(); _ = pprofSrv.Close() }() //nolint:errcheck // best-effort shutdown
		slog.Info("pprof listening", "addr", *pprofAddr)
	}

	httpMux := http.NewServeMux()
	tracker := newWorkerTracker()
	// Cap concurrent archive-member extractions to the CPU count (decompression
	// is CPU-bound), clamped so a many-core host can't pile up unbounded disk
	// spooling from a request burst.
	api := &apiServer{
		tracker:     tracker,
		hopperStart: time.Now().UTC(),
		extractSem:  make(chan struct{}, min(16, max(2, runtime.NumCPU()))),
		// Result ingestion is memory-bound (each store expands an envelope to
		// several times its size), not CPU-bound, so cap it tighter than
		// extraction: enough for steady throughput, low enough that a burst of
		// large archive results can't blow up the heap.
		resultSem: make(chan struct{}, min(8, max(2, runtime.NumCPU()))),
	} // db, progress, allowedDirs, uploadTokenHash set after init
	api.registerAPI(httpMux)
	httpMux.HandleFunc("GET /_/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) //nolint:errcheck // best-effort HTTP response
	})
	httpMux.Handle("GET /_/metrik", obs.MetricsHandler())

	var wd *webDashboard
	if *dashAddr != "" {
		wd = &webDashboard{}
		if err := startWebDashboard(ctx, *dashAddr, wd, httpMux); err != nil {
			slog.Warn("web dashboard disabled", "error", err)
			wd = nil
		} else {
			slog.Info("web dashboard + API listening", "addr", *dashAddr)
			// Publish the dashboard's numerics at /_/metrik. Registered now;
			// the callback no-ops until the load session is configured.
			if err := wd.enableMetrics(); err != nil {
				slog.Warn("dashboard metrics disabled", "error", err)
			}
		}
	}
	// Feed the systemd watchdog (no-op outside a watchdog-armed unit). Started
	// after the listener so the self-probe tests a socket that should exist.
	go runSDWatchdog(ctx, *dashAddr)
	// Carve the delegated workers/ cgroup before anything spawns children, so
	// litmus and cleave land under the kernel-enforced budget from the start.
	setupWorkerCgroup(*maxRSSGB)
	wd.beginStage("discover", "Discovering label directories")

	// Discover label directories under --data.
	// Convention: each pool directory maps 1:1 to its label — bad/, good/,
	// sighted/ (feed claims pending verification), unknown/.
	var loadDirs []struct{ dir, label string }
	for _, entry := range []struct{ name, label string }{
		{"bad", "bad"},
		{"good", "good"},
		{"sighted", "sighted"},
		{"unknown", "unknown"},
	} {
		dir := filepath.Join(*dataDir, entry.name)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			loadDirs = append(loadDirs, struct{ dir, label string }{dir, entry.label})
		}
	}
	if len(loadDirs) == 0 {
		wd.failStage("discover", fmt.Sprintf("no bad/, good/, sighted/, or unknown/ in %s", *dataDir))
		return fmt.Errorf("no bad/, good/, sighted/, or unknown/ subdirectories found in %s", *dataDir)
	}
	wd.endStage("discover")

	prepStart := time.Now()

	// Rebuild sibling tools only when Hopper is using the default tool names.
	// If the caller supplied --litmus or --cleave, that path is authoritative
	// and should not be shadowed by `make install` into another location.
	litmusBuildCh := make(chan struct{}, 1)
	cleaveBuildCh := make(chan struct{}, 1)
	go func() {
		if explicitLitmusBin {
			slog.Info("skipping litmus rebuild for explicit binary", "bin", *litmusBin)
		} else {
			wd.beginStage("build.scan", "Building Atomdrift Scan")
			updateSiblingTool(ctx, "scan", "../scan")
			wd.endStage("build.scan")
		}
		litmusBuildCh <- struct{}{}
	}()
	go func() {
		if explicitCleaveBin {
			slog.Info("skipping cleave rebuild for explicit binary", "bin", *cleaveBinFlag)
		} else {
			wd.beginStage("build.cleave", "Building cleave")
			updateSiblingTool(ctx, "cleave", "../cleave")
			wd.endStage("build.cleave")
		}
		cleaveBuildCh <- struct{}{}
	}()
	<-litmusBuildCh
	<-cleaveBuildCh

	// With a freshly built binary, pull latest rules and check the version.
	var traitsVersion string
	if *litmusBin != "" {
		wd.beginStage("litmus.rules", "Refreshing litmus rules")
		refreshToolRules(ctx, "litmus", *litmusBin)
		traitsVersion = litmusTraitsVersion(ctx, *litmusBin)
		wd.endStage("litmus.rules")
		if traitsVersion != "" {
			slog.Info("traits version for rescan", "version", traitsVersion)
		}
		// Cleave-traits validation is no longer a one-shot gate here: it runs
		// inside superviseLocalWorker, which retries it (and re-pulls rules)
		// forever so a transient failure — e.g. traits still landing after a
		// fresh fetch — never disables the local worker.
	}

	// Start the local scan (atomscan) worker under a supervisor that never gives
	// up: it waits for cleave traits to validate, starts the worker, and lets
	// Monitor restart it on every crash — all in the background, so a flaky local
	// worker never blocks ingestion (remote workers keep running). Failures
	// surface on the dashboard banner via the server's published health.
	var litmus *litmusServer
	if *litmusBin != "" {
		// Local worker always connects to loopback. Replace 0.0.0.0 with
		// 127.0.0.1 since 0.0.0.0 is a bind address, not a destination.
		hopperURL := "http://127.0.0.1:8081"
		if *dashAddr != "" {
			addr := *dashAddr
			if after, ok := strings.CutPrefix(addr, "0.0.0.0:"); ok {
				addr = "127.0.0.1:" + after
			}
			hopperURL = "http://" + addr
		}
		litmus = newLitmusServer(litmusConfig{
			Bin:        *litmusBin,
			HopperURL:  hopperURL,
			DataDir:    *dataDir,
			MaxRSSGB:   *maxRSSGB,
			MaxWorkers: *litmusWorkers,
			Verbose:    *litmusVerbose,
		})
		litmus.tracker = tracker
		litmus.workerName = "local"
		litmus.setHealth(false, "starting", "")
		defer litmus.Stop()
		go superviseLocalWorker(ctx, litmus, *cleaveBinFlag)
	}

	// Run independent startup work in parallel: hash cache load, DB
	// connect+migrate, and file enumeration alongside litmus startup.
	var dirNames []string
	for _, d := range loadDirs {
		dirNames = append(dirNames, d.label)
	}
	attrs := []any{
		"data", *dataDir,
		"labels", dirNames,
		"workers", *hashWorkers,
		"rescan", *rescan,
		"cache", !*noCache,
		"max_analyzed", *maxAnalyzed,
		"experiment", *experimentTag,
	}
	attrs = append(attrs, runtimeIdentityAttrs()...)
	slog.Info("load starting", attrs...)

	// Start file enumeration early — cleave iter-files doesn't need the
	// hash cache or database, so overlap it with those slower init steps.
	fileChs := make([]<-chan labeledPath, len(loadDirs))
	for i, d := range loadDirs {
		fileChs[i] = startEnumeration(ctx, d.dir, time.Time{}) // full enumeration on startup
	}

	type cacheResult struct {
		cache *hashCache
		err   error
	}
	cacheCh := make(chan cacheResult, 1)
	go func() {
		if *noCache {
			cacheCh <- cacheResult{}
			return
		}
		wd.beginStage("cache.load", "Loading hash cache")
		c, err := openHashCache(ctx, hashCachePath())
		if err != nil {
			slog.Warn("hash cache load failed; continuing without it", "error", err, "path", hashCachePath())
			wd.failStage("cache.load", err.Error())
		} else {
			wd.endStage("cache.load")
		}
		cacheCh <- cacheResult{cache: c, err: err}
	}()

	type dbResult struct {
		db           *hopper.DB
		buildIndexes func(context.Context) error
		err          error
	}
	dbCh := make(chan dbResult, 1)
	dbStart := time.Now()
	var dbPhase atomic.Value
	dbPhase.Store("queued")
	dbPhaseString := func() string {
		if phase, ok := dbPhase.Load().(string); ok {
			return phase
		}
		return "unknown"
	}
	go func() {
		dbPhase.Store("connecting")
		slog.Info("database startup task started", "phase", dbPhaseString())
		wd.beginStage("db.connect", "Connecting to database")
		d, err := openDB(ctx, *dsn)
		if err != nil {
			wd.failStage("db.connect", err.Error())
			dbPhase.Store("connect failed")
			slog.Error("database connection failed", "elapsed", time.Since(dbStart), "error", err)
			dbCh <- dbResult{err: err}
			return
		}
		wd.endStage("db.connect")
		slog.Info("database connection established", "elapsed", time.Since(dbStart))
		dbPhase.Store("migrating schema")
		wd.beginStage("db.migrate", "Migrating database")
		slog.Info("running schema migrations")
		// Apply only the migrations needed before serving (schema, columns,
		// extensions). Index builds are returned and run in the background once
		// the API is up — building a new index on the multi-million-row samples
		// table can take many minutes, and blocking startup on it strands every
		// worker with 503s for the duration.
		buildIndexes, err := d.MigrateServing(ctx)
		if err != nil {
			wd.failStage("db.migrate", err.Error())
			d.Close()
			dbPhase.Store("migration failed")
			slog.Error("schema migrations failed", "elapsed", time.Since(dbStart), "error", err)
			dbCh <- dbResult{err: err}
			return
		}
		wd.endStage("db.migrate")
		dbPhase.Store("complete")
		slog.Info("database startup task complete", "elapsed", time.Since(dbStart))
		dbCh <- dbResult{db: d, buildIndexes: buildIndexes}
	}()

	// Remote litmus workers now self-register via the pull API.
	// No dialing needed — they poll /api/next when ready.

	// Collect results. Order doesn't matter — each blocks until ready.
	slog.Info("waiting for hash cache")
	cr := <-cacheCh
	var cache *hashCache
	if cr.err != nil {
		slog.Warn("hash cache unavailable, continuing without cache", "error", cr.err)
	} else {
		cache = cr.cache
		if cache != nil {
			defer cache.close(ctx)
		}
	}

	var dr dbResult
	select {
	case dr = <-dbCh:
	default:
		waitStart := time.Now()
		slog.Info("waiting for database connect/migrate task", "phase", dbPhaseString(), "already_elapsed", time.Since(dbStart))
		dr = <-dbCh
		slog.Info("database startup wait complete", "phase", dbPhaseString(), "waited", time.Since(waitStart), "total_elapsed", time.Since(dbStart))
	}
	if dr.err != nil {
		return dr.err
	}
	db := dr.db
	defer db.Close()
	slog.Info("database ready", "elapsed", time.Since(dbStart))

	if err := obs.PoolStats("hopper", db.Pool()); err != nil {
		slog.Warn("pool stats registration", "error", err)
	}

	// Periodic pgxpool stats so saturation is visible. Without this, a
	// connection-starved pool looks like "the dashboard is slow" with no
	// further signal.
	go logPoolStatsLoop(ctx, db)

	forcePrefixes, err := normalizeForceRescanDirs(*dataDir, forceRescanDirs)
	if err != nil {
		return err
	}
	api.forceRescanPrefixes = forcePrefixes
	if len(forcePrefixes) > 0 {
		slog.Info("force rescan enabled", "paths", forcePrefixes, "since", api.hopperStart)
	}

	// Claims live in workerTracker (in-memory only), so a fresh process
	// starts with an empty claim set — nothing to clear here.

	if litmus != nil {
		// The scan worker self-updates rules every 10 minutes via its
		// own spawn_resource_renewal_task (in worker.rs). We poll the
		// resulting traits version on the same cadence so the dashboard's
		// "is this worker stale?" check measures against the live local
		// litmus, not the snapshot taken at startup. No external restart
		// needed — the worker reloads its capability mapper in-place.
		// 10-minute cadence trades a bit of git-pull traffic for faster
		// rule rollout to the fleet.
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if v := litmusTraitsVersion(ctx, *litmusBin); v != "" {
						api.SetTraitsVersion(v)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	loadCtx, loadCancel := context.WithCancel(ctx)
	defer loadCancel()

	// Wire the API server now that the DB is ready.
	var allowedDirs []string
	for _, d := range loadDirs {
		if resolved, err := filepath.EvalSymlinks(d.dir); err == nil {
			allowedDirs = append(allowedDirs, resolved)
		} else if abs, err := filepath.Abs(d.dir); err == nil {
			allowedDirs = append(allowedDirs, abs)
		}
	}
	// dataDir was already resolved (symlinks + absolute) at startup.
	api.db = db
	api.dataRoot = *dataDir
	api.datasetIncomplete = *datasetIncomplete
	api.allowedDirs = allowedDirs

	// Nested-archive extraction spools intermediate containers to disk before
	// descending. The default temp location is often a tmpfs (RAM) under
	// PrivateTmp, which would put a multi-GB inner archive back in memory; keep
	// it on the data volume instead. Use the upload temp dir: it sits under the
	// service's one writable path (systemd ReadWritePaths=<uploadDir>), unlike
	// the samples root which another service owns and hopper cannot write. On
	// failure, leave the default in place — the WARN is the canary that the
	// spool fell back to tmpfs.
	if *dataDir != "" {
		spool := filepath.Join(*dataDir, uploadDir, ".tmp")
		if err := mkdirSharedAll(spool); err != nil {
			slog.Warn("nested-archive spool dir unavailable; using default temp (may be tmpfs)", "dir", spool, "error", err)
		} else {
			hopper.NestedSpoolDir = spool
		}
	}

	// Decompressed-parent cache: compressed-tar archives (tar.xz/zst/gz/bz2) are
	// not seekable, so without it every member fetch re-runs the whole
	// decompressor — the O(N×M) cost that exhausts extraction slots and times
	// clients out under a many-member workload. Cache the decompressed tar on the
	// data volume, keyed by parent SHA, so members decompress once. The build
	// holds an extraction slot; cache hits do not. Budget is operator-tunable;
	// zero disables it.
	if *dataDir != "" {
		total := envBytes("HOPPER_EXTRACT_CACHE_BYTES", defaultExtractCacheBytes)
		perEntry := envBytes("HOPPER_EXTRACT_CACHE_MAX_ENTRY_BYTES", defaultExtractCacheEntryBytes)
		cacheDir := filepath.Join(*dataDir, uploadDir, ".extract-cache")
		if ec, err := newExtractCache(cacheDir, total, perEntry, api.acquireExtract, api.releaseExtract); err != nil {
			slog.Warn("extract cache disabled; archive members will decompress per request", "dir", cacheDir, "error", err)
		} else if ec != nil {
			api.extractCache = ec
			defer ec.close()
			slog.Info("extract cache enabled", "dir", cacheDir, "budget_bytes", total, "max_entry_bytes", perEntry)
		}
	}

	api.SetTraitsVersion(traitsVersion)
	api.rescanAge = *rescanAge

	// Build deferred indexes in the background now that the API is serving.
	// On an established database these are ledger-skipped no-ops; a genuinely
	// new index warms up without blocking workers, who keep running on the
	// existing query plans until it becomes valid. Uses the root ctx (not
	// loadCtx) so a long build isn't cut short by load completion.
	if dr.buildIndexes != nil {
		go func() {
			if err := dr.buildIndexes(ctx); err != nil {
				slog.Warn("background index migration failed; queries may be slower until next restart", "error", err)
			}
		}()
	}

	// Archive members are now persisted atomically with the parent in
	// StoreResult (the /api/result handler), so there's no background expansion
	// pool to start or drain.

	// Reap orphaned upload temp files left by a previous crash. No-op when
	// the directory doesn't exist yet.
	api.sweepUploadTmp()

	// Resolve the upload token: env override > persisted DB value >
	// generated-and-persisted. The plaintext is scoped to this block; only
	// the SHA-256 lives in api once setUploadToken returns. Prism reads
	// the persisted value from hopper_kv to discover the same token.
	bootstrapUploadToken(ctx, api, db)
	if api.uploadTokenSet && *dashAddr != "" && !isLoopbackAddr(*dashAddr) {
		slog.Warn("dashboard bound to non-loopback; /api/file and /data remain unauthenticated",
			"addr", *dashAddr,
			"recommendation", "run with --local or behind an authenticated reverse proxy")
	}

	slog.Info("load prep complete",
		"elapsed", time.Since(prepStart),
		"dirs", len(loadDirs),
		"allowed_dirs", len(allowedDirs),
		"local_litmus", litmus != nil,
		"cache", cache != nil,
		"next", "load samples")

	total := loadAll(loadCtx, loadCancel, db, litmus, tracker, api, cache,
		loadDirs, fileChs, *source, *hashWorkers, *rescan, *maxAnalyzed, *experimentTag, wd, traitsVersion, *rescanAge)
	if *reportsDir != "" {
		wd.beginStage("reports.ingest", "Ingesting reports")
		stats, err := db.IngestReportsDir(ctx, *reportsDir, "re", "cyclotron")
		if err != nil {
			slog.Error("report ingest failed", "error", err, "dir", *reportsDir)
			wd.failStage("reports.ingest", err.Error())
			return err
		}
		wd.endStage("reports.ingest")
		slog.Info("report ingest complete",
			"dir", *reportsDir,
			"scanned", stats.Scanned,
			"inserted", stats.Inserted,
			"skipped_existing", stats.SkippedExisting,
			"skipped_missing_sample", stats.SkippedMissingSample,
			"skipped_invalid", stats.SkippedInvalid)
	}
	servingAPI := *dashAddr != ""
	slog.Info("file walk complete",
		"samples", total,
		"serving_api", servingAPI,
		"local_litmus", litmus != nil)

	// Serving never prunes: statting the tree to delete "missing" location rows is
	// wrong on a host that holds only part of the corpus, and even on the full
	// mirror it's a destructive maintenance step that shouldn't ride the ingest
	// loop. Pruning now lives in the explicit `hopper prune` subcommand.

	// Block while there is something useful to keep alive: the dashboard/API
	// for remote workers, or the local litmus worker process.
	if servingAPI || litmus != nil {
		slog.Info("load service running until interrupted",
			"serving_api", servingAPI,
			"local_litmus", litmus != nil)
		<-ctx.Done()
		slog.Info("load service shutting down", "reason", ctx.Err())
	} else {
		slog.Info("load service exiting after file walk",
			"reason", "no dashboard/API listener and no local litmus worker")
	}
	return nil
}

// loadProgress tracks counters across concurrent load workers.
type loadProgress struct { //nolint:govet // fields grouped by pipeline stage, not alignment
	// Enumeration phase.
	walked   atomic.Int64
	walkDone atomic.Bool

	// Hashing phase.
	hashed     atomic.Int64
	cacheHits  atomic.Int64
	tooSmall   atomic.Int64 // files below minFileSize
	tooLarge   atomic.Int64 // files above maxFileSize
	hashErrors atomic.Int64 // hash failures (subset of errors)

	// Insert phase.
	inserted atomic.Int64
	skipped  atomic.Int64
	markers  atomic.Int64 // files skipped due to misclassification markers
	queued   atomic.Int64 // items sent for analysis
	exploded atomic.Int64 // archive members inserted

	// Analysis phase.
	analyzed           atomic.Int64
	startAnalyzed      atomic.Int64 // analyzed total carried over from prior runs; session delta = analyzed - startAnalyzed
	analyzeDurationSum atomic.Int64
	analyzeDurationMax atomic.Int64
	analyzeDurationMin atomic.Int64 // initialized to math.MaxInt64
	scoreSum           atomic.Int64

	// Errors.
	errors atomic.Int64
	// insertFails counts failed inserts by cause (indexed by insertFailCause).
	// A subset of errors, broken out so lock-contention stalls are visible
	// apart from malformed input. See recordInsertFailure.
	insertFails [numInsertFailCauses]atomic.Int64
	errMu       sync.Mutex
	errs        []progressError
}

type progressError struct {
	At      time.Time
	Stage   string
	Message string
}

const maxProgressErrors = 5

func (p *loadProgress) recordErrorf(n int64, stage, format string, args ...any) {
	if p == nil {
		return
	}
	if n > 0 {
		p.errors.Add(n)
	}
	msg := fmt.Sprintf(format, args...)
	p.errMu.Lock()
	defer p.errMu.Unlock()
	p.errs = append(p.errs, progressError{
		At:      time.Now(),
		Stage:   stage,
		Message: msg,
	})
	if len(p.errs) > maxProgressErrors {
		p.errs = p.errs[len(p.errs)-maxProgressErrors:]
	}
}

// recordInsertFailure attributes n lost samples to the cause of err and rolls
// the failure into the error log. A batch insert fails all of its rows at once,
// so n is the row count of the failed statement: the per-cause counter reflects
// samples that did not land, not just the number of failed statements.
func (p *loadProgress) recordInsertFailure(n int64, err error) {
	if p == nil {
		return
	}
	cause := classifyInsertFailure(err)
	if n > 0 {
		p.insertFails[cause].Add(n)
	}
	p.recordErrorf(n, "insert", "insert (%s): %v", cause, err)
}

func (p *loadProgress) recentErrors() []progressError {
	if p == nil {
		return nil
	}
	p.errMu.Lock()
	defer p.errMu.Unlock()
	out := make([]progressError, len(p.errs))
	copy(out, p.errs)
	return out
}

const (
	loadBatchSize = 2000
	minFileSize   = 13 // skip trivially small files (markers, empty, etc.)
	// 20 GiB — admit full OS images (ISO/UDF, DMG) from the os-image feed;
	// cleave streams-to-temp and workers are memory-scheduled.
	defaultMaxFileSize = 20 * 1024 * 1024 * 1024
)

const (
	// ingestWalkInterval is how often the backstop walk re-scans the data dir
	// for new files forager's direct-insert missed. After the first full pass
	// each walk is incremental (only files modified since the previous walk
	// began), so it stays cheap.
	ingestWalkInterval = 30 * time.Minute
	// reconcileWalkInterval is the slower cadence for a full walk that also
	// reconciles pools (detects moved/missing/relabeled files). It is kept
	// separate from ingest so the expensive reconcile never gates ingestion.
	reconcileWalkInterval = 6 * time.Hour
	// reconcileTimeout bounds a single ReconcilePools pass. A reconcile that
	// once ran unbounded for over an hour stranded all ingestion; capping it
	// means a pathological pass is abandoned and retried next cycle instead.
	reconcileTimeout = 20 * time.Minute
)

// maxFileSize is the per-file byte cap applied during enumeration, hashing,
// and analysis. Overridable via the load command's --max-file-size flag.
var maxFileSize int64 = defaultMaxFileSize

var (
	errTooSmall = errors.New("too small")
	errTooLarge = errors.New("too large")
)

// loadAll orchestrates a load: analysis workers, a progress dashboard, and
// one per-directory pipeline goroutine that owns cleave→hash→batch→insert
// for its directory and queues analysis jobs directly. Everything waits on
// the directory pipelines; then the analysis queue is closed and drained;
// then the summary is logged. nworkers bounds how many directory pipelines
// may run concurrently (irrelevant for typical 3-dir loads).
func loadAll( //nolint:nolintlint,revive // many params reflect the many subsystems coordinated here.
	ctx context.Context,
	_ context.CancelFunc,
	db *hopper.DB,
	litmus *litmusServer,
	tracker *workerTracker,
	api *apiServer,
	cache *hashCache,
	dirs []struct{ dir, label string },
	fileChs []<-chan labeledPath,
	source string,
	nworkers int,
	_ bool,
	maxAnalyzed int,
	experimentTag string,
	wd *webDashboard,
	traitsVersion string,
	rescanAge time.Duration,
) int {
	slog.Info("loading", "dirs", len(dirs))
	start := time.Now()

	// markMissing is false when the data root deliberately holds only part of the
	// corpus (--dataset-incomplete). Reconcile still runs — so bad<->good pool
	// moves among the locally-present files are relabeled — but the passes that
	// treat a locally-absent file as gone (mark skip='missing'/'unsupported' and
	// the archive-member cascade) are suppressed: here "not on this host" does not
	// mean "gone from the corpus", and marking it would drop the record from
	// training and replicate to the primary.
	markMissing := api == nil || !api.datasetIncomplete

	var progress loadProgress
	progress.analyzeDurationMin.Store(math.MaxInt64)

	// Wire the API server's progress pointer so /api/result can update counters.
	if api != nil {
		api.progress = &progress
	}

	// Progress dashboard — runs until ctx is cancelled (ctrl-C).
	var dashWG sync.WaitGroup
	dashWG.Go(func() {
		runDashboard(ctx, &progress, litmus, tracker, db, start, maxAnalyzed, len(dirs), traitsVersion, rescanAge)
	})

	// Local time-series cache for the dashboard queue graphs. Historical queue
	// depth can't be reconstructed from the sample table, so the sampler
	// snapshots live counts here. It's a pure cache (lives in the OS cache
	// dir); failing to open it only costs graph history.
	var metrics *metricsStore
	if wd != nil {
		if ms, err := openMetricsStore(ctx, metricsDBPath()); err != nil {
			slog.Warn("queue metrics cache disabled", "error", err)
		} else {
			metrics = ms
			defer func() {
				if err := metrics.close(); err != nil {
					slog.Debug("close metrics cache failed", "error", err)
				}
			}()
		}
		wd.configure(&progress, litmus, tracker, api, db, start, maxAnalyzed, len(dirs), traitsVersion, rescanAge, metrics)
	}

	// Seed the progress denominators carried over from prior runs off the
	// startup critical path. CountAnalyzed/CountPending are full count(*) scans
	// over the samples table whose supporting partial indexes
	// (idx_samples_litmus_done, idx_samples_unanalyzed_id) may still be building
	// in the background after a deploy — a fresh index build can leave them
	// taking minutes. The dashboard is already configured above, so it switches
	// to the live view immediately and these baselines fill in once the counts
	// return; until then the session delta is simply measured from zero.
	go seedProgressBaseline(ctx, db, &progress)

	// Queue maintenance: reap poison samples and (when the cache is open)
	// sample queue depths for the graphs, on one ticker tied to ctx.
	dashWG.Go(func() {
		runQueueMaintenance(ctx, db, &progress, metrics, traitsVersion, rescanAge)
	})

	// runWalk executes one enumeration→hash→insert pass across all dirs. When
	// cutoff is non-zero the enumeration is incremental — only files modified at
	// or after cutoff are considered. When reconcile is true the pass also
	// records a present-set in walk_staging and runs ReconcilePools; otherwise
	// it is a pure ingest pass that never touches the staging table.
	runWalk := func(chs []<-chan labeledPath, cutoff time.Time, reconcile bool) {
		// Only a reconcile pass touches walk_staging: it records a fresh
		// present-set that ReconcilePools anti-joins against samples to find
		// moved/missing files. Ingest passes skip staging entirely, so they
		// never contend on the table and an incremental (partial) present-set
		// can never make live files look missing. If the table can't be cleared
		// we skip reconcile rather than stage onto a stale set (the original
		// cause of unbounded walk_staging growth).
		stageOK := false
		if reconcile {
			if err := db.StartWalkStaging(ctx); err != nil {
				slog.Error("walk staging clear failed; skipping reconcile this pass", "error", err)
			} else {
				stageOK = true
			}
		}

		// Reset walk-phase counters so they reflect the current pass, not a
		// cumulative total across re-walks.
		progress.walked.Store(0)
		progress.hashed.Store(0)
		progress.inserted.Store(0)
		progress.skipped.Store(0)
		progress.cacheHits.Store(0)
		progress.tooSmall.Store(0)
		progress.tooLarge.Store(0)
		progress.hashErrors.Store(0)

		if chs == nil {
			chs = make([]<-chan labeledPath, len(dirs))
			for i, d := range dirs {
				chs[i] = startEnumeration(ctx, d.dir, cutoff)
			}
		}

		sem := make(chan struct{}, max(1, nworkers))
		var pipeWG sync.WaitGroup
		for i, d := range dirs {
			ch := chs[i]
			pipeWG.Go(func() {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				runDirPipeline(ctx, db, d, source, cache, &progress, ch, stageOK)
			})
		}
		pipeWG.Wait()
		progress.walkDone.Store(true)

		// Reconcile the derived label/skip cache against the pools, but only
		// after a complete staged walk — a cancelled (partial) walk would make
		// present files look missing. Bounded by reconcileTimeout so a
		// pathological pass is abandoned instead of stranding the walk loop (and
		// with it all ingestion), as an unbounded reconcile once did.
		if stageOK && ctx.Err() == nil {
			reconcilePools(ctx, db, dirs, markMissing)
		}

		logLoadSummary(start, experimentTag, dirs, &progress)
	}

	// Initial pass: a full walk (pre-started enumeration channels) that also
	// reconciles pools. Reconcile is bounded by reconcileTimeout, so it can no
	// longer strand startup the way an unbounded pass once did — yet it still
	// runs on every restart, which matters on a host that recycles more often
	// than reconcileWalkInterval (otherwise reconcile would rarely run at all).
	initialStart := time.Now()
	runWalk(fileChs, time.Time{}, true)

	// Periodic passes pick up files forager's direct-insert missed while workers
	// analyze. Ingest walks are incremental (only files modified since the
	// previous walk began) and skip reconcile, so they stay cheap; a slower full
	// pass also reconciles pools. Both fire from one goroutine via select, so a
	// reconcile and an ingest pass never overlap or contend on walk_staging.
	if litmus != nil {
		go func() {
			lastStart := initialStart
			ingest := time.NewTicker(ingestWalkInterval)
			recon := time.NewTicker(reconcileWalkInterval)
			defer ingest.Stop()
			defer recon.Stop()
			for {
				select {
				case <-ingest.C:
					cutoff := lastStart
					lastStart = time.Now()
					progress.walkDone.Store(false)
					slog.Info("starting incremental ingest walk", "since", cutoff)
					runWalk(nil, cutoff, false)
				case <-recon.C:
					lastStart = time.Now()
					progress.walkDone.Store(false)
					slog.Info("starting full reconcile walk")
					runWalk(nil, time.Time{}, true)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// If there's a litmus server, keep the dashboard running — analysis
	// is still in progress via the pull API. The dashboard goroutine exits
	// when ctx is cancelled (ctrl-C). Without litmus there's nothing to
	// wait for (remote workers also need the server to stay up).
	if litmus != nil {
		dashWG.Wait()
	}

	return int(progress.inserted.Load() + progress.skipped.Load())
}

// reconcilePools anti-joins the just-staged present-set against samples to flag
// moved/missing/relabeled files. It is bounded by reconcileTimeout: an
// unbounded pass once ran for over an hour and stranded all ingestion, so a
// pathological pass is now abandoned and retried next cycle. Only called after a
// complete, staged walk. markMissing=false (--dataset-incomplete) keeps the
// relabel pass but suppresses the missing/unsupported marking and cascade.
func reconcilePools(ctx context.Context, db *hopper.DB, dirs []struct{ dir, label string }, markMissing bool) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	toDiskPath := func(path string) string {
		return sampleDiskPath(filepath.Dir(dirs[0].dir), filepath.FromSlash(path))
	}
	st, err := db.ReconcilePools(ctx, toDiskPath, markMissing)
	if err != nil {
		slog.Error("reconcile pools failed", "error", err)
		return
	}
	if st.Relabeled+st.MarkedMissing+st.MarkedUnsupported+st.CascadedMissing+st.Revived > 0 {
		slog.Info("reconciled pools",
			"relabeled", st.Relabeled,
			"missing", st.MarkedMissing,
			"unsupported", st.MarkedUnsupported,
			"cascaded_missing", st.CascadedMissing,
			"revived", st.Revived)
	}
}

// walkStager batches every standalone file seen this walk into walk_staging,
// which ReconcilePools anti-joins against samples to find moved/missing files.
// Appending to an unlogged staging table is far cheaper than the per-file
// last_seen_at UPDATE it replaces (millions of indexed writes per walk).
type walkStager struct {
	db    *hopper.DB
	batch []hopper.SampleLocationKey
}

func (s *walkStager) add(ctx context.Context, sha, path string) {
	s.batch = append(s.batch, hopper.SampleLocationKey{SHA256: sha, Path: path})
	if len(s.batch) >= loadBatchSize {
		s.flush(ctx)
	}
}

func (s *walkStager) flush(ctx context.Context) {
	if len(s.batch) == 0 {
		return
	}
	if err := s.db.StageLocations(ctx, s.batch); err != nil && ctx.Err() == nil {
		slog.Warn("stage locations failed", "error", err, "batch_size", len(s.batch))
	}
	s.batch = s.batch[:0]
}

// runDirPipeline is the hash→batch→insert pipeline for one labeled directory,
// fed by a pre-started enumeration channel. Everything runs sequentially in
// this one goroutine so batches stay coherent without cross-goroutine plumbing;
// parallelism comes from running one instance per directory.
func runDirPipeline(
	ctx context.Context,
	db *hopper.DB,
	target struct{ dir, label string },
	source string,
	cache *hashCache,
	progress *loadProgress,
	fileCh <-chan labeledPath,
	stage bool,
) {
	batch := make([]*hopper.Sample, 0, loadBatchSize)
	batchKeys := make([]cacheKey, 0, loadBatchSize)
	pathBySha := make(map[string]string, loadBatchSize)

	// On a reconcile pass every standalone file seen is staged for
	// reconciliation, regardless of whether it also goes through the batch
	// insert below. On an ingest pass stage is false and stager stays nil — an
	// incremental walk must not record a partial present-set.
	var stager *walkStager
	if stage {
		stager = &walkStager{db: db}
		defer stager.flush(ctx)
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		n, _, err := db.InsertSampleBatch(ctx, batch)
		if err != nil {
			if ctx.Err() == nil {
				progress.recordInsertFailure(int64(len(batch)), err)
				slog.Error("batch insert failed", "error", err, "batch_size", len(batch), "dir", target.dir)
			}
			batch = batch[:0]
			batchKeys = batchKeys[:0]
			clear(pathBySha)
			return
		}
		progress.inserted.Add(n)
		progress.skipped.Add(int64(len(batch)) - n)
		// Only newly inserted rows; needsAnalysis also includes pre-existing
		// unanalyzed samples, which would double-count on each periodic re-walk.
		progress.queued.Add(n)

		// Mark entries as inserted in the hash cache so future startups
		// can skip the DB round-trip entirely.
		if cache != nil && len(batchKeys) > 0 {
			cache.markInserted(ctx, batchKeys)
		}

		batch = batch[:0]
		batchKeys = batchKeys[:0]
		clear(pathBySha)
	}
	defer flush()

	for lp := range fileCh {
		if ctx.Err() != nil {
			break
		}
		if isMarkerFile(filepath.Base(lp.path)) {
			continue
		}
		if isForagerSidecar(filepath.Base(lp.path)) {
			continue
		}
		lp.label = target.label
		progress.walked.Add(1)
		storedPath := filepath.ToSlash(relativeSamplePath(filepath.Dir(target.dir), lp.path))

		hr, err := hashFile(ctx, lp.path, lp.label, lp.fileType, source, cache, progress)
		if err != nil {
			switch {
			case errors.Is(err, errTooSmall):
				progress.tooSmall.Add(1)
			case errors.Is(err, errTooLarge):
				progress.tooLarge.Add(1)
			default:
				progress.hashErrors.Add(1)
				progress.recordErrorf(1, "hash", "hash: %s: %v", filepath.Base(lp.path), err)
				slog.Warn("hash failed", "path", lp.path, "error", err)
			}
			continue
		}

		progress.hashed.Add(1)

		// Stage every file seen this walk (present at its current pool path) so
		// reconciliation can anti-join walk_staging against samples. Only on a
		// reconcile pass; ingest passes leave stager nil.
		if stager != nil && hr.sample != nil {
			stager.add(ctx, hr.sample.SHA256, storedPath)
		}

		// Cache hit + already inserted into DB → skip the batch insert entirely
		// when there is no path-derived metadata to refresh.
		if hr.inserted && (hr.sample == nil || (hr.sample.Feed == "" && hr.sample.Ecosystem == "")) {
			progress.skipped.Add(1)
			continue
		}

		sample := hr.sample
		sample.Path = storedPath

		// Apply misclassification marker if it contradicts the label.
		if marker, markerMtime := markerInfo(lp.path); marker != "" {
			if (lp.label == "bad" && marker == "benign") || (lp.label == "good" && marker == "bad") {
				progress.markers.Add(1)
				if marker == "benign" {
					sample.Label = "good"
				} else {
					sample.Label = "bad"
				}
				sample.LabelSource = "marker"
				sample.Skip = "misclassified"
				sample.MarkerMtime = markerMtime
				// Debug, not Info: a full re-walk re-emits this for every marker
				// file every cycle, which floods the log on large pools.
				slog.Debug("misclassified file", "path", lp.path, "original_label", lp.label, "marker", marker)
			}
		}

		batch = append(batch, sample)
		batchKeys = append(batchKeys, hr.cacheKey)
		pathBySha[sample.SHA256] = lp.path
		if len(batch) >= loadBatchSize {
			flush()
		}
	}
}

// runQueueMaintenance runs the periodic background jobs that keep the pending
// queue healthy and the dashboard graphs fed. On each tick it reaps poison
// samples (claimed too many times without a result) and, when the metrics
// cache is available, snapshots the live queue depths. It runs the first pass
// immediately so the graphs and reaper don't wait a full interval, then ticks
// until ctx is cancelled.
func runQueueMaintenance(
	ctx context.Context, db *hopper.DB, progress *loadProgress,
	metrics *metricsStore, traitsVersion string, rescanAge time.Duration,
) {
	const interval = 5 * time.Minute
	const retention = 8 * 24 * time.Hour // a little beyond the 72h graph window
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if n, err := db.ReapStuck(ctx); err != nil {
			slog.Warn("reap stuck samples failed", "error", err)
		} else if n > 0 {
			slog.Info("reaped stuck samples", "count", n, "max_attempts", hopper.MaxClaimAttempts)
		}
		if n, err := db.ReapOversized(ctx); err != nil {
			slog.Warn("reap oversized samples failed", "error", err)
		} else if n > 0 {
			slog.Info("reaped oversized samples", "count", n, "max_job_bytes", int64(hopper.MaxJobBytes))
		}
		if metrics != nil {
			sampleQueueMetrics(ctx, db, progress, metrics, traitsVersion, rescanAge, retention)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sampleQueueMetrics records one snapshot of the queue depths plus the
// cumulative completion count into the metrics cache, then prunes points older
// than retention. The completion count is read from the in-memory analyzed
// counter (seeded from the DB at startup, bumped on each stored result) rather
// than a fresh count(*): counting tens of millions of analyzed rows every few
// minutes blew the query timeout and stopped every sample from being recorded.
// Best-effort throughout — a slow count just skips one sample.
func sampleQueueMetrics(
	ctx context.Context, db *hopper.DB, progress *loadProgress, metrics *metricsStore,
	traitsVersion string, rescanAge, retention time.Duration,
) {
	qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
	defer cancel()

	pending, err := db.CountPending(qctx)
	if err != nil {
		slog.Warn("queue metrics: count pending failed", "error", err)
		return
	}
	var rescan int64
	if traitsVersion != "" {
		if n, err := db.CountRescanPending(qctx, traitsVersion, rescanAge); err == nil {
			rescan = n
		} else {
			slog.Debug("queue metrics: count rescan failed", "error", err)
		}
	}
	completed := progress.analyzed.Load()

	// Record/prune on a fresh context: a slow (or timed-out) PG count above
	// must not carry an exhausted deadline into the local SQLite write, or the
	// snapshot is lost even though the values are in hand.
	wctx, wcancel := context.WithTimeout(ctx, dashQueryTimeout)
	defer wcancel()
	if err := metrics.record(wctx, queuePoint{T: time.Now(), Pending: pending, Rescan: rescan, Completed: completed}); err != nil {
		slog.Warn("queue metrics: record failed", "error", err)
		return
	}
	if err := metrics.prune(wctx, time.Now().Add(-retention)); err != nil {
		slog.Debug("queue metrics: prune failed", "error", err)
	}
}

// seedProgressBaseline records the analyzed/queued totals carried over from
// prior runs so the dashboard's session percentage has the right denominator.
// It runs off the startup critical path because the underlying count(*) scans
// can take minutes while their partial indexes are still building in the
// background. The counters are added (not stored) so results that arrive
// before this returns aren't clobbered: the session delta stays correct
// throughout — measured from zero until the baseline lands, then from it.
// Best-effort: a failed count leaves the baseline at its zero value.
func seedProgressBaseline(ctx context.Context, db *hopper.DB, progress *loadProgress) {
	n, err := db.CountAnalyzed(ctx)
	if err != nil {
		slog.Debug("seed baseline: count analyzed failed", "error", err)
		return
	}
	progress.startAnalyzed.Store(n)
	progress.analyzed.Add(n)

	// Without the pending count the denominator reflects all prior work, so
	// pre-existing unanalyzed samples can't push analyzed past queued (>100%).
	pending, err := db.CountPending(ctx)
	if err != nil {
		slog.Debug("seed baseline: count pending failed", "error", err)
		progress.queued.Add(n)
		return
	}
	progress.queued.Add(n + pending)
}

// runDashboard renders the periodic progress view (TTY bars or slog lines)
// until ctx is cancelled. It reads progress counters directly; no
// coordination with workers is required beyond those atomic loads. The pool
// status block is fed by background nodeMonitors so this function never
// blocks on a slow remote.
func runDashboard( //nolint:nolintlint,gocognit,revive,maintidx // complex dashboard loop with many coordinated params.
	ctx context.Context,
	progress *loadProgress,
	_ *litmusServer,
	tracker *workerTracker,
	db *hopper.DB,
	start time.Time,
	maxAnalyzed, ndirs int,
	traitsVersion string,
	rescanAge time.Duration,
) {
	interval := 10 * time.Second
	if !isTTY() {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Ring buffer for 15-minute rolling rate (one sample per tick).
	type sample struct {
		t        time.Time
		byNode   map[string]int64 // keyed by worker name
		count    int64            // session analyzed
		inserted int64            // session inserted (new DB rows)
	}
	const maxSamples = 120 // 10s * 120 = 20 minutes of history
	var samples []sample

	// rescanPending is an index-only count over millions of rows; recompute it at
	// most once a minute (not every tick) and reuse the last value between, so the
	// progress logger neither hammers the DB nor stalls on a slow count.
	const rescanRecompute = time.Minute
	var rescanPending int64
	var lastRescanAt time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var workers []namedWorkerStats
		if tracker != nil {
			workers = tracker.all()
		}

		// Oldest active claim per worker, read from the in-memory tracker.
		oldestClaims := tracker.oldestPerWorker(staleClaimAge)
		var newestAnalyzedAt time.Time
		if db != nil {
			newestAnalyzedAt, _ = db.NewestAnalyzedAt(ctx) //nolint:errcheck // best-effort; zero time is acceptable fallback
			if lastRescanAt.IsZero() || time.Since(lastRescanAt) >= rescanRecompute {
				qctx, cancel := context.WithTimeout(ctx, dashQueryTimeout)
				rescanPending, _ = db.CountRescanPending(qctx, traitsVersion, rescanAge) //nolint:errcheck // best-effort; zero is acceptable fallback
				cancel()
				lastRescanAt = time.Now()
			}
		}

		analyzedAbs := progress.analyzed.Load()
		sessionAnalyzed := max(analyzedAbs-progress.startAnalyzed.Load(), 0)
		walked := progress.walked.Load()
		hashedN := progress.hashed.Load()
		inserted := progress.inserted.Load()
		skipped := progress.skipped.Load()
		hashDone := hashedN + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()

		// totalInDB = all samples in the database (analyzed + pending).
		totalInDB := progress.queued.Load()
		// totalExpected adds files still in the walk→hash→insert pipeline
		// that haven't reached the DB yet. This prevents premature 100%.
		insertDone := inserted + skipped + progress.tooSmall.Load() + progress.tooLarge.Load() + progress.hashErrors.Load()
		inPipeline := max(walked-insertDone, 0)
		totalExpected := totalInDB
		if !progress.walkDone.Load() || inPipeline > 0 {
			totalExpected += inPipeline
		}
		pending := max(totalExpected-analyzedAbs, 0)
		if maxAnalyzed > 0 && int64(maxAnalyzed) < pending {
			pending = int64(maxAnalyzed)
		}

		// Record sample (with per-worker counts) and compute 15-minute rolling rates.
		now := time.Now()
		s := sample{t: now, count: sessionAnalyzed, inserted: inserted}
		if len(workers) > 0 {
			s.byNode = make(map[string]int64, len(workers))
			for i := range workers {
				s.byNode[workers[i].Name] = workers[i].Analyzed
			}
		}
		samples = append(samples, s)
		if len(samples) > maxSamples {
			samples = samples[len(samples)-maxSamples:]
		}

		var rate15m float64
		var insertRate15m float64
		var nodeRates map[string]float64
		if len(samples) >= 2 {
			cutoff := now.Add(-15 * time.Minute)
			oldest := samples[0]
			for _, ss := range samples {
				if !ss.t.Before(cutoff) {
					oldest = ss
					break
				}
			}
			if dt := now.Sub(oldest.t).Seconds(); dt > 5 {
				rate15m = max(float64(sessionAnalyzed-oldest.count)/dt, 0)
				insertRate15m = max(float64(inserted-oldest.inserted)/dt, 0)
				latest := samples[len(samples)-1]
				if len(latest.byNode) > 0 {
					nodeRates = make(map[string]float64, len(latest.byNode))
					for name, latestCount := range latest.byNode {
						if oldCount, ok := oldest.byNode[name]; ok {
							nodeRates[name] = max(float64(latestCount-oldCount)/dt, 0)
						}
					}
				}
			}
		}

		if !isTTY() {
			attrs := []any{
				"dirs", ndirs,
				"walked", walked, "hashed", hashedN,
				"inserted", inserted, "skipped", skipped,
				"analyzed", analyzedAbs, "pending", pending, "errors", progress.errors.Load(),
			}
			if walked > 0 {
				attrs = append(attrs, "hash_pct", fmt.Sprintf("%.0f%%", float64(hashDone)/float64(walked)*100))
			}
			if totalExpected > 0 {
				attrs = append(attrs, "analyze_pct", fmt.Sprintf("%.0f%%", float64(analyzedAbs)/float64(totalExpected)*100))
			}
			if rate15m > 0 {
				attrs = append(attrs, "rate_15m", fmt.Sprintf("%.1f/s", rate15m))
			}
			if elapsed := time.Since(start).Seconds(); elapsed > 5 && sessionAnalyzed > 0 {
				attrs = append(attrs, "rate_overall", fmt.Sprintf("%.1f/s", float64(sessionAnalyzed)/elapsed))
			}
			if rescanPending > 0 {
				attrs = append(attrs, "rescan_pending", rescanPending)
			}
			if rate15m > 0.1 && pending > 0 {
				etaDur := time.Duration(float64(pending)/rate15m) * time.Second
				attrs = append(attrs, "pending_eta", formatETA(etaDur))
			}
			if rate15m > 0.1 && rescanPending > 0 {
				rescanRemaining := rescanPending
				if pending > 0 {
					rescanRemaining += pending
				}
				etaDur := time.Duration(float64(rescanRemaining)/rate15m) * time.Second
				attrs = append(attrs, "rescan_eta", formatETA(etaDur))
			}
			slog.Info("load progress", attrs...)
			logWorkerStatus(workers, nodeRates, oldestClaims)
			continue
		}

		// TTY dashboard
		var pendingETA string
		if rate15m > 0.1 && pending > 0 {
			pendingETA = formatETA(time.Duration(float64(pending)/rate15m) * time.Second)
		}
		var rescanETA string
		if rate15m > 0.1 && rescanPending > 0 {
			rescanRemaining := rescanPending
			if pending > 0 {
				rescanRemaining += pending
			}
			rescanETA = formatETA(time.Duration(float64(rescanRemaining)/rate15m) * time.Second)
		}

		pct := 0.0
		if totalExpected > 0 {
			pct = float64(analyzedAbs) / float64(totalExpected) * 100
			if pct > 100 {
				pct = 100
			}
		}

		writeStdout("\033[H\033[2J")

		elapsed := time.Since(start)

		// Line 1: analysis progress
		analysisLine := fmt.Sprintf(
			"\033[1mhopper\033[0m  %s    %s / %s analyzed  %.0f%%",
			elapsed.Round(time.Second),
			fmtN(analyzedAbs), fmtN(totalExpected), pct)
		if rate15m > 0.1 {
			analysisLine += fmt.Sprintf("  %.1f/s", rate15m)
		}
		if pendingETA != "" {
			analysisLine += "  pending ETA " + pendingETA
		}
		writeStdoutf("%s\n", analysisLine)

		// Line 2: remaining work breakdown
		if pending > 0 || rescanPending > 0 || !progress.walkDone.Load() {
			remainLine := "  "
			if pending > 0 {
				remainLine += fmt.Sprintf("initial: %s pending", fmtN(pending))
			}
			if rescanPending > 0 {
				if pending > 0 {
					remainLine += "  ·  "
				}
				remainLine += fmt.Sprintf("%s rescan", fmtN(rescanPending))
				if rescanETA != "" {
					if pending > 0 {
						remainLine += fmt.Sprintf(" (finish after initial %s)", rescanETA)
					} else {
						remainLine += fmt.Sprintf(" (ETA %s)", rescanETA)
					}
				}
			}
			if insertRate15m > 0.1 {
				remainLine += fmt.Sprintf("  %.1f/s new", insertRate15m)
			}
			if !progress.walkDone.Load() {
				remainLine += "  walking\u2026"
			}
			writeStdoutf("%s\n", remainLine)
		}

		// Workers
		if len(workers) > 0 {
			nameWidth := 6
			for i := range workers {
				if len(workers[i].Name) > nameWidth {
					nameWidth = len(workers[i].Name)
				}
			}
			writeStdoutf("\n  \033[2m  %-*s  tasks    seen    rate  analyzed  errors  oldest job\033[0m\n",
				nameWidth, "worker")

			sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
			for i := range workers {
				idle := time.Since(workers[i].LastSeen)
				status, dot := workerStatus(workers[i].ActiveClaims, idle)

				rateStr := "    —"
				if r := nodeRates[workers[i].Name]; r > 0.05 {
					rateStr = fmt.Sprintf("%4.1f/s", r)
				}

				oldestStr := ""
				if claim, ok := oldestClaims[workers[i].Name]; ok {
					age := time.Since(claim.ClaimedAt)
					oldestStr = fmt.Sprintf("  %s (%s)", filepath.Base(claim.Path), shortDuration(age))
				}

				seenStr := fmt.Sprintf("%5s", shortDuration(idle))

				line := fmt.Sprintf("  %s %-*s  %3d/%d  %s  %s  %8s  %s",
					dot, nameWidth, workers[i].Name,
					workers[i].ActiveClaims, workers[i].Slots, seenStr, rateStr,
					fmtN(workers[i].Analyzed), fmtN(workers[i].Errors))
				if oldestStr != "" {
					line += oldestStr
				}
				if status != "" {
					line += fmt.Sprintf("  \033[33m%s\033[0m", status)
				}
				writeStdoutLine(line)
			}
		}

		// Footer: pipeline summary showing how walked files flow into analysis.
		cacheHits := progress.cacheHits.Load()
		tooSmall := progress.tooSmall.Load()
		tooLarge := progress.tooLarge.Load()
		errs := progress.errors.Load()
		lastCompleted := ""
		if !newestAnalyzedAt.IsZero() {
			lastCompleted = fmt.Sprintf(" · last completed %s ago", shortDuration(time.Since(newestAnalyzedAt)))
		}
		walkStatus := "…"
		if progress.walkDone.Load() {
			walkStatus = "done"
		}
		// skipped includes both cache-hit skips and batch-insert dupes;
		// subtract cache hits to show only the batch-insert dupes.
		dupes := max(skipped-cacheHits, 0)
		writeStdoutf("\n  %s walked (%s) · %s known · %s new · %s inserted",
			fmtN(walked), walkStatus, fmtN(cacheHits), fmtN(walked-cacheHits-tooSmall-tooLarge), fmtN(inserted))
		if dupes > 0 {
			writeStdoutf(" · %s dupes", fmtN(dupes))
		}
		if tooSmall+tooLarge > 0 {
			writeStdoutf(" · %s filtered", fmtN(tooSmall+tooLarge))
		}
		if errs > 0 {
			writeStdoutf(" · %s errors", fmtN(errs))
		}
		writeStdoutf("%s\n", lastCompleted)

		if recent := progress.recentErrors(); len(recent) > 0 {
			writeStdout("\n  \033[2mrecent errors\033[0m\n")
			for i := len(recent) - 1; i >= 0; i-- {
				e := recent[i]
				writeStdoutf("  \033[31m%s %-7s\033[0m %s\n",
					e.At.Format("15:04:05"), e.Stage, e.Message)
			}
		}
	}
}

// Worker presence windows — shared by the CLI status line, the web
// dashboard, and the non-TTY log. Check-in cadence is tens of seconds,
// so anything under workerActiveWindow is treated as "recently present"
// even with zero active claims. The lower bound used to be 10min; the
// non-TTY log once used 30s, which made workers flicker offline
// between polls. Keep all three presentations in lockstep.
const (
	workerActiveWindow   = 20 * time.Minute
	workerInactiveWindow = 60 * time.Minute
	// workerRetentionWindow is how long a worker remains on the dashboard
	// after its last contact.
	workerRetentionWindow = 72 * time.Hour
)

// workerStatus returns a display status and ANSI dot color for a worker.
// Active claims > 0 means the worker is busy (green). Otherwise, fall
// back to time-based: active within workerActiveWindow, inactive up to
// workerInactiveWindow, down beyond that.
func workerStatus(activeClaims int, idle time.Duration) (status string, dot string) {
	green := "\033[32m●\033[0m"
	yellow := "\033[33m●\033[0m"
	red := "\033[31m●\033[0m"

	if activeClaims > 0 {
		return "", green
	}
	switch {
	case idle < workerActiveWindow:
		return "", green // recently active, just idle
	case idle < workerInactiveWindow:
		return fmt.Sprintf("inactive %s", shortDuration(idle)), yellow
	default:
		return fmt.Sprintf("down %s", shortDuration(idle)), red
	}
}

func logWorkerStatus(workers []namedWorkerStats, nodeRates map[string]float64, oldestClaims map[string]hopper.WorkerClaim) {
	for i := range workers {
		online := time.Since(workers[i].LastSeen) < workerActiveWindow
		status := "online"
		if !online {
			status = "offline"
		}
		attrs := []any{
			"worker", workers[i].Name,
			"status", status,
			"slots", workers[i].Slots,
			"claimed", workers[i].TotalClaimed,
			"analyzed", workers[i].Analyzed,
			"errors", workers[i].Errors,
		}
		if r := nodeRates[workers[i].Name]; r > 0.05 {
			attrs = append(attrs, "rate", fmt.Sprintf("%.1f/s", r))
		}
		if workers[i].RSSMB > 0 {
			attrs = append(attrs, "rss_mb", workers[i].RSSMB)
		}
		if workers[i].Load1 > 0 {
			attrs = append(attrs, "load1", fmt.Sprintf("%.2f", workers[i].Load1))
		}
		if claim, ok := oldestClaims[workers[i].Name]; ok {
			attrs = append(attrs,
				"oldest_job", filepath.Base(claim.Path),
				"oldest_age", shortDuration(time.Since(claim.ClaimedAt)))
		}
		// Why the worker is/isn't pulling more: free buffer room (0 = saturated,
		// so it stops polling on purpose), and what its last poll asked for vs got
		// (want>got with room means hopper had nothing for it).
		attrs = append(attrs,
			"buffer_room", workers[i].BufferRoom,
			"want", workers[i].LastWant,
			"got", workers[i].LastClaim)
		if workers[i].MemCeilingMB > 0 {
			attrs = append(attrs, "mem_mb",
				fmt.Sprintf("%d/%d", workers[i].MemReservedMB, workers[i].MemCeilingMB))
		}
		// Room to spare but a stale last poll = the poll loop is wedged, not just
		// saturated (a full buffer stops polling normally).
		if workers[i].BufferRoom > 0 && !workers[i].LastPollAt.IsZero() {
			if age := time.Since(workers[i].LastPollAt); age > workerActiveWindow {
				attrs = append(attrs, "poll_age", shortDuration(age))
			}
		}
		slog.Info("litmus worker", attrs...)
	}
}

// logLoadSummary emits the final "directory complete" line with the
// per-stage counters and analysis timing stats gathered during the load.
func logLoadSummary(start time.Time, experimentTag string, dirs []struct{ dir, label string }, progress *loadProgress) {
	analyzed := progress.analyzed.Load()
	elapsed := time.Since(start)
	attrs := []any{
		"dirs", len(dirs),
		"walked", progress.walked.Load(), "hashed", progress.hashed.Load(),
		"inserted", progress.inserted.Load(),
		"skipped", progress.skipped.Load(), "markers", progress.markers.Load(),
		"too_small", progress.tooSmall.Load(), "too_large", progress.tooLarge.Load(),
		"cache_hits", progress.cacheHits.Load(),
		"analyzed", analyzed,
		"exploded", progress.exploded.Load(),
		"errors", progress.errors.Load(),
		"elapsed", elapsed.Round(time.Millisecond),
	}
	if analyzed > 0 {
		throughput := float64(analyzed) / elapsed.Seconds()
		attrs = append(attrs,
			"avg_score", int(progress.scoreSum.Load()/analyzed),
			"throughput_per_sec", fmt.Sprintf("%.2f", throughput),
			"analyze_avg_ms", progress.analyzeDurationSum.Load()/analyzed/int64(time.Millisecond),
			"analyze_min_ms", progress.analyzeDurationMin.Load()/int64(time.Millisecond),
			"analyze_max_ms", progress.analyzeDurationMax.Load()/int64(time.Millisecond),
		)
	}
	if experimentTag != "" {
		attrs = append(attrs, "experiment", experimentTag)
	}
	slog.Info("directory complete", attrs...)
}

// Marker file conventions (shared with cyclotron):
//
//	._<filename>.BENIGN — file is actually benign (overrides --bad label)
//	._<filename>.BAD    — file is actually malicious (overrides --good label)
const (
	markerPrefix = "._"
	markerBenign = ".BENIGN"
	markerBad    = ".BAD"
)

// isMarkerFile returns true if the filename is itself a marker (e.g. ._foo.whl.BENIGN).
func isMarkerFile(name string) bool {
	return strings.HasPrefix(name, markerPrefix) &&
		(strings.HasSuffix(name, markerBenign) || strings.HasSuffix(name, markerBad))
}

// isForagerSidecar reports whether name is a forager vendor-fetch metadata
// sidecar rather than sample content. The current naming is a hidden dotfile
// (".<sha256>.sidecar.json"); the legacy form is a bare "<sha256>.json". Both
// describe a sibling binary and must never be ingested as samples — forager
// direct-inserts the real row, and on a disaster-recovery walk the binary
// carries its own provenance.
func isForagerSidecar(name string) bool {
	if strings.HasSuffix(name, ".sidecar.json") {
		return true
	}
	if stem, ok := strings.CutSuffix(name, ".json"); ok {
		return isHexSHA256Name(stem)
	}
	return false
}

// isHexSHA256Name reports whether s is exactly 64 lowercase hex digits, the
// shape of a forager sha256-named file.
func isHexSHA256Name(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// checkMarker looks for a sibling marker file that contradicts the given label.
// Returns "benign" or "bad" if a marker exists, "" otherwise.
func checkMarker(path string) string {
	kind, _ := markerInfo(path)
	return kind
}

func markerInfo(path string) (kind string, mtime *time.Time) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	benign := filepath.Join(dir, markerPrefix+base+markerBenign)
	if info, err := os.Stat(benign); err == nil {
		t := info.ModTime()
		return "benign", &t
	}

	bad := filepath.Join(dir, markerPrefix+base+markerBad)
	if info, err := os.Stat(bad); err == nil {
		t := info.ModTime()
		return "bad", &t
	}

	return "", nil
}

// labeledPath is a file path with its classification label and the file type
// reported by cleave. The file type flows into the Sample row so DB queries
// can filter by type without waiting for analysis.
type labeledPath struct {
	path     string
	label    string
	fileType string
}

// pathLister enumerates recognized files under a directory and invokes emit
// for each one as cleave produces it. emit returns false when the caller
// wants to stop (typically because ctx.Done() fired on a blocked send), in
// which case the lister returns early with a nil error. Tests override this
// variable with a pure-Go walker that skips the real cleave binary.
var pathLister = streamCleaveIterFiles

// startEnumeration kicks off pathLister in a goroutine and streams results
// into a channel so file enumeration can overlap with other startup work
// (hash cache loading, DB migrations, etc.).
// sidecarSuffix names forager's per-artifact provenance sidecars (mirrors
// forager.SidecarSuffix; hopper sits below forager in the module graph and
// cannot import it). The sidecars live next to samples but are metadata, not
// samples, so enumeration skips them rather than ingesting one as a sample.
const sidecarSuffix = ".forage.json"

func isSidecarPath(path string) bool {
	return strings.HasSuffix(path, sidecarSuffix)
}

// stagingDirName is the subdirectory cooperating writers (forager, hopper
// uploads) use to assemble an artifact before atomically renaming the finished
// file into the sample tree. cleave's iter-files walks into it (it only skips
// .git), so enumeration must filter it here: a scratch file caught mid-write,
// or in the window before its rename/cleanup, would otherwise be ingested as a
// sample and leave a DB row pointing at a path that vanishes when the rename
// runs. Keep in sync with forager's stagingSubdir.
const stagingDirName = ".tmp"

// legacyUnpkgScratchSuffix matches the pre-staging scratch name forager wrote
// directly into the sample dir for unpkg-reconstructed tarballs. A forager that
// predates the staging-dir change still produces these, so skip them by name
// too until every forager is redeployed.
const legacyUnpkgScratchSuffix = "-unpkg-tmp.tgz"

// legacyPartialScratchPrefix matches the pre-staging vendor-fetch scratch name
// forager used directly in the host directory. Keep this guard for stale files
// left by an older forager or a crashed download; current forager stages these
// under .tmp instead.
const legacyPartialScratchPrefix = ".partial-"

// isStagingPath reports whether path is a transient artifact that enumeration
// must not ingest: anything inside a stagingDirName component, or a legacy
// unpkg/partial scratch file sitting beside real samples.
func isStagingPath(path string) bool {
	if strings.HasSuffix(path, legacyUnpkgScratchSuffix) {
		return true
	}
	if strings.HasPrefix(filepath.Base(path), legacyPartialScratchPrefix) {
		return true
	}
	// Match stagingDirName as a whole path component, not a substring, so a
	// legitimately-named file like "foo.tmp.tgz" is not skipped.
	return slices.Contains(strings.Split(path, string(filepath.Separator)), stagingDirName)
}

// startEnumeration streams files under dir. A non-zero newerThan makes the
// enumeration incremental: only files modified at or after it are emitted.
func startEnumeration(ctx context.Context, dir string, newerThan time.Time) <-chan labeledPath {
	ch := make(chan labeledPath, 4096)
	go func() {
		defer close(ch)
		slog.Info("listing files", "dir", dir, "newer_than", newerThan)
		err := pathLister(ctx, dir, newerThan, func(lp labeledPath) bool {
			if isSidecarPath(lp.path) {
				return true // provenance sidecar, not a sample; keep enumerating
			}
			if isStagingPath(lp.path) {
				return true // transient staging artifact; not a sample
			}
			select {
			case ch <- lp:
				return true
			case <-ctx.Done():
				return false
			}
		})
		if err != nil {
			slog.Warn("list files failed", "dir", dir, "error", err)
		}
	}()
	return ch
}

// cleaveBinary is the path (or name, for $PATH lookup) of the cleave binary
// used for file enumeration. Set by the load command's --cleave flag.
var cleaveBinary = "cleave"

// streamCleaveIterFiles invokes `cleave iter-files` against dir and streams
// each decoded record to emit as cleave produces it. This lets the caller
// forward entries into the hash pipeline without buffering a whole
// directory's output first — the reason for the callback shape.
//
// Per-record decode errors stop the scan at the first bad record. A nonzero
// cleave exit caused by context cancellation is surfaced as an error so
// callers can unwind cleanly. A nonzero exit for any other reason degrades
// gracefully: whatever records were already emitted stay emitted, and a
// warn log captures the tail of cleave's stderr for diagnosis.
//
// Cleave's stderr is captured to a buffer and only shown on failure so the
// startup banner doesn't clutter every successful run.
func streamCleaveIterFiles(ctx context.Context, dir string, newerThan time.Time, emit func(labeledPath) bool) error {
	// Hopper's max file size is in bytes; cleave's --max-file-size is in
	// megabytes and is a top-level flag that must precede the subcommand.
	args := make([]string, 0, 6)
	if mb := maxFileSize / (1024 * 1024); mb > 0 {
		args = append(args, "--max-file-size", strconv.FormatInt(mb, 10))
	}
	args = append(args, "iter-files", dir)
	// Incremental walk: let cleave skip files older than the cutoff by their
	// mtime, before it reads each file's magic bytes (the costly step on a cold
	// cache). --newer-than takes Unix seconds; requires a cleave that supports
	// the flag (deploy cleave before hopper starts passing it).
	if !newerThan.IsZero() {
		args = append(args, "--newer-than", strconv.FormatInt(newerThan.Unix(), 10))
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, cleaveBinary, args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cleave iter-files stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cleave iter-files start: %w", err)
	}
	// Walk helpers count against the workers' memory budget, not the
	// master's protected floor (see workercgroup.go).
	moveToWorkerCgroup(cmd.Process.Pid)
	slog.Info("cleave iter-files started", "dir", dir, "pid", cmd.Process.Pid)

	var emitted int
	var stopped bool
	dec := json.NewDecoder(stdout)
	for dec.More() {
		var rec struct {
			Path     string `json:"path"`
			FileType string `json:"type"`
			Sz       int64  `json:"sz"`
		}
		if err := dec.Decode(&rec); err != nil {
			slog.Warn("cleave iter-files decode", "dir", dir, "error", err)
			break
		}
		if !emit(labeledPath{path: rec.Path, fileType: rec.FileType}) {
			stopped = true
			break
		}
		emitted++
	}
	// If the caller asked us to stop, drain stdout so cmd.Wait doesn't
	// block on a full pipe; the CommandContext will kill cleave when the
	// parent context fires, so any read error here is expected.
	if stopped {
		_, _ = io.Copy(io.Discard, stdout) //nolint:errcheck // drained for shutdown, error expected
	}

	if err := cmd.Wait(); err != nil {
		// Context cancellation is an orderly shutdown, not a cleave crash.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("cleave iter-files: %w", ctxErr)
		}
		stderrTail := tailBytes(stderrBuf.Bytes(), 2048)
		if emitted == 0 {
			return fmt.Errorf("cleave iter-files: %w (stderr: %s)", err, stderrTail)
		}
		slog.Warn("cleave iter-files exited with error",
			"dir", dir, "error", err, "emitted", emitted, "stderr", stderrTail)
	}
	slog.Info("cleave iter-files complete",
		"dir", dir, "files", emitted, "elapsed", time.Since(start).Round(time.Millisecond))
	return nil
}

// tailBytes returns the last n bytes of b as a string, or all of b if
// shorter. Used to truncate captured subprocess stderr for log lines.
func tailBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[len(b)-n:])
}

// hashResult bundles a sample with cache metadata so the pipeline can skip
// DB inserts for files that are both cache hits and already inserted.
type hashResult struct {
	sample   *hopper.Sample
	cacheKey cacheKey
	inserted bool // true if the hash cache says this SHA256 is already in the DB
}

// hashFile stats path, enforces size limits, consults the hash cache, and
// returns a Sample stamped with the cleave-classified file type. The file is
// only opened for reading on a cache miss. Pass "" for fileType in contexts
// that don't yet know it (tests, ad-hoc callers). Pass nil for progress when
// no cache-hit metric is being collected.
func hashFile(ctx context.Context, path, label, fileType, source string, cache *hashCache, progress *loadProgress) (hashResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return hashResult{}, err
	}

	if info.Size() < minFileSize {
		return hashResult{}, errTooSmall
	}
	if info.Size() >= maxFileSize {
		return hashResult{}, errTooLarge
	}

	dev, inode := fileStat(info)

	ck := cacheKey{dev: dev, inode: inode, size: info.Size(), mtime: info.ModTime().UnixNano()}

	// Check hash cache before reading file contents.
	if cache != nil {
		if cached, ins, ok := cache.lookup(ctx, dev, inode, info.Size(), info.ModTime()); ok {
			if progress != nil {
				progress.cacheHits.Add(1)
			}
			modTime := info.ModTime()
			s := &hopper.Sample{
				SHA256:      cached,
				Source:      source,
				Filename:    filepath.Base(path),
				FileType:    fileType,
				Label:       label,
				LabelSource: source,
				SizeBytes:   info.Size(),
				Path:        path,
				Mtime:       &modTime,
			}
			prov := extractPathProvenance(path, label)
			fillSampleProvenance(s, prov, filepath.Base(path))
			attachSidecarProvenance(s, path)
			return hashResult{
				cacheKey: ck,
				sample:   s,
				inserted: ins,
			}, nil
		}
	}

	// Cache miss — open and read the file to compute SHA256.
	f, err := os.Open(path)
	if err != nil {
		return hashResult{}, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return hashResult{}, err
	}

	digest := hex.EncodeToString(h.Sum(nil))

	if cache != nil {
		cache.store(ctx, dev, inode, info.Size(), info.ModTime(), digest)
	}

	mtime := info.ModTime()
	s := &hopper.Sample{
		SHA256:      digest,
		Source:      source,
		Filename:    filepath.Base(path),
		FileType:    fileType,
		Label:       label,
		LabelSource: source,
		SizeBytes:   info.Size(),
		Path:        path,
		Mtime:       &mtime,
	}
	prov := extractPathProvenance(path, label)
	fillSampleProvenance(s, prov, filepath.Base(path))
	attachSidecarProvenance(s, path)
	return hashResult{cacheKey: ck, sample: s}, nil
}

// attachSidecarProvenance loads the forager provenance sidecar next to an
// artifact (if present) into the sample's provenance column and fetched_at.
// This backfills provenance for samples that reach hopper via the reconcile
// walk rather than forager's direct-insert. A missing or malformed sidecar is
// the common case and silently leaves both unset; the insert conflict clause
// preserves any provenance a prior direct-insert already wrote.
func attachSidecarProvenance(s *hopper.Sample, artifactPath string) {
	data, err := os.ReadFile(artifactPath + sidecarSuffix)
	if err != nil || !json.Valid(data) {
		return
	}
	s.Provenance = data
	var meta struct {
		Fetch struct {
			At time.Time `json:"at"`
		} `json:"fetch"`
		Artifact struct {
			Filename string `json:"filename"`
			SHA256   string `json:"sha256"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return
	}
	if !meta.Fetch.At.IsZero() {
		s.FetchedAt = &meta.Fetch.At
	}
	// Prefer the producer's recorded filename over the on-disk basename: it is
	// the original upstream name (e.g. "k.php"), immune to a transient sha-named
	// copy a relocation may leave beside the sample. The sha256 binds the sidecar
	// to these exact bytes, so adopt the name only when it matches what we hashed.
	if meta.Artifact.Filename != "" && strings.EqualFold(meta.Artifact.SHA256, s.SHA256) {
		s.Filename = meta.Artifact.Filename
	}
}

// fillSampleProvenance populates the provenance fields on s using the
// path-extracted values, falling back to filename parsing for any
// fields the path didn't carry. The forager layout has name in the
// path but not version, so we always parse the filename for version
// and use parsed name as a fallback when the path component was empty
// (legacy paths that predate the relayout migration).
func fillSampleProvenance(s *hopper.Sample, prov pathProvenance, filename string) {
	s.Feed = prov.feed
	// Normalize the path-extracted ecosystem through the runtime map.
	// Legacy paths put registry names ("npm"), file-type classifiers
	// ("elf"), or junk dataset names ("vxunderground-inthewild") in the
	// ecosystem slot — we want the canonical runtime name in the DB so
	// queries and dropdowns stay clean.
	s.Ecosystem = pkgparse.NormalizeEcosystem(prov.ecosystem)
	s.Domain = prov.domain
	s.Package = prov.pkg
	s.Version = prov.version
	// A coordinate-tier upload path carries a complete PURL, so the walk can
	// populate the queryable identity column without reading a sidecar.
	if prov.purl != "" {
		s.PURLBase = pkgparse.VersionlessPURL(prov.purl)
	}
	parsedName, parsedVersion, _ := pkgparse.ParseFilename(filename)
	if s.Package == "" {
		s.Package = parsedName
	}
	if s.Version == "" {
		// Prefer the name-anchored split: ParseFilename has to guess the
		// name/version boundary jointly, and digit-bearing names like
		// "@kl-starfish/test-01" make it absorb name segments into the version
		// ("01-1.0.0"). With the package name known, the split is unambiguous.
		if v := pkgparse.VersionForName(filename, s.Package); v != "" {
			s.Version = v
		} else {
			s.Version = parsedVersion
		}
	}
	enrichFromVendorSidecar(s)
}

// enrichFromVendorSidecar fills url/feed/domain on a vendor-fetched sample from
// the provenance sidecar forager writes next to each binary
// (".<sha>.sidecar.json", or the legacy "<sha>.json"). The walk skips the
// sidecar as its own sample (isForagerSidecar); reading it here is how its
// metadata — most importantly the fetch URL — still reaches the binary's row
// when forager isn't direct-inserting (and after a from-scratch DR walk).
//
// Called while s.Path is still the absolute on-disk path (hashFile sets it
// before runDirPipeline rewrites it to the stored relative path), so the
// sidecar sibling resolves correctly.
func enrichFromVendorSidecar(s *hopper.Sample) {
	if s.SHA256 == "" || s.Path == "" {
		return
	}
	if !strings.Contains(filepath.ToSlash(s.Path), "/foraged/vendor/") {
		return
	}
	sc, ok := readVendorSidecar(filepath.Dir(s.Path), s.SHA256)
	if !ok {
		return
	}
	if s.URL == "" {
		s.URL = sc.FetchURL
	}
	if s.Feed == "" {
		s.Feed = sc.Source
	}
	if s.Domain == "" {
		s.Domain = vendorSidecarDomain(sc.Hostname)
	}
}

// vendorSidecar is the subset of forager's sidecar JSON that hopper consumes.
type vendorSidecar struct {
	FetchURL string `json:"fetch_url"`
	Source   string `json:"source"`
	Hostname string `json:"hostname"`
}

// readVendorSidecar reads and parses the forager sidecar for sha in dir,
// trying the current hidden name then the legacy bare name. Returns ok=false
// when neither exists or the JSON can't be parsed.
func readVendorSidecar(dir, sha string) (vendorSidecar, bool) {
	for _, name := range []string{"." + sha + ".sidecar.json", sha + ".json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var v vendorSidecar
		if json.Unmarshal(b, &v) == nil {
			return v, true
		}
	}
	return vendorSidecar{}, false
}

// vendorSidecarDomain keeps only the leading host of a vendor hostname
// ("github.com/abiosoft/colima" → "github.com"), matching the value the
// dashboard groups by.
func vendorSidecarDomain(hostname string) string {
	if host, _, found := strings.Cut(hostname, "/"); found {
		return host
	}
	return hostname
}

// pathProvenance captures the metadata recoverable from a forager-output
// path. Whatever the path doesn't carry stays empty.
type pathProvenance struct {
	feed      string
	ecosystem string
	domain    string
	pkg       string
	version   string
	// purl is set only by the upload trees' coordinate tier, whose layout is a
	// reversible projection of the PURL. The foraged layout cannot recover one:
	// it names a registry and a package but never a version, so there is no
	// complete coordinate to rebuild.
	purl string
}

// extractPathProvenance parses provenance fields from a forager output path.
//
// New layout (forager 2026-05+, marker = "foraged"):
//
//	.../<label>/foraged/<runtime>/<domain>/<feed>/<name>/<file>
//
// Legacy harvest layout (still walked during the relayout transition):
//
//	.../bad/harvest/<feed>/<ecosystem>/<file>     → feed + ecosystem
//	.../bad/harvest/<feed>/<file>                 → feed only
//	.../<label>/harvest/<ecosystem>/<file>        → ecosystem only (good/unknown)
//
// "_unknown" placeholders that the relayout migration may have introduced
// for missing name are normalized to empty strings so they don't pollute
// downstream queries. Version is read from the filename (forager doesn't
// give version its own path component) and left empty when not parseable.
func extractPathProvenance(path, label string) pathProvenance {
	parts := strings.Split(filepath.ToSlash(path), "/")
	marker, idx := findLayoutMarker(parts, label)
	if idx < 0 || idx+1 >= len(parts) {
		return pathProvenance{}
	}
	after := parts[idx+1:]
	if len(after) < 2 {
		return pathProvenance{}
	}
	dirs := after[:len(after)-1]

	switch {
	case marker == "foraged":
		return parseForagedDirs(dirs)
	case isUploadProducer(marker):
		return parseUploadDirs(dirs)
	case isPromotionTree(marker):
		// Promotion keeps whatever layout the sample had where it was
		// discovered, so the grammar is whichever wrote it: an upload tree's
		// leading tier segment, or forager's runtime/domain/feed/name. "pkg"
		// and "sha" are reserved — neither is ever a runtime name — so the two
		// are told apart without guessing.
		if len(dirs) > 0 && (dirs[0] == coordinateTier || dirs[0] == digestTier) {
			return parseUploadDirs(dirs)
		}
		return parseForagedDirs(dirs)
	}
	return parseHarvestDirs(dirs, label)
}

// promotionTrees are the destinations a ruled or reviewed sample is moved into,
// by promoter's own passes or by /api/triage. Each preserves the subpath the
// sample had in its discovery tree (see rulingPlan), so its provenance is still
// written in the path — just one level deeper than where it started.
var promotionTrees = []string{
	"foraged-promote",           // good/: ruled good
	"foraged-quarantine",        // bad/: ruled bad
	"foraged-suspicious-review", // unknown/: promoter's LLM tier wants a human
	"foraged-undetermined",      // unknown/: the LLM could not grade it
	"foraged-bad-review",        // unknown/: likely bad, awaiting confirmation
}

func isPromotionTree(marker string) bool { return slices.Contains(promotionTrees, marker) }

// findLayoutMarker scans path components for the layout-marker segment.
// Prefers a marker immediately following the label segment so paths that
// happen to contain the marker name as a package name don't confuse us.
// Returns the marker name and its index in parts, or ("", -1) if absent.
func findLayoutMarker(parts []string, label string) (marker string, idx int) {
	labelIdx := -1
	for i, p := range parts {
		if p == label {
			labelIdx = i
		}
	}
	if labelIdx >= 0 && labelIdx+1 < len(parts) {
		switch next := parts[labelIdx+1]; {
		case next == "foraged", next == "harvest":
			return next, labelIdx + 1
		case isUploadProducer(next), isPromotionTree(next):
			// Only recognized directly under the label. A producer name is an
			// ordinary word ("scan") that could equally be a package name
			// deeper in a path, so unlike the forager markers these never match
			// on the positional fallback below.
			return next, labelIdx + 1
		}
	}
	for i, p := range parts {
		if p == "foraged" || p == "harvest" {
			return p, i
		}
	}
	return "", -1
}

// parseForagedDirs maps the directory components between the "foraged"
// marker and the filename onto the new-layout provenance fields.
//
// Expected dirs slice (length 4+): [runtime, domain, feed, name...], where a
// scoped package name occupies more than one component.
// Shorter slices fall through gracefully — fields stay empty.
// Version is not a path component; it lives in the filename.
//
// The "_" placeholder for feed indicates "same as domain" — used for
// goodfeed paths where the discovery channel is the registry itself.
// Expand it back here so the DB row carries the actual feed value.
func parseForagedDirs(dirs []string) pathProvenance {
	p := pathProvenance{}
	if len(dirs) >= 1 {
		p.ecosystem = dirs[0]
	}
	if len(dirs) >= 2 {
		p.domain = unknownToEmpty(dirs[1])
	}
	if len(dirs) >= 3 {
		feed := unknownToEmpty(dirs[2])
		if feed == "_" {
			feed = p.domain
		}
		p.feed = feed
	}
	if len(dirs) >= 4 {
		// A scoped name spans several directories: forager's
		// sanitizePathSegment deliberately preserves the slash in a package
		// name, so "@vue/cli" is written as two levels. Rejoin everything past
		// the feed or the scope alone ("@vue") would be recorded as the package.
		p.pkg = unknownToEmpty(strings.Join(dirs[3:], "/"))
	}
	return p
}

// parseHarvestDirs preserves the legacy harvest-layout extraction: bad
// paths carry feed+ecosystem under harvest/, good/unknown carry only the
// ecosystem.
func parseHarvestDirs(dirs []string, label string) pathProvenance {
	switch label {
	case "bad":
		if len(dirs) == 1 {
			return pathProvenance{feed: dirs[0]}
		}
		return pathProvenance{feed: dirs[0], ecosystem: dirs[1]}
	default:
		return pathProvenance{ecosystem: dirs[0]}
	}
}

// unknownToEmpty maps the "_unknown" placeholder back to "" so callers
// don't have to special-case it. The placeholder is a marker forager's
// relayout migration uses for missing values; treating it as empty
// downstream keeps queries clean.
func unknownToEmpty(s string) string {
	if s == "_unknown" {
		return ""
	}
	return s
}

func cmdStats(ctx context.Context) error {
	f := flag.NewFlagSet("stats", flag.ExitOnError)
	dsn := f.String("db", "", "postgres connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	counts, err := db.CountByLabel(ctx)
	if err != nil {
		return err
	}
	var total int
	for label, n := range counts {
		writeStdoutf("%-10s %d\n", label, n)
		total += n
	}
	writeStdoutf("%-10s %d\n", "total", total)
	return nil
}

func cmdBackfill(ctx context.Context) error {
	f := flag.NewFlagSet("backfill", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// Migrate runs only schema migrations. Backfill is intentionally explicit
	// so normal startup/load paths do not spend minutes rewriting old rows.
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	pending, err := db.BackfillPending(ctx)
	if err != nil {
		return err
	}
	logBackfillPending(pending)
	if pending.TotalRows() == 0 {
		slog.Info("backfill skipped; no matching rows")
		return nil
	}

	slog.Info("backfilling explicit legacy data repairs")
	stats, err := db.Backfill(ctx)
	if err != nil {
		return err
	}
	slog.Info("backfill complete", "scanned", stats.Scanned, "updated", stats.Updated, "markers_cleared", stats.MarkersCleared)
	return nil
}

// cmdRehealCrit repairs the max_crit/suspicious_count columns that the
// samples_derive_cleave_cols trigger zeroed for every cleave v8 row (the per-file
// trait array was renamed 'find'->'traits' in v8; the trigger only knew 'find',
// so it derived max_crit=0 for all post-v8 samples and silently dropped them from
// the bloom's bad tiers and every criticality gate). Migrate first so the fixed
// trigger is in place before healing, then drain the broken backlog. Idempotent:
// only rows whose corrected criticality is non-zero are rewritten.
func cmdRehealCrit(ctx context.Context) error {
	f := flag.NewFlagSet("reheal-crit", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}

	slog.Info("rehealing max_crit/suspicious_count for cleave v8 rows")
	n, err := db.RehealCleaveCrit(ctx)
	if err != nil {
		return err
	}
	slog.Info("reheal-crit complete", "rows_repaired", n)
	return nil
}

// cmdBackfillPURL derives samples.purl_base for older rows that have a package
// coordinate but no stored PURL identity — the backlog from before forager
// derived it on write, plus rows whose runtime ecosystem the old registry-only
// mapping could not translate (javascript/rust/java/…), which is what kept the
// bad-PURL bloom near-empty. It rebuilds from the ecosystem + package columns via
// the shared pkgparse builder and never overwrites an existing purl_base, so it is
// safe to re-run.
func cmdBackfillPURL(ctx context.Context) error {
	f := flag.NewFlagSet("backfill-purl", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}

	slog.Info("backfilling purl_base from ecosystem+package")
	n, err := db.BackfillPURL(ctx)
	if err != nil {
		return err
	}
	slog.Info("backfill-purl complete", "rows_filled", n)
	return nil
}

// cmdCanonicalizePURLs rewrites every stored purl_base onto the current
// canonical spelling — the follow-up whenever a normalization fold changes
// (the AUR namespace move, PEP 503 PyPI names, extension-id case folds).
// Batched by id cursor so it never locks more than ~20k rows at a time,
// idempotent (canonicalization is a fixed point), and safe to re-run or
// interrupt. Run with -dry-run first to see how many rows a fold touches;
// rebuild the published bloom filters afterwards so the exported keys match.
func cmdCanonicalizePURLs(ctx context.Context) error {
	f := flag.NewFlagSet("canonicalize-purls", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dryRun := f.Bool("dry-run", false, "report what would be rewritten without writing")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}

	slog.Info("canonicalizing stored purl_base spellings", "dry_run", *dryRun)
	n, err := db.CanonicalizePURLBases(ctx, *dryRun)
	if err != nil {
		return err
	}
	// The sightings ledger keys corroboration by the same version-less
	// canonical purl_base; drifted subject spellings would silently miss the
	// exact-match joins, so re-key it in the same pass.
	s, err := db.CanonicalizeSightingSubjects(ctx, *dryRun)
	if err != nil {
		return err
	}
	slog.Info("canonicalize-purls complete", "rows_rewritten", n, "sightings_rewritten", s, "dry_run", *dryRun)
	return nil
}

// cmdPrune drops sample_locations rows whose files are gone from disk (ENOENT)
// and marks any top-level sample left with no surviving location skip='missing'.
// It stats the tree directly, so it MUST run on a host that holds the full sample
// corpus — on a partial mirror it would mark present-in-corpus files missing. The
// serving loop (`hopper load`) deliberately never prunes; this is the explicit,
// operator-run maintenance step instead. A 40%-of-rows safety cap aborts the
// unmount/wrong-root case; --force lifts it after you've confirmed the mount. A
// re-observed file auto-reverts skip to ” on the next walk, so a mistaken prune
// self-heals.
func cmdPrune(ctx context.Context) error {
	f := flag.NewFlagSet("prune", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	dataDir := f.String("data", "", "data directory containing bad/, good/, unknown/ subdirectories")
	force := f.Bool("force", false, "bypass the 40%-of-rows safety cap (use only after confirming the data root is fully mounted)")
	parseFlags(f, os.Args[2:])

	if *dataDir == "" {
		return errors.New("pass --data <directory> (the fully-mounted sample tree)")
	}
	// Resolve symlinks + absolute so paths match the roots stored in the DB.
	if resolved, err := filepath.EvalSymlinks(*dataDir); err == nil {
		*dataDir = resolved
	}
	if abs, err := filepath.Abs(*dataDir); err == nil {
		*dataDir = abs
	}

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	maxFraction := 0.40
	if *force {
		maxFraction = 1.0
	}
	removed, err := db.PruneMissingLocations(ctx, *dataDir, maxFraction)
	switch {
	case err == nil:
		slog.Info("pruned missing locations", "removed", removed, "data_dir", *dataDir)
		return nil
	case errors.As(err, new(*hopper.PruneSafetyExceeded)):
		return fmt.Errorf("prune safety cap tripped — refusing to delete; pass --force after confirming the data root is fully mounted: %w", err)
	default:
		return fmt.Errorf("prune missing locations: %w", err)
	}
}

// cmdRescan queues files for re-analysis in the repair tier (rescan_priority=1),
// drained behind new ingestion so it never starves fresh work. With
// --missing-members it flags every truncated archive that has no member rows —
// the historical data-loss backlog from the old async explosion; otherwise it
// flags the SHA-256s given as arguments. For an interactive, ahead-of-new rescan
// of a single file, use prism's per-file rescan button (RequestRescan).
func cmdRescan(ctx context.Context) error {
	f := flag.NewFlagSet("rescan", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	missingMembers := f.Bool("missing-members", false, "flag every truncated archive that has no member rows")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		return err
	}

	if *missingMembers {
		n, err := db.QueueMissingMembersForRepair(ctx)
		if err != nil {
			return err
		}
		slog.Info("queued memberless archives for repair", "count", n)
		return nil
	}

	shas := f.Args()
	if len(shas) == 0 {
		return errors.New("rescan: pass --missing-members, or one or more SHA-256 arguments")
	}
	norm := make([]string, len(shas))
	for i, s := range shas {
		s = strings.ToLower(s)
		if !validSHA256(s) {
			return fmt.Errorf("rescan: %q is not a SHA-256", shas[i])
		}
		norm[i] = s
	}
	n, err := db.QueueRescan(ctx, norm)
	if err != nil {
		return err
	}
	slog.Info("queued samples for repair-tier rescan", "requested", len(norm), "queued", n)
	return nil
}

func logBackfillPending(p hopper.BackfillPending) {
	slog.Info("backfill pending rows",
		"total", p.TotalRows(),
		"cleave_columns", p.CleaveColumns,
		"file_type_empties", p.FileTypeEmpties,
		"archive_member_litmus_candidates", p.ArchiveMemberLitmus,
		"archive_member_analyzed_at", p.ArchiveMemberAnalyzed,
		"stale_good_markers", p.StaleGoodMarkers,
		"stale_bad_markers", p.StaleBadMarkers)
}

// cmdPurgeUnsupported deletes samples that were analyzed but cleave could
// not classify — i.e. the file_type column came back empty. Dry-run by
// default: pass --apply to actually delete. Uses the idx_samples_file_type
// index so it's cheap even on multi-million-row tables.
func cmdPurgeUnsupported(ctx context.Context) error {
	f := flag.NewFlagSet("purge-unsupported", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	apply := f.Bool("apply", false, "actually delete rows (default is dry-run)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if !*apply {
		n, err := db.PurgeUnsupported(ctx, true)
		if err != nil {
			return err
		}
		writeStdoutf("would delete %d unsupported row(s) (cleave_result set, file_type empty)\n", n)
		writeStdoutLine("re-run with --apply to actually delete")
		return nil
	}

	slog.Info("purging unsupported rows")
	n, err := db.PurgeUnsupported(ctx, false)
	if err != nil {
		return err
	}
	slog.Info("purge complete", "deleted", n)
	return nil
}

// cmdNormalizeEcosystems re-applies pkgparse.NormalizeEcosystem to every
// distinct ecosystem value already stored, rewriting legacy/junk labels to
// their canonical runtime or clearing them when no runtime is known. It
// repairs rows written before the normalizer existed (feed names like
// "objectivesee", file-type tags like "c_linux") that the sticky upsert
// would otherwise preserve forever. Dry-run by default; pass --apply to write.
func cmdNormalizeEcosystems(ctx context.Context) error {
	f := flag.NewFlagSet("normalize-ecosystems", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	apply := f.Bool("apply", false, "actually rewrite rows (default is dry-run)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	values, err := db.DistinctEcosystems(ctx)
	if err != nil {
		return err
	}

	// Build the old→new remap, skipping values that already normalize to
	// themselves. The whole set is applied in one pass per table below.
	mapping := make(map[string]string, len(values))
	var cleared int
	for _, v := range values {
		n := pkgparse.NormalizeEcosystem(v)
		if n == v {
			continue
		}
		mapping[v] = n
		if n == "" {
			cleared++
			writeStdoutf("would clear %q (no known runtime)\n", v)
		} else {
			writeStdoutf("would rewrite %q -> %q\n", v, n)
		}
	}

	if !*apply {
		writeStdoutf("%d distinct value(s) would change (%d cleared); re-run with --apply to write\n", len(mapping), cleared)
		return nil
	}
	rows, err := db.UpdateEcosystems(ctx, mapping)
	if err != nil {
		return err
	}
	slog.Info("ecosystem normalization complete", "distinct_changed", len(mapping), "cleared", cleared, "rows_updated", rows)
	return nil
}

// cmdCascadeBackfill propagates existing good/bad archive labels onto their
// members for archives labeled before CascadeLabel existed: bad archives demote
// their suspicious (score >= 30) unknown members, good archives promote their
// unknown members. Dry-run by default — it reports the member counts that would
// change; re-run with --apply to write. Idempotent and safe to re-run.
func cmdCascadeBackfill(ctx context.Context) error {
	f := flag.NewFlagSet("cascade-backfill", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	apply := f.Bool("apply", false, "actually relabel members (default is dry-run)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	pending, err := db.CascadeBackfillPending(ctx)
	if err != nil {
		return err
	}
	if !pending {
		slog.Info("cascade backfill: nothing to do")
		writeStdoutf("no good/bad archive has unknown members; nothing to cascade\n")
		return nil
	}

	slog.Info("cascade backfill starting", "apply", *apply)
	st, err := db.CascadeBackfill(ctx, !*apply)
	if err != nil {
		return err
	}
	if !*apply {
		writeStdoutf("would demote %d member(s) across %d bad archive(s) and promote %d across %d good archive(s); re-run with --apply to write\n",
			st.MembersDemoted, st.BadArchives, st.MembersPromoted, st.GoodArchives)
		writeStdoutf("note: dry-run sums each archive independently; a member shared by a bad and a good\n")
		writeStdoutf("      archive is counted in both, but --apply resolves it bad (bad-first)\n")
		return nil
	}
	slog.Info("cascade backfill complete",
		"bad_archives", st.BadArchives, "members_demoted", st.MembersDemoted,
		"good_archives", st.GoodArchives, "members_promoted", st.MembersPromoted)
	return nil
}

// cmdCleanup walks each cleanup stage, reports how many rows match, and
// (with --apply) prompts per stage before deleting. Without --apply the
// command is read-only — always safe to run for a quick status report.
func cmdCleanup(ctx context.Context) error {
	f := flag.NewFlagSet("cleanup", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	apply := f.Bool("apply", false, "actually delete rows (default is count-only)")
	yes := f.Bool("yes", false, "skip per-stage confirmation prompts")
	only := f.String("stage", "", "only operate on the named stage")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	stages := hopper.CleanupStages
	if *only != "" {
		s, ok := hopper.CleanupStageByName(*only)
		if !ok {
			names := make([]string, len(hopper.CleanupStages))
			for i := range hopper.CleanupStages {
				names[i] = hopper.CleanupStages[i].Name
			}
			return fmt.Errorf("unknown stage %q; valid: %s", *only, strings.Join(names, ", "))
		}
		stages = []hopper.CleanupStage{s}
	}

	reader := bufio.NewReader(os.Stdin)
	var totalDeleted int64
	for _, s := range stages {
		n, err := db.CountCleanup(ctx, s)
		if err != nil {
			return err
		}
		if n == 0 {
			writeStdoutf("%-11s  0 rows\n", s.Name)
			continue
		}
		writeStdoutf("%-11s  %d rows — %s\n", s.Name, n, s.Description)

		if !*apply {
			continue
		}

		if !*yes {
			writeStdoutf("  delete %d rows? [y/N] ", n)
			ans, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("read confirmation: %w", err)
			}
			switch strings.TrimSpace(strings.ToLower(ans)) {
			case "y", "yes":
			default:
				writeStdoutLine("  skipped")
				continue
			}
		}

		deleted, err := db.ApplyCleanup(ctx, s)
		if err != nil {
			return err
		}
		writeStdoutf("  deleted %d rows\n", deleted)
		totalDeleted += deleted
	}

	if *apply {
		writeStdoutf("\nTotal deleted: %d rows\n", totalDeleted)
		return nil
	}
	writeStdoutLine("")
	writeStdoutLine("Dry run. To delete:")
	writeStdoutLine("  hopper cleanup --apply                    # prompt per stage")
	writeStdoutLine("  hopper cleanup --apply --yes              # no prompts")
	writeStdoutLine("  hopper cleanup --apply --stage=missing    # one stage only")
	return nil
}

type sampleListFunc func(context.Context, *hopper.DB, int, int) ([]*hopper.Sample, error)

// reviewOpts bundles the flags shared by the review subcommands so their
// setup can return a single value instead of a 5-tuple.
type reviewOpts struct {
	fs    *flag.FlagSet
	dsn   *string
	score *int
	limit *int
	flush *bool
}

func reviewFlags(name string) reviewOpts {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	score := fs.Int("threshold", 85, "score threshold")
	fs.IntVar(score, "score", 85, "score threshold (deprecated: use --threshold)")
	return reviewOpts{
		fs:    fs,
		dsn:   fs.String("db", "", "database connection string"),
		score: score,
		limit: fs.Int("limit", 100, "maximum rows to print"),
		flush: fs.Bool("flush", false, "delete matching review markers and restore the underlying label"),
	}
}

func runReviewCommand(ctx context.Context, args []string, name string, list sampleListFunc) error {
	o := reviewFlags(name)
	parseFlags(o.fs, args)

	db, err := openDB(ctx, *o.dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	samples, err := list(ctx, db, *o.score, *o.limit)
	if err != nil {
		return err
	}
	if *o.flush {
		return flushReviewSamples(ctx, db, name, samples)
	}
	for _, s := range samples {
		age := sampleAgeDays(s.Mtime)
		if name == "benign-review" || name == "bad-review" {
			age = sampleAgeDays(s.MarkerMtime)
		}
		writeStdoutf("%4d  %-64s  %-5d  %-4s  %-6s  %-8s  %s\n",
			s.ID, s.SHA256, s.Score, age, s.Label, s.LabelSource, s.Path)
	}
	return nil
}

func flushReviewSamples(ctx context.Context, db *hopper.DB, name string, samples []*hopper.Sample) error {
	if name != "benign-review" && name != "bad-review" {
		return fmt.Errorf("%s does not support --flush", name)
	}

	targetLabel := "bad"
	targetSource := "flush"
	if name == "bad-review" {
		targetLabel = "good"
	}

	for _, s := range samples {
		markerPath := reviewMarkerPath(name, s.Path)
		if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove marker for %s: %w", s.Path, err)
		}
		if err := db.Reclassify(ctx, s.SHA256, targetLabel, targetSource); err != nil {
			return err
		}
		if err := db.SetSkip(ctx, s.SHA256, ""); err != nil {
			return err
		}
		writeStdoutf("flushed  %-64s  %s\n", s.SHA256, s.Path)
	}
	return nil
}

func reviewMarkerPath(name, samplePath string) string {
	suffix := markerBenign
	if name == "bad-review" {
		suffix = markerBad
	}
	dir := filepath.Dir(samplePath)
	base := filepath.Base(samplePath)
	return filepath.Join(dir, markerPrefix+base+suffix)
}

func sampleAgeDays(ts *time.Time) string {
	if ts == nil {
		return ""
	}
	days := max(int(time.Since(*ts).Hours()/24), 0)
	return strconv.Itoa(days)
}

func cmdTriage(ctx context.Context) error {
	f := flag.NewFlagSet("triage", flag.ExitOnError)
	dsn := f.String("db", "", "database connection string")
	count := f.Int("count", 40, "maximum rows per dataset")
	baseURL := f.String("url", "http://127.0.0.1:8081", "hopper API base URL")
	out := f.String("out", "/var/tmp/hopper-triage", "output root directory")
	ecosystem := f.String("ecosystem", "", "filter by ecosystem (e.g. wolfi, archlinux)")
	fileType := f.String("file-type", "", "filter by file type (e.g. apk, pkg.tar.zst)")
	parseFlags(f, os.Args[2:])

	db, err := openDB(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	filter := hopper.TriageFilter{Ecosystem: *ecosystem, FileType: *fileType}

	type dataset struct {
		fetch func(context.Context, int) ([]*hopper.Sample, error)
		name  string
	}
	datasets := []dataset{
		{name: "bad", fetch: func(ctx context.Context, n int) ([]*hopper.Sample, error) { return db.TriageBad(ctx, n, filter) }},
		{name: "good", fetch: func(ctx context.Context, n int) ([]*hopper.Sample, error) { return db.TriageGood(ctx, n, filter) }},
		{name: "new", fetch: func(ctx context.Context, n int) ([]*hopper.Sample, error) { return db.TriageNew(ctx, n, filter) }},
	}

	if err := os.RemoveAll(*out); err != nil {
		return fmt.Errorf("clear output dir: %w", err)
	}

	// Reuse connections across the serial run for throughput, and bound each
	// attempt with its own context deadline rather than a single client Timeout:
	// a blanket timeout would also abort a legitimately large download, while a
	// per-attempt deadline lets a slow sample finish yet still caps a true hang.
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	var totalOK, totalFail int

	for _, ds := range datasets {
		samples, err := ds.fetch(ctx, *count)
		if err != nil {
			return fmt.Errorf("%s: %w", ds.name, err)
		}
		writeStdoutf("%s: fetching %d samples...\n", ds.name, len(samples))

		for _, s := range samples {
			bucket := s.Ecosystem
			if bucket == "" {
				bucket = s.Feed
			}
			if bucket == "" {
				bucket = s.Source
			}
			if bucket == "" {
				bucket = "unknown"
			}
			name := s.Filename
			if name == "" {
				name = s.SHA256
			}

			destDir := filepath.Join(*out, ds.name, bucket)
			if err := os.MkdirAll(destDir, 0o750); err != nil {
				return fmt.Errorf("mkdir %s: %w", destDir, err)
			}
			dest := filepath.Join(destDir, name)

			apiURL := strings.TrimRight(*baseURL, "/") + "/api/file/" + s.SHA256
			detail, ok := fetchSample(ctx, client, apiURL, dest)
			if !ok {
				writeStdoutf("  err %-64s  %s\n", s.SHA256, detail)
				totalFail++
				continue
			}
			writeStdoutf("  ok  %-64s  %s/%s/%s\n", s.SHA256, ds.name, bucket, name)
			totalOK++
		}
	}

	writeStdoutf("\nSummary: %d ok, %d failed\n", totalOK, totalFail)
	return nil
}

const (
	// triageMaxAttempts bounds retries per sample: enough to ride out a brief
	// server saturation window (each shed is a fast 503 + Retry-After) without
	// turning a permanently-broken sample into a long stall.
	triageMaxAttempts = 4
	// triageAttemptTimeout caps a single GET — generous, since a large sample on
	// a slow link is legitimate; it is the per-attempt context deadline that
	// replaces a blanket client timeout.
	triageAttemptTimeout = 5 * time.Minute
	triageBackoffBase    = 500 * time.Millisecond
	triageBackoffMax     = 10 * time.Second
	triageErrBodyMax     = 512 // bytes of a non-200 body to surface in the log line
)

// fetchSample downloads one sample to dest, serial but resilient: it retries
// transient network errors and a 503/429 (honoring the server's Retry-After)
// with bounded backoff, surfaces the server's structured error body on a
// permanent failure, and reuses the client's connection pool for throughput.
// Returns "ok" / true on success, else a human-readable reason / false.
func fetchSample(ctx context.Context, client *http.Client, fileURL, dest string) (string, bool) {
	backoff := triageBackoffBase
	var last string
	for attempt := range triageMaxAttempts {
		if attempt > 0 {
			if !sleepCtx(ctx, backoff) {
				return "canceled", false
			}
			backoff = min(backoff*2, triageBackoffMax)
		}

		reqCtx, cancel := context.WithTimeout(ctx, triageAttemptTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fileURL, http.NoBody)
		if err != nil {
			cancel()
			return "bad request: " + err.Error(), false
		}
		resp, err := client.Do(req) //nolint:gosec // fileURL derives from the operator-supplied --url; this is a CLI client, not a server
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return "canceled", false
			}
			last = "request failed: " + classifyNetErr(err)
			continue // transient: retry with backoff
		}

		if resp.StatusCode == http.StatusOK {
			werr := streamToFile(resp.Body, dest)
			resp.Body.Close() //nolint:errcheck,gosec // body fully read or errored; close is best-effort
			cancel()
			if werr != nil {
				return "write failed: " + werr.Error(), false // local issue; a retry won't help
			}
			return "ok", true
		}

		// Non-200: read a short body so hopper's structured error is visible.
		body := errBodySnippet(resp.Body)
		retryAfter, hasRA := retryAfterSeconds(resp.Header.Get("Retry-After"))
		code := resp.StatusCode
		resp.Body.Close() //nolint:errcheck,gosec // best-effort close
		cancel()

		detail := fmt.Sprintf("%d %s", code, body)
		if code == http.StatusServiceUnavailable || code == http.StatusTooManyRequests {
			last = detail
			if hasRA {
				backoff = retryAfter
			}
			continue // server shed load: back off and retry
		}
		return detail, false // other 4xx/5xx: permanent, do not retry
	}
	return last + " (gave up after retries)", false
}

// streamToFile writes r to dest, reporting the first of the copy or close error.
func streamToFile(r io.Reader, dest string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// classifyNetErr renders a transport error as a short, human diagnosis so the
// triage line distinguishes a timeout from a connection reset from anything else.
func classifyNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout awaiting response"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return err.Error()
}

// errBodySnippet reads up to triageErrBodyMax bytes of a non-200 body and folds
// it to a single trimmed line for the log.
func errBodySnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, triageErrBodyMax)) //nolint:errcheck // best-effort diagnostic
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\n", " "))
}

// retryAfterSeconds parses the integer-seconds form of a Retry-After header.
// The HTTP-date form is unsupported and reported absent, so the caller falls
// back to its own backoff.
func retryAfterSeconds(h string) (time.Duration, bool) {
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	return 0, false
}

func cmdFalsePositives(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "false-positives",
		func(ctx context.Context, db *hopper.DB, _, limit int) ([]*hopper.Sample, error) {
			return db.FalsePositives(ctx, limit)
		})
}

func cmdFalseNegatives(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "false-negatives",
		func(ctx context.Context, db *hopper.DB, _, limit int) ([]*hopper.Sample, error) {
			return db.FalseNegatives(ctx, limit)
		})
}

func cmdBenignReview(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "benign-review",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.BenignReview(ctx, score, limit)
		})
}

func cmdBadReview(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "bad-review",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.BadReview(ctx, score, limit)
		})
}

func cmdConflictReview(ctx context.Context) error {
	return runReviewCommand(ctx, os.Args[2:], "conflict-review",
		func(ctx context.Context, db *hopper.DB, score, limit int) ([]*hopper.Sample, error) {
			return db.ConflictReview(ctx, score, limit)
		})
}

func isTTY() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// logPoolStatsLoop emits a snapshot of the pgxpool every 30s. Anything other
// than baseline numbers (acquired_conns near max, non-zero acquire_wait) is a
// pool-saturation signal.
func logPoolStatsLoop(ctx context.Context, db *hopper.DB) {
	pool := db.Pool()
	if pool == nil {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s := pool.Stat()
		slog.Info("pg pool stats",
			"acquired", s.AcquiredConns(),
			"idle", s.IdleConns(),
			"total", s.TotalConns(),
			"max", s.MaxConns(),
			"acquire_count", s.AcquireCount(),
			"acquire_wait", s.AcquireDuration().Round(time.Millisecond),
			"empty_acquire", s.EmptyAcquireCount(),
			"canceled_acquire", s.CanceledAcquireCount())
	}
}
