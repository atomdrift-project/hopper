package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestLoadIngestsAndServesWorker starts hopper the way production does, on
// testdata/load: `hopper load` walks the data root into the verdict store
// and runs its local postdoc worker, which claims every file, scans it and
// reports back. A restart with one more file in the root files and scans
// that file, and only that one.
//
// It needs a disposable Postgres (HOPPER_TEST_PG_DSN), a postdoc binary and a
// cleave binary (HOPPER_TEST_POSTDOC_BIN and HOPPER_TEST_CLEAVE_BIN, or on
// PATH). Without them it skips, unless HOPPER_TEST_INTEGRATION=require, which
// `make test` sets: there a missing dependency fails the run.
func TestLoadIngestsAndServesWorker(t *testing.T) {
	need := func(what string) {
		t.Helper()
		if os.Getenv("HOPPER_TEST_INTEGRATION") == "require" {
			t.Fatalf("%s is needed (HOPPER_TEST_INTEGRATION=require)", what)
		}
		t.Skipf("%s is needed", what)
	}
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))
	if dsn == "" {
		need("HOPPER_TEST_PG_DSN (a disposable Postgres database)")
	}
	if strings.Contains(dsn, "hopper-db") {
		t.Fatal("HOPPER_TEST_PG_DSN names the production host; this test writes data")
	}
	tool := func(env, name string) string {
		t.Helper()
		if p := os.Getenv(env); p != "" {
			return p
		}
		p, err := exec.LookPath(name)
		if err != nil {
			need(name + " (" + env + " or PATH)")
		}
		return p
	}
	postdoc, cleave := tool("HOPPER_TEST_POSTDOC_BIN", "postdoc"), tool("HOPPER_TEST_CLEAVE_BIN", "cleave")

	ctx := t.Context()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "hopper")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build hopper: %v\n%s", err, out)
	}
	data := filepath.Join(tmp, "data")
	copyTree(t, "testdata/load", data)

	// Hopper's legacy tables and its verdict store each get a schema of
	// their own, dropped afterwards.
	suffix := time.Now().UnixNano()
	legacy, verdict := fmt.Sprintf("load_%d", suffix), fmt.Sprintf("load_v_%d", suffix)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+legacy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		for _, s := range []string{legacy, verdict} {
			if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+s+" CASCADE"); err != nil {
				t.Errorf("drop %s: %v", s, err)
			}
		}
		admin.Close(ctx) //nolint:errcheck // test teardown
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	api := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Hopper runs with a home of its own, which keeps its log and caches out
	// of the user's; cleave's rules and the scan models are linked in from
	// the real one.
	home := filepath.Join(tmp, "home")
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"Library/Application Support/atomdrift", ".local/share/atomdrift"} {
		if _, err := os.Stat(filepath.Join(realHome, rel)); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, rel)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(realHome, rel), filepath.Join(home, rel)); err != nil {
			t.Fatal(err)
		}
	}
	h := &loadProcess{
		t: t, bin: bin, home: home,
		args: []string{
			"load",
			"--db", dsn + sep + "search_path=" + legacy, "--store", verdict, "--data", data,
			"--postdoc", postdoc, "--cleave", cleave, "--workers", "2", "--max-memory-gb", "4",
			"--postdoc-llm", "", "--api-addr", api, "--dashboard-addr", "", "--pprof-addr", "", "--local", "--no-cache", "--no-cleave-validate",
		},
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = verdict
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	first := digests(t, data)
	h.start()
	scanned := h.waitScanned(ctx, pool, first, startupLimit)

	checkFiled(ctx, t, pool, first)
	h.checkServed(ctx, data, first)
	h.checkDependency(ctx, pool, hex.EncodeToString(first["good/npm/hopper-load-parent-1.0.0.tgz"]))

	// A restart with one more file: the startup walk files it, the worker
	// scans it, and nothing scanned before is scanned again.
	h.stop()
	copyTree(t, "testdata/load-later", filepath.Join(data, "incoming"))
	all := maps.Clone(first)
	for path, sha := range digests(t, "testdata/load-later") {
		all["incoming/"+path] = sha
	}
	h.start()
	after := h.waitScanned(ctx, pool, all, startupLimit)
	for path, at := range scanned {
		if !after[path].Equal(at) {
			t.Errorf("%s scanned again (%s, then %s)", path, at, after[path])
		}
	}
	h.stop()
}

// startupLimit is how long a start may take to scan everything. The test
// skips hopper's preflight (`cleave validate` over the whole rule set, which
// takes minutes), so what is left is the walk, the worker's start and six
// small scans.
const startupLimit = 5 * time.Minute

// loadProcess is one `hopper load`, started and stopped as a deploy does.
type loadProcess struct {
	t       *testing.T
	started time.Time
	cmd     *exec.Cmd
	out     *bytes.Buffer
	exit    chan error
	bin     string
	home    string
	args    []string
}

// checkFiled checks what the walk filed and the worker reported: each file
// has a location, atomscan's verdict and no queue row, and each archive its
// members.
func checkFiled(ctx context.Context, t *testing.T, pool *pgxpool.Pool, first map[string][]byte) {
	t.Helper()
	for path, sha := range first {
		var locations, verdicts, queued int
		if err := pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM locations l WHERE l.sample_id = s.id),
				(SELECT count(*) FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = 1),
				(SELECT count(*) FROM queue q WHERE q.sample_id = s.id)
			FROM samples s WHERE s.sha256 = $1`, sha).Scan(&locations, &verdicts, &queued); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if locations == 0 || verdicts != 1 || queued != 0 {
			t.Errorf("%s: %d locations, %d atomscan verdicts, %d queue rows; want a location, a verdict and no queue row",
				path, locations, verdicts, queued)
		}
	}
	for path, sha := range first {
		if filepath.Ext(path) == ".sh" {
			continue
		}
		var members int
		if err := pool.QueryRow(ctx, `SELECT coalesce((SELECT cardinality(c.child_ids) FROM contents c
			JOIN samples s ON s.id = c.parent_id WHERE s.sha256 = $1), 0)`, sha).Scan(&members); err != nil {
			t.Fatal(err)
		}
		if members == 0 {
			t.Errorf("%s: an archive stored with no members", path)
		}
	}
}

// checkServed checks that the API answers from the store: a lookup of the
// gem, and the script's bytes.
func (h *loadProcess) checkServed(ctx context.Context, data string, first map[string][]byte) {
	t := h.t
	t.Helper()
	gem := hex.EncodeToString(first["good/ruby/ruby_everywhere-0.1.12.gem"])
	var record struct {
		SHA256 string `json:"sha256"`
		State  string `json:"state"`
	}
	if code := h.get(ctx, "/v1/lookup?sha256="+gem, &record); code != http.StatusOK || record.State != "analyzed" || record.SHA256 != gem {
		t.Errorf("lookup = %d %+v, want 200 analyzed for %s", code, record, gem)
	}
	script := "good/scripts/hello.sh"
	var body bytes.Buffer
	if code := h.get(ctx, "/v1/files/"+hex.EncodeToString(first[script]), &body); code != http.StatusOK {
		t.Errorf("file = %d, want 200", code)
	} else if want, _ := os.ReadFile(filepath.Join(data, script)); !bytes.Equal(body.Bytes(), want) { //nolint:errcheck // compared below
		t.Errorf("file served %d bytes, not the script's", body.Len())
	}
}

// checkDependency plays a worker that fetched the dependency the parent
// package pins (see the comment in the test) and checks hopper's side of it.
func (h *loadProcess) checkDependency(ctx context.Context, pool *pgxpool.Pool, parent string) {
	t := h.t
	t.Helper()
	// Dependencies. A worker that fetches a package's declared dependency
	// uploads it with a sidecar naming the release. The test plays that
	// worker: a real fetch would leave the machine, and scan refuses loopback
	// addresses. hopper files the upload, its worker scans it, the package's
	// refs name the release, and a conviction of the release raises the
	// package that pins it.
	var pinned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refs r JOIN names n ON n.id = r.name_id JOIN samples s ON s.id = r.sample_id
		WHERE s.sha256 = decode($1, 'hex') AND n.name = 'pkg:npm/events-router' AND r.version = '2.1.5' AND r.kind = 'dependency'`,
		parent).Scan(&pinned); err != nil || pinned != 1 {
		t.Errorf("the parent's refs name events-router@2.1.5 %d times, %v; want once", pinned, err)
	}
	dep, err := os.ReadFile("testdata/load-deps/events-router-2.1.5.tgz")
	if err != nil {
		t.Fatal(err)
	}
	depSum := sha256.Sum256(dep)
	sidecar, err := json.Marshal(&hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: "events-router-2.1.5.tgz", SHA256: hex.EncodeToString(depSum[:]), SizeBytes: int64(len(dep))},
		// As scan sends a fetched dependency's: always with its PURL.
		Package: hopper.PackageRef{
			PURL: "pkg:npm/events-router@2.1.5", Ecosystem: "npm", Name: "events-router", Version: "2.1.5", Feed: "npm",
		},
		Fetch: hopper.Fetch{
			Collector: "scan+load-test", Category: "new", At: time.Now().UTC(),
			URL: "https://registry.npmjs.org/events-router/-/events-router-2.1.5.tgz",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := h.upload(ctx, sidecar, dep); code != http.StatusOK {
		t.Fatalf("upload = %d, want 200", code)
	}
	h.waitScanned(ctx, pool, map[string][]byte{"the uploaded dependency": depSum[:]}, startupLimit)
	var record struct {
		SHA256 string `json:"sha256"`
		State  string `json:"state"`
	}
	if code := h.get(ctx, "/v1/lookup?purl=pkg:npm/events-router@2.1.5", &record); code != http.StatusOK ||
		record.State != "analyzed" || record.SHA256 != hex.EncodeToString(depSum[:]) {
		t.Errorf("lookup of the dependency = %d %+v, want it analyzed under its release", code, record)
	}
	var claims []map[string]string
	for _, source := range []string{"aikido", "socket", "osv"} {
		claims = append(claims, map[string]string{
			"source": source, "subject": "pkg:npm/events-router",
			"affected": "2.1.5", "claim": "malicious", "basis": "hosted",
		})
	}
	if code := h.postJSON(ctx, "/v1/sightings", claims); code != http.StatusOK {
		t.Fatalf("sightings = %d, want 200", code)
	}
	var raised struct {
		FiresAt  *int `json:"fires_at"`
		RaisedBy []struct {
			Kind, Name, Version, Why string
		} `json:"raised_by"`
	}
	code := h.get(ctx, "/v1/lookup?sha256="+parent, &raised)
	if code != http.StatusOK || raised.FiresAt == nil || *raised.FiresAt != 1 || len(raised.RaisedBy) != 1 ||
		raised.RaisedBy[0].Name != "pkg:npm/events-router" || raised.RaisedBy[0].Version != "2.1.5" ||
		raised.RaisedBy[0].Why != hopper.RaisedCorroborated {
		t.Errorf("lookup of the parent = %d %+v, want it raised to 1 by its convicted dependency", code, raised)
	}
}

func (h *loadProcess) start() {
	h.t.Helper()
	h.out = &bytes.Buffer{}
	h.cmd = exec.Command(h.bin, h.args...)
	// The worker runs atomdrift's jurors only: no LLM, no third-party
	// scanners, which a test host need not have installed, and no fetching
	// of the dependencies a sample declares, which would make the test hang
	// on the network and add the packages it fetched to the data root.
	h.cmd.Env = append(os.Environ(), "HOME="+h.home, "SCAN_LLM=", "POSTDOC_SCANNERS=none", "SCAN_FOLLOW=none")
	h.cmd.Stdout, h.cmd.Stderr = h.out, h.out
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := h.cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.started = time.Now()
	h.exit = make(chan error, 1)
	go func() { h.exit <- h.cmd.Wait() }()
	h.t.Cleanup(h.stop)
}

// stop asks hopper to shut down, as systemd does, and waits for it and its
// worker; it kills them if they outlast the grace period.
func (h *loadProcess) stop() {
	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	pgid := h.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM) //nolint:errcheck // already gone is fine
	select {
	case err := <-h.exit:
		if err != nil {
			h.t.Logf("hopper exited: %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL) //nolint:errcheck // already gone is fine
		h.t.Errorf("hopper did not stop within 30 s of SIGTERM (%v)\n%s", <-h.exit, h.log())
	}
	h.cmd = nil
	h.reap()
}

// reap fails the test, and kills them, if any process still names this
// run's data root once hopper has exited: hopper stops its local worker on
// the way out, and a worker left running is the same leak in production.
func (h *loadProcess) reap() {
	data := h.args[indexOf(h.args, "--data")+1]
	out, err := exec.Command("pgrep", "-f", data).Output()
	if err != nil {
		return // pgrep exits 1 when nothing matches
	}
	for pid := range strings.FieldsSeq(string(out)) {
		var n int
		if _, err := fmt.Sscan(pid, &n); err != nil || n == os.Getpid() {
			continue
		}
		cmdline, _ := exec.Command("ps", "-o", "command=", "-p", pid).Output() //nolint:errcheck // for the message only
		h.t.Errorf("hopper left process %d running after it exited: %s", n, strings.TrimSpace(string(cmdline)))
		_ = syscall.Kill(n, syscall.SIGKILL) //nolint:errcheck // already gone is fine
	}
}

// waitScanned waits until every file in want has a scan, and returns when
// each was scanned. It fails, with hopper's log, if hopper exits or the time
// runs out first.
func (h *loadProcess) waitScanned(ctx context.Context, pool *pgxpool.Pool, want map[string][]byte, limit time.Duration) map[string]time.Time {
	h.t.Helper()
	deadline := time.Now().Add(limit)
	for {
		got := map[string]time.Time{}
		for path, sha := range want {
			var at time.Time
			err := pool.QueryRow(ctx, `SELECT sc.scanned_at FROM scans sc JOIN samples s ON s.id = sc.sample_id
				WHERE s.sha256 = $1`, sha).Scan(&at)
			if err == nil {
				got[path] = at
			}
		}
		if len(got) == len(want) {
			h.t.Logf("%d files scanned %s after start", len(got), time.Since(h.started).Round(time.Second))
			return got
		}
		select {
		case err := <-h.exit:
			h.cmd = nil
			h.t.Fatalf("hopper exited (%v) with %d of %d files scanned\n%s", err, len(got), len(want), h.log())
		case <-time.After(2 * time.Second):
		}
		if time.Now().After(deadline) {
			var missing []string
			for path := range want {
				if _, ok := got[path]; !ok {
					missing = append(missing, path)
				}
			}
			h.t.Fatalf("after %s, not scanned: %v\n%s", limit, missing, h.log())
		}
	}
}

// get fetches path from hopper's API into out: a JSON value, or a buffer.
func (h *loadProcess) get(ctx context.Context, path string, out any) int {
	h.t.Helper()
	addr := h.args[indexOf(h.args, "--api-addr")+1]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, http.NoBody)
	if err != nil {
		h.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if b, ok := out.(*bytes.Buffer); ok {
		if _, err := io.Copy(b, resp.Body); err != nil {
			h.t.Fatal(err)
		}
	} else if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			h.t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// postJSON posts v as JSON to path and returns the status.
func (h *loadProcess) postJSON(ctx context.Context, path string, v any) int {
	h.t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.post(ctx, path, "application/json", body)
}

// upload sends bytes with their provenance sidecar, as a worker that fetched
// them does, and returns the status.
func (h *loadProcess) upload(ctx context.Context, sidecar, file []byte) int {
	h.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, part := range []struct {
		name string
		data []byte
	}{{"provenance", sidecar}, {"file", file}} {
		w, err := mw.CreateFormField(part.name)
		if err != nil {
			h.t.Fatal(err)
		}
		if _, err := w.Write(part.data); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		h.t.Fatal(err)
	}
	return h.post(ctx, "/v1/intake/upload", mw.FormDataContentType(), body.Bytes())
}

func (h *loadProcess) post(ctx context.Context, path, contentType string, body []byte) int {
	h.t.Helper()
	addr := h.args[indexOf(h.args, "--api-addr")+1]
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10)) //nolint:errcheck // for the message only
		h.t.Logf("POST %s = %d: %s", path, resp.StatusCode, msg)
	}
	return resp.StatusCode
}

// log is hopper's output and log file, for a failure message: every line
// about the worker or cleave and every warning and error, then the log's tail.
func (h *loadProcess) log() string {
	logFile, _ := os.ReadFile(filepath.Join(h.home, "Library", "Logs", "hopper", "hopper.log")) //nolint:errcheck // absent on Linux
	if len(logFile) == 0 {
		logFile, _ = os.ReadFile(filepath.Join(h.home, ".local", "state", "hopper", "hopper.log")) //nolint:errcheck // absent on macOS
	}
	var picked strings.Builder
	for line := range strings.Lines(string(logFile)) {
		if strings.Contains(line, `"level":"ERROR"`) || strings.Contains(line, `"level":"WARN"`) ||
			strings.Contains(line, "litmus") || strings.Contains(line, "postdoc") || strings.Contains(line, "cleave") {
			picked.WriteString(line)
		}
	}
	tail := func(b string, n int) string {
		if len(b) > n {
			b = b[len(b)-n:]
		}
		return b
	}
	return "--- output ---\n" + tail(h.out.String(), 8<<10) + "\n--- worker, cleave, warnings and errors ---\n" +
		tail(picked.String(), 24<<10) + "\n--- log tail ---\n" + tail(string(logFile), 4<<10)
}

func indexOf(args []string, flag string) int {
	for i, a := range args {
		if a == flag {
			return i
		}
	}
	return -1
}

// digests maps each file under root, by its path from root, to its sha256.
func digests(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[filepath.ToSlash(rel)] = sum[:]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// copyTree copies the files under src into dst, keeping their layout.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
