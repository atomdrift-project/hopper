package main

// The write relay lets a serve-replica instance present the FULL hopper API
// from a single URL: reads answer locally from the replica database, and the
// client-facing mutations are proxied verbatim to the primary. Clients then
// need one endpoint and zero routing knowledge — the topology (which calls
// must land on the publisher) becomes this process's concern instead of every
// client's. Before this, each consumer that moved to the replica needed its
// own read/write DSN split, and two of them (prism, cyclotron) shipped with
// subtly wrong halves.
//
// Three rules keep the relay from becoming a liability:
//
//  1. Pass-through, never store-and-forward. The proxy adds no buffering, no
//     queueing, and no retries, and the primary's status codes propagate
//     verbatim — above all its 503 slot-shed responses, whose semantics
//     clients' lanes depend on (a shed worker result is re-dispatched; a shed
//     renewal is gone for good). A relay that "helpfully" retried or queued
//     would mint duplicate stores during publisher hiccups.
//
//  2. The worker firehose stays out. GET /api/next, GET /api/heartbeat and
//     POST /api/result keep answering 403 here even with the relay enabled:
//     result envelopes are the publisher's hot ingest path, and routing them
//     client → replica → publisher would double-ship every body through this
//     box for zero benefit. Workers are fleet config, not casual clients —
//     they point at the primary directly.
//
//  3. Read-after-write is explicit, not implied. A client that mutates via
//     the relay and immediately reads it back would otherwise see the
//     replica's apply lag (seconds normally, unbounded during backlog) — the
//     exact mechanism behind the 2026-07 forced-rescan invisibility bug. Any
//     lookup route accepts ?fresh=1 (or X-Hopper-Fresh: 1) to route that one
//     read to the primary instead.

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/atomdrift-project/hopper"
)

// relayResponseHeaderWait bounds how long the relay waits for the primary to
// begin answering. It must comfortably exceed the primary's slotAcquireWait
// (3s) plus a slow store (tens of seconds observed under load), because a
// premature 502 here would mask the primary's real answer — including the 503
// shed that clients are required to see. Generous rather than snappy: the
// client owns the overall deadline.
const relayResponseHeaderWait = 2 * time.Minute

// newWriteRelay builds the reverse proxy that forwards client-facing
// mutations to the primary hopper at base (scheme://host[:port]; any path on
// it is rejected — the relay preserves the request's own path and query).
// tokenFile optionally names a file holding a bearer token for the primary:
// when set, the relay REPLACES the inbound Authorization header with it, for
// deployments where replica and primary tokens differ. When empty, the
// client's own Authorization header passes through untouched and the primary
// applies its normal auth.
func newWriteRelay(base string, tokenFile string) (http.Handler, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("relay: --relay-writes-to must be a base URL like http://hopper-api:8081 (got %q)", base)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("relay: --relay-writes-to must not carry a path (got %q); the relay preserves each request's own path", base)
	}

	var primaryToken *string
	if tokenFile != "" {
		tok, terr := hopper.ReadTokenFile(tokenFile)
		if terr != nil {
			return nil, fmt.Errorf("relay: --relay-token-file %s: %w", tokenFile, terr)
		}
		primaryToken = &tok
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)          // scheme+host from the primary; path/query from the request
			pr.SetXForwarded()    // X-Forwarded-For/Host/Proto for the primary's logs
			pr.Out.Host = u.Host // primary routes/authenticates by its own name
			// Everything else — Authorization, the lane header, content type —
			// passes through verbatim from the inbound request.
			if primaryToken != nil {
				pr.Out.Header.Set("Authorization", "Bearer "+*primaryToken)
			}
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: relayResponseHeaderWait,
			// Modest pool: the relay carries low-volume client mutations, not
			// the worker firehose (rule 2 above).
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Reachability failures are OURS to report (502); everything the
			// primary itself said — 4xx, 5xx, 503 sheds — has already been
			// streamed through untouched and never lands here.
			slog.WarnContext(r.Context(), "write relay: primary unreachable",
				"method", r.Method, "path", r.URL.Path, "error", err)
			writeJSONError(w, http.StatusBadGateway,
				`{"error":"primary hopper unreachable via relay; retry later or address the primary directly"}`)
		},
	}
	return proxy, nil
}

// freshOr wraps a local read handler with the read-after-write escape hatch:
// ?fresh=1 (or X-Hopper-Fresh: 1) routes this one request to the primary via
// the relay, so a client that just mutated can read its own write instead of
// racing replica apply lag. Without the relay configured — or without the
// flag — the local handler answers from the replica as usual.
func (s *apiServer) freshOr(local http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.relay != nil && (r.URL.Query().Get("fresh") == "1" || r.Header.Get("X-Hopper-Fresh") == "1") {
			s.relay.ServeHTTP(w, r)
			return
		}
		local(w, r)
	}
}
