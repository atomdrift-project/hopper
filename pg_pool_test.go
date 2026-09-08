package hopper

import "testing"

// The publisher has 100 connections with 3 reserved for superusers, so 97 are
// usable. Every long-lived service must fit inside that with room for an
// operator's psql and a maintenance command.
//
// On 2026-09-07 they did not: one pool size served every consumer, four
// services at 32 apiece is 128 against 97, and the cluster refused a
// `reconcile-corroborated` run with 94 slots held and 92 of them idle.
func TestServicePoolsFitThePublisherBudget(t *testing.T) {
	const (
		maxConnections = 100
		superuserOnly  = 3
		usable         = maxConnections - superuserOnly
	)

	// Every consumer that runs continuously, plus the serving API.
	services := []AppName{"hopper", "forager", "promoter", "prism"}
	var ceiling, reserved int32
	for _, app := range services {
		maxC, minC := poolSize(app)
		if minC > maxC {
			t.Errorf("%s: minimum %d exceeds ceiling %d", app, minC, maxC)
		}
		ceiling += maxC
		reserved += minC
	}

	// The whole fleet at full stretch must still leave most of the publisher
	// free, because a connection budget spent is a budget an operator cannot
	// borrow when something is wrong.
	if int(ceiling) > usable/2 {
		t.Errorf("service ceilings total %d of %d usable connections; want at most half", ceiling, usable)
	}
	if int(reserved) > usable/8 {
		t.Errorf("services permanently reserve %d of %d connections", reserved, usable)
	}
}

// Only the serving API gets a pool. Everything else is a client, and a client
// that is not serving requests has no business holding capacity from one that
// is. This is the inversion of the policy that locked an operator out of
// reconcile-corroborated on 2026-09-07.
func TestOnlyTheServingAPIGetsAPool(t *testing.T) {
	if maxC, minC := poolSize("hopper"); maxC < 8 || minC == 0 {
		t.Errorf("serving API pool = %d/%d; it serves a polling worker fleet and needs both", maxC, minC)
	}
	for _, app := range []AppName{
		"forager", "promoter", "prism",
		"hopper-reconcile-corroborated", "hopper-cli", "hopper-migrate", "anything-else",
	} {
		maxC, minC := poolSize(app)
		if maxC != 4 {
			t.Errorf("%s may open %d connections; the default is four, widened per-DSN when measured", app, maxC)
		}
		if minC != 0 {
			t.Errorf("%s reserves %d connections; only the serving API reserves", app, minC)
		}
	}
}

// Two is a floor, not a preference. tryMigrationLock acquires a connection and
// holds it for the whole migration, so every statement the migration then runs
// needs a second one from the same pool. At MaxConns=1 that second acquire
// waits on the pool semaphore forever, and nothing is visible server-side: the
// held connection is idle and no query is blocked.
//
// Measured 2026-09-08: `hopper load` sat 45 minutes at "Migrating database",
// holding the migration advisory lock, its single connection idle since
// SELECT pg_try_advisory_lock.
func TestEveryPoolCanHoldAConnectionAndStillQuery(t *testing.T) {
	for _, app := range []AppName{
		"hopper", "hopper-load", "forager", "promoter", "prism",
		"hopper-cli", "hopper-migrate", "anything-else",
	} {
		if maxC, _ := poolSize(app); maxC < 3 {
			t.Errorf("%s pool allows %d connections; migrating holds one, builds an index on another, and probes the catalog, so it would deadlock", app, maxC)
		}
	}
}
