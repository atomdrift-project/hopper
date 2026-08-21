#!/bin/sh
# watch.sh — compact live view of local hopper logical-replica health.
# One line of subscription status plus one line per subscribed table
# (capped at 10). Read-only. Loops in portable sh: GNU watch(1) does not
# exist on FreeBSD (watch(8) there is an unrelated tty-snooping tool).
#
# Overridable via env: REMOTE_HOST, REMOTE_USER, REMOTE_DB, LOCAL_DB,
# SUBSCRIPTION (auto-detected from pg_subscription when unset),
# INTERVAL (seconds, default 60), ETA_WINDOW (seconds, default 900),
# ONCE (true = single snapshot). History survives restarts under /tmp so
# a 15-minute ETA average can accumulate across invocations.
# Remote queries read ~/.pgpass; a missing publisher just blanks ETAs.

set -u

REMOTE_HOST="${REMOTE_HOST:-hopper-db}"
REMOTE_USER="${REMOTE_USER:-hopper}"
REMOTE_DB="${REMOTE_DB:-hopper}"
LOCAL_DB="${LOCAL_DB:-hopper}"
SUBSCRIPTION="${SUBSCRIPTION:-}"
INTERVAL="${INTERVAL:-60}"
ETA_WINDOW="${ETA_WINDOW:-900}"
ONCE="${ONCE:-false}"

# A pipe or file isn't a dashboard — print one frame and exit.
if [ ! -t 1 ]; then
    ONCE=true
fi

# Pick a local admin escalation tool (matches diagnose.sh / setup.sh).
if psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { psql -U postgres "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -n -u postgres psql "$@"; }
elif command -v doas >/dev/null 2>&1 && doas -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { doas -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -n -u postgres psql "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -u postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; then
    admin() { sudo -u postgres psql "$@"; }
else
    echo "error: no admin access to local postgres" >&2
    exit 1
fi

remote() {
    PGCONNECT_TIMEOUT=3 psql -h "$REMOTE_HOST" -U "$REMOTE_USER" -d "$REMOTE_DB" "$@"
}

# Auto-detect the subscription name rather than guessing: a wrong name makes
# every filtered query come back empty, which reads as "not set up at all".
if [ -z "$SUBSCRIPTION" ]; then
    subs=$(admin -d "$LOCAL_DB" -tA <<'SQL'
SELECT subname FROM pg_subscription
 WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
 ORDER BY subname;
SQL
)
    SUBSCRIPTION=$(printf '%s\n' "$subs" | head -n 1)
    if [ -z "$SUBSCRIPTION" ]; then
        echo "error: no subscription found in database '$LOCAL_DB'; is the replica set up?" >&2
        exit 1
    fi
fi

SNAP="${TMPDIR:-/tmp}/hopper-replica-watch.$$.snap"
# Persist samples across restarts so the 15-minute window survives Ctrl-C.
hist_safe=$(printf '%s' "$SUBSCRIPTION" | tr -c 'A-Za-z0-9._-' '_')
HIST="${TMPDIR:-/tmp}/hopper-replica-watch.${hist_safe}.hist"
: >>"$HIST"
COLOR=0
[ -t 1 ] && COLOR=1

cleanup() {
    [ -t 1 ] && tput cnorm >/dev/null 2>&1 || true
    rm -f "$SNAP"
}
trap cleanup EXIT INT TERM HUP

[ -t 1 ] && [ "$ONCE" != true ] && tput civis >/dev/null 2>&1 || true

# Collect one snapshot. Fields are '|' separated; kinds are the first column.
#   SUB   name|enabled|apply_pid|last_msg_age|ready|total|latest_end_age|wait_event|received_bytes
#   ERRS  apply_err|sync_err
#   SLOT  name|active|wal_status|retained_bytes|confirmed_bytes
#   REM   table|rows|bytes
#   TBL   table|state|local_rows|local_bytes|copy_bytes|copy_total|copy_tuples|sync_pid|idx_phase|analyze_phase|idx_done|idx_total|unready_idx
#   NOW   epoch
collect() {
    now=$(date +%s)
    {
        printf 'NOW|%s\n' "$now"

        admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA -F '|' <<'SQL'
SELECT 'SUB',
       s.subname,
       CASE WHEN s.subenabled THEN 't' ELSE 'f' END,
       COALESCE(a.pid::text, ''),
       COALESCE((EXTRACT(EPOCH FROM (now() - a.last_msg_receipt_time)))::bigint::text, ''),
       (SELECT count(*) FROM pg_subscription_rel r
         WHERE r.srsubid = s.oid AND r.srsubstate = 'r'),
       (SELECT count(*) FROM pg_subscription_rel r
         WHERE r.srsubid = s.oid),
       COALESCE((EXTRACT(EPOCH FROM (now() - a.latest_end_time)))::bigint::text, ''),
       COALESCE((SELECT wait_event FROM pg_stat_activity WHERE pid = a.pid), ''),
       COALESCE(pg_wal_lsn_diff(a.received_lsn, '0/0'), 0)
  FROM pg_subscription s
  LEFT JOIN pg_stat_subscription a
    ON a.subname = s.subname AND a.relid IS NULL
 WHERE s.subname = :'sub';
SQL

        # PG15+; a missing view must not fail the whole snapshot.
        errs=$(admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA -F '|' <<'SQL' 2>/dev/null || true
SELECT apply_error_count, sync_error_count
  FROM pg_stat_subscription_stats
 WHERE subname = :'sub';
SQL
)
        case "$errs" in
            *\|*) printf 'ERRS|%s\n' "$errs" ;;
            *)    printf 'ERRS|0|0\n' ;;
        esac

        admin -d "$LOCAL_DB" -v sub="$SUBSCRIPTION" -tA -F '|' <<'SQL'
SELECT 'TBL',
       CASE WHEN n.nspname = 'public' THEN c.relname
            ELSE n.nspname || '.' || c.relname END,
       r.srsubstate,
       COALESCE(st.n_live_tup, 0),
       COALESCE(pg_table_size(c.oid), 0),
       COALESCE(p.bytes_processed, 0),
       COALESCE(p.bytes_total, 0),
       COALESCE(p.tuples_processed, 0),
       COALESCE(ss.pid::text, ''),
       COALESCE(i.phase, ''),
       COALESCE(an.phase, ''),
       COALESCE(i.tuples_done, 0),
       COALESCE(i.tuples_total, 0),
       COALESCE((SELECT count(*) FROM pg_index x
                  WHERE x.indrelid = c.oid AND NOT x.indisready), 0)
  FROM pg_subscription_rel r
  JOIN pg_subscription s ON s.oid = r.srsubid
  JOIN pg_class c ON c.oid = r.srrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_stat_user_tables st ON st.relid = c.oid
  LEFT JOIN LATERAL (
      SELECT bytes_processed, bytes_total, tuples_processed
        FROM pg_stat_progress_copy
       WHERE relid = c.oid
       LIMIT 1
  ) p ON true
  LEFT JOIN pg_stat_subscription ss ON ss.relid = c.oid
  LEFT JOIN LATERAL (
      SELECT phase, tuples_done, tuples_total
        FROM pg_stat_progress_create_index
       WHERE relid = c.oid
       ORDER BY tuples_total DESC NULLS LAST
       LIMIT 1
  ) i ON true
  LEFT JOIN LATERAL (
      SELECT phase
        FROM pg_stat_progress_analyze
       WHERE relid = c.oid
       LIMIT 1
  ) an ON true
 WHERE s.subname = :'sub'
 ORDER BY c.relname;
SQL

        remote -v sub="$SUBSCRIPTION" -tA -F '|' <<'SQL' 2>/dev/null || true
SELECT 'SLOT',
       slot_name,
       CASE WHEN active THEN 't' ELSE 'f' END,
       COALESCE(wal_status, ''),
       COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0),
       COALESCE(pg_wal_lsn_diff(confirmed_flush_lsn, '0/0'), 0)
  FROM pg_replication_slots
 WHERE slot_name = :'sub' OR slot_name LIKE 'pg\_%\_sync\_%'
 ORDER BY slot_name;
SQL

        remote -tA -F '|' <<'SQL' 2>/dev/null || true
SELECT 'REM',
       relname,
       COALESCE(n_live_tup, 0),
       COALESCE(pg_table_size(relid), 0)
  FROM pg_stat_user_tables
 WHERE schemaname = 'public'
 ORDER BY relname;
SQL
    } >"$SNAP"
}

# Render ≤10 lines from SNAP, using HIST for a rolling ETA_WINDOW average.
render() {
    clock=$(date +%H:%M:%S)
    awk -F'|' -v color="$COLOR" -v clock="$clock" -v histname="$HIST" -v window="$ETA_WINDOW" '
    function esc(code) { return color ? sprintf("\033[%sm", code) : "" }
    function green(s)  { return esc(32) s esc(0) }
    function red(s)    { return esc(31) s esc(0) }
    function dim(s)    { return esc(2) s esc(0) }
    function fmt_bytes(n) {
        n = n + 0
        if (n >= 1099511627776) return sprintf("%.1fTB", n / 1099511627776)
        if (n >= 1073741824)    return sprintf("%.1fGB", n / 1073741824)
        if (n >= 1048576)       return sprintf("%.0fMB", n / 1048576)
        if (n >= 1024)          return sprintf("%.0fkB", n / 1024)
        return sprintf("%dB", n)
    }
    function fmt_num(n) {
        n = n + 0
        if (n >= 1000000000) return sprintf("%.1fB", n / 1000000000)
        if (n >= 1000000)    return sprintf("%.1fM", n / 1000000)
        if (n >= 1000)       return sprintf("%.1fk", n / 1000)
        return sprintf("%d", n)
    }
    function fmt_dur(s) {
        s = int(s + 0.5)
        if (s < 0) return "?"
        if (s >= 86400) return sprintf("%dd%dh", int(s / 86400), int((s % 86400) / 3600))
        if (s >= 3600)  return sprintf("%dh%02dm", int(s / 3600), int((s % 3600) / 60))
        if (s >= 60)    return sprintf("%dm%02ds", int(s / 60), s % 60)
        return sprintf("%ds", s)
    }
    function eta_word(sec) {
        if (sec == "" || sec + 0 <= 0) return ""
        if (sec + 0 > 86400 * 14) return "ETA >2w"
        return "ETA " fmt_dur(sec)
    }
    function eta_avg(sec) {
        e = eta_word(sec)
        if (e == "" || dt < 60) return e
        return e " (" int((dt / 60) + 0.5) "m)"
    }
    function line(icon, name, state, rest) {
        printf "%s  %-22s  %-10s  %s\n", icon, name, state, rest
    }

    BEGIN { apply_err = 0; sync_err = 0; lost = 0; ntbl = 0; nslot = 0 }

    FILENAME == histname {
        if ($1 == "SAMP") {
            ns++
            hts[ns] = $2 + 0
            hret[ns] = $3 + 0
            hconf[ns] = $4 + 0
            hrecv[ns] = $5 + 0
            hend[ns] = $6 + 0
        } else if ($1 == "TB") {
            tb[$2 + 0, $3] = $4 + 0
            tt[$2 + 0, $3] = $5 + 0
        }
        next
    }

    $1 == "NOW"  { now = $2 + 0; next }
    $1 == "ERRS" { apply_err = $2 + 0; sync_err = $3 + 0; next }
    $1 == "SUB"  {
        subname = $2; enabled = $3; apply_pid = $4
        last_age = $5; ready = $6 + 0; total = $7 + 0
        end_age = $8; wait_ev = $9; recv_bytes = $10 + 0
        next
    }
    $1 == "SLOT" {
        slot[++nslot] = $2
        slot_active[$2] = $3
        slot_wal[$2] = $4
        slot_ret[$2] = $5 + 0
        slot_conf[$2] = $6 + 0
        if ($2 == subname) {
            main_slot = $2
            main_active = $3
            main_wal = $4
            main_ret = $5 + 0
            main_conf = $6 + 0
        }
        if ($4 == "lost") lost = 1
        next
    }
    $1 == "REM" { rem_rows[$2] = $3 + 0; rem_bytes[$2] = $4 + 0; next }
    $1 == "TBL" {
        ntbl++
        name[ntbl] = $2
        st[ntbl] = $3
        lrows[ntbl] = $4 + 0
        lbytes[ntbl] = $5 + 0
        cbytes[ntbl] = $6 + 0
        ctotal[ntbl] = $7 + 0
        ctups[ntbl] = $8 + 0
        spid[ntbl] = $9
        iphase[ntbl] = $10
        aphase[ntbl] = $11
        idone[ntbl] = $12 + 0
        itotal[ntbl] = $13 + 0
        unready[ntbl] = $14 + 0
        next
    }

    END {
        # Oldest sample still inside the window is the 15-minute (or shorter
        # warming-up) baseline. Samples at/after `now` are the current frame.
        cutoff = (now > 0 && window > 0) ? now - window : 0
        oldest = 0
        for (i = 1; i <= ns; i++) {
            if (hts[i] >= now || hts[i] < cutoff) continue
            if (oldest == 0 || hts[i] < hts[oldest]) oldest = i
        }
        if (oldest) {
            prev_now = hts[oldest]
            prev_ret = hret[oldest]
            prev_conf = hconf[oldest]
            prev_recv = hrecv[oldest]
            prev_end = hend[oldest]
        }
        dt = (prev_now > 0 && now > prev_now) ? (now - prev_now) : 0
        busy = 0
        remain_bytes = 0
        rate_bytes = 0
        known_remain = 0

        for (i = 1; i <= ntbl; i++) {
            t = name[i]
            worked = (cbytes[i] > 0 || ctups[i] > 0 || spid[i] != "" || iphase[i] != "" || aphase[i] != "")
            if (worked) busy++

            # Prefer live COPY bytes, then local heap size, for rate samples.
            cur_b = cbytes[i] > 0 ? cbytes[i] : lbytes[i]
            if (oldest && ((hts[oldest], t) in tb))
                pbytes[t] = tb[hts[oldest], t]
            if (oldest && ((hts[oldest], t) in tt))
                ptups[t] = tt[hts[oldest], t]
            if (dt > 0 && t in pbytes && cur_b > pbytes[t])
                rate_bytes += (cur_b - pbytes[t]) / dt

            remain = -1
            if (ctotal[i] > 0 && cbytes[i] >= 0)
                remain = ctotal[i] - cbytes[i]
            else if (t in rem_bytes && rem_bytes[t] > 0) {
                done = cbytes[i] > 0 ? cbytes[i] : lbytes[i]
                remain = rem_bytes[t] - done
            }
            if (st[i] != "r" || iphase[i] != "" || aphase[i] != "") {
                if (remain >= 0) {
                    remain_bytes += remain
                    known_remain = 1
                } else if (t in rem_bytes && st[i] != "r") {
                    remain_bytes += rem_bytes[t]
                    known_remain = 1
                }
            }
            t_remain[i] = remain
            t_curb[i] = cur_b
        }

        all_ready = (total > 0 && ready == total && busy == 0)
        apply_up = (apply_pid != "")
        sub_down = (enabled == "f" && busy == 0)
        apply_dead = (enabled == "t" && !apply_up && busy == 0 && total > 0)
        stale = (apply_up && last_age != "" && last_age + 0 > 120)
        # Tables can all be srsubstate=r while apply is still chewing the
        # post-copy WAL backlog — 64MB / 45s is "caught up enough to call live".
        lagging = (main_ret > 64*1024*1024 || (end_age != "" && end_age + 0 > 45))
        # Error counters are cumulative since stats_reset — show them, but
        # only siren on a live failure (slot lost, sub down, apply dead, stale).
        bad = (lost || sub_down || apply_dead || stale)

        net_bps = 0
        apply_bps = 0
        if (dt > 0) {
            if (prev_ret > 0 && main_ret > 0) net_bps = (prev_ret - main_ret) / dt
            if (prev_conf > 0 && main_conf > prev_conf) apply_bps = (main_conf - prev_conf) / dt
            else if (prev_recv > 0 && recv_bytes > prev_recv) apply_bps = (recv_bytes - prev_recv) / dt
        }

        if (bad) {
            hicon = red("🚨")
            if (lost)                hstate = "slot-lost"
            else if (enabled == "f") hstate = "DISABLED"
            else if (apply_dead)     hstate = "apply-down"
            else                     hstate = "stale"
        } else if (all_ready && apply_up && !lagging) {
            hicon = green("✅")
            hstate = "streaming"
        } else if (lagging && apply_up) {
            if (dt > 0 && net_bps < -1024*1024) {
                hicon = red("🚨")
                hstate = "falling-behind"
            } else {
                hicon = "🏃"
                hstate = "catch-up"
            }
        } else if (busy > 0 || (total > 0 && ready < total)) {
            hicon = "🏃"
            hstate = (ready == total && busy > 0) ? "finishing" : "copying"
        } else {
            hicon = "⏳"
            hstate = "starting"
        }

        rest = ""
        if (total > 0) rest = rest sprintf("%d/%d tbls", ready, total)
        if (apply_up) rest = rest (rest == "" ? "" : "  ") "apply " apply_pid
        else if (enabled == "t") rest = rest (rest == "" ? "" : "  ") "apply —"
        if (wait_ev != "") rest = rest (rest == "" ? "" : "  ") wait_ev
        if (main_ret > 0) rest = rest (rest == "" ? "" : "  ") "lag " fmt_bytes(main_ret)
        else if (main_slot == "" && nslot == 0) rest = rest (rest == "" ? "" : "  ") dim("publisher ?")
        if (end_age != "" && end_age + 0 > 5)
            rest = rest (rest == "" ? "" : "  ") fmt_dur(end_age + 0) " behind"
        if (main_active == "f" && main_slot != "") rest = rest "  slot idle"
        if (apply_err > 0) rest = rest "  apply_err=" apply_err
        if (sync_err > 0) rest = rest "  sync_err=" sync_err
        if (lagging && apply_up) {
            if (apply_bps > 1024)
                rest = rest "  " fmt_bytes(apply_bps) "/s"
            caught = 0
            if (dt > 0 && prev_end > 0 && end_age != "")
                caught = prev_end - (end_age + 0)
            if (net_bps > 1024) {
                e = eta_avg(main_ret / net_bps)
                if (e != "") rest = rest "  " e
            } else if (caught > 0 && end_age + 0 > 0) {
                e = eta_avg((end_age + 0) * dt / caught)
                if (e != "") rest = rest "  " e
            } else if (apply_bps > 1024 && main_ret > 0) {
                e = eta_avg(main_ret / apply_bps)
                if (e != "") rest = rest "  " e
                if (net_bps < -1024) rest = rest "  gap widening"
            } else if (dt >= 60 && caught <= 0 && end_age + 0 > 45) {
                rest = rest "  not catching up"
            } else {
                rest = rest "  ETA …"
            }
        } else if (known_remain && rate_bytes > 1024 && !all_ready) {
            overall = remain_bytes / rate_bytes
            e = eta_avg(overall)
            if (e != "") rest = rest "  " e
        } else if (!all_ready && (busy > 0 || ready < total)) {
            rest = rest "  ETA …"
        }
        rest = rest "  " dim(clock)

        if (subname == "") subname = "(no subscription)"
        line(hicon, subname, hstate, rest)

        max_tbl = 8
        shown = 0
        for (i = 1; i <= ntbl && shown < max_tbl; i++) {
            shown++
            t = name[i]
            state = st[i]
            worked = (cbytes[i] > 0 || ctups[i] > 0 || spid[i] != "" || iphase[i] != "" || aphase[i] != "")
            stalled = (state ~ /^[idf]/ && !worked && (enabled == "f" || !apply_up))
            if (state == "r" && !worked && (unready[i] > 0)) stalled = 0

            kind = "wait"
            word = "queued"
            extra = ""

            if (stalled || (state ~ /^[id]/ && enabled == "f" && !worked)) {
                kind = "dead"
                word = "stalled"
                extra = "no worker"
            } else if (iphase[i] != "") {
                kind = "run"
                word = "indexing"
                if (itotal[i] > 0)
                    extra = sprintf("%s  %s/%s tuples", iphase[i], fmt_num(idone[i]), fmt_num(itotal[i]))
                else
                    extra = iphase[i]
                if (unready[i] > 0) extra = extra sprintf("  %d idx", unready[i])
            } else if (aphase[i] != "") {
                kind = "run"
                word = "analyzing"
                extra = aphase[i]
            } else if (cbytes[i] > 0 || ctups[i] > 0 || (state == "d" && worked)) {
                kind = "run"
                word = "copying"
                pct = ""
                frac = -1
                if (ctotal[i] > 0) frac = cbytes[i] / ctotal[i]
                else if (t in rem_bytes && rem_bytes[t] > 0 && (cbytes[i] > 0 || lbytes[i] > 0))
                    frac = (cbytes[i] > 0 ? cbytes[i] : lbytes[i]) / rem_bytes[t]
                else if (t in rem_rows && rem_rows[t] > 0 && ctups[i] > 0)
                    frac = ctups[i] / rem_rows[t]
                if (frac > 1) frac = 1
                if (frac >= 0) pct = sprintf("%d%%  ", int(frac * 100))
                if (ctotal[i] > 0)
                    extra = pct fmt_bytes(cbytes[i]) "/" fmt_bytes(ctotal[i])
                else if (t in rem_bytes && rem_bytes[t] > 0 && cbytes[i] > 0)
                    extra = pct fmt_bytes(cbytes[i]) "/" fmt_bytes(rem_bytes[t])
                else if (ctups[i] > 0 && t in rem_rows && rem_rows[t] > 0)
                    extra = pct fmt_num(ctups[i]) "/" fmt_num(rem_rows[t]) " rows"
                else if (ctups[i] > 0)
                    extra = fmt_num(ctups[i]) " rows"
                else if (lrows[i] > 0)
                    extra = "~" fmt_num(lrows[i]) " rows"
                else
                    extra = "starting"
            } else if (state == "d") {
                kind = "wait"
                word = "copying"
                extra = "waiting worker"
            } else if (state == "i") {
                kind = "wait"
                word = "init"
                extra = worked ? ("pid " spid[i]) : "waiting its turn"
            } else if (state == "f" || state == "s") {
                kind = apply_up || worked ? "run" : "wait"
                word = (state == "f") ? "catch-up" : "syncing"
                extra = apply_up ? ("apply " apply_pid) : "waiting apply"
                if (lrows[i] > 0) extra = extra "  ~" fmt_num(lrows[i]) " rows"
            } else if (state == "r") {
                kind = "ok"
                word = "ready"
                extra = "~" fmt_num(lrows[i]) " rows"
            } else {
                kind = "wait"
                word = (state == "" ? "unknown" : state)
            }

            # Per-table ETA from this tables own rate, else the aggregate.
            teta = ""
            if (kind == "run") {
                t_rate = 0
                if (dt > 0 && t in pbytes && t_curb[i] > pbytes[t])
                    t_rate = (t_curb[i] - pbytes[t]) / dt
                if (t_rate <= 0 && rate_bytes > 0 && ntbl - ready <= 2)
                    t_rate = rate_bytes
                if (iphase[i] != "" && itotal[i] > 0 && dt > 0 && t in ptups && idone[i] > ptups[t]) {
                    irate = (idone[i] - ptups[t]) / dt
                    if (irate > 0) teta = eta_avg((itotal[i] - idone[i]) / irate)
                } else if (t_remain[i] >= 0 && t_rate > 1024) {
                    teta = eta_avg(t_remain[i] / t_rate)
                } else if (kind == "run" && teta == "") {
                    teta = "ETA …"
                }
            }

            if (kind == "ok")   ic = green("✅")
            else if (kind == "run") ic = "🏃"
            else if (kind == "dead") ic = red("❌")
            else ic = "⏳"

            detail = extra
            if (teta != "") detail = (detail == "" ? teta : detail "  " teta)
            if (detail == "") detail = dim("—")
            line(ic, t, word, detail)
        }
        if (ntbl > max_tbl)
            line("⏳", "+" (ntbl - max_tbl) " more", "", dim("see make diagnose-replica"))
        if (ntbl == 0)
            line("⏳", "(no tables)", "waiting", "subscription has no relations yet")
    }
    ' "$HIST" "$SNAP"
}

# Append this SNAP onto HIST and drop samples older than the ETA window.
record() {
    [ -f "$HIST" ] || : >"$HIST"
    awk -F'|' -v window="$ETA_WINDOW" -v interval="$INTERVAL" -v snap="$SNAP" '
        FILENAME != snap && $1 == "SAMP" {
            ns++
            hts[ns] = $2 + 0; line[ns] = $0
            next
        }
        FILENAME != snap && $1 == "TB" {
            nt++
            tts[nt] = $2 + 0; tline[nt] = $0
            next
        }
        $1 == "NOW" { now = $2 + 0 }
        $1 == "SUB" { subn = $2; recv = $10 + 0; endage = $8 + 0 }
        $1 == "SLOT" {
            if ($2 == subn || (!have_main && $2 != "")) {
                ret = $5 + 0
                conf = $6 + 0
                if ($2 == subn) have_main = 1
            }
        }
        $1 == "TBL" {
            tn++
            tname[tn] = $2
            tbytes[tn] = ($6 + 0 > 0) ? $6 : $5
            ttups[tn] = $12 + 0
        }
        END {
            keep_after = now - window - interval - 30
            if (keep_after < 0) keep_after = 0
            for (i = 1; i <= ns; i++)
                if (hts[i] >= keep_after && hts[i] < now) print line[i]
            for (i = 1; i <= nt; i++)
                if (tts[i] >= keep_after && tts[i] < now) print tline[i]
            print "SAMP|" now+0 "|" ret+0 "|" conf+0 "|" recv+0 "|" endage+0
            for (i = 1; i <= tn; i++)
                print "TB|" now+0 "|" tname[i] "|" tbytes[i] "|" ttups[i]
        }
    ' "$HIST" "$SNAP" >"$HIST.new" && mv "$HIST.new" "$HIST"
}

if [ "$ONCE" = true ]; then
    collect
    render
    record
    exit 0
fi

# Hide the clear-screen CSI when stdout is a tty; each frame is ≤10 lines.
collect
render
record
while :; do
    sleep "$INTERVAL"
    collect
    printf '\033[2J\033[H'
    render
    record
done
