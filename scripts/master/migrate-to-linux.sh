#!/bin/sh
# migrate-to-linux.sh - Move the hopper Postgres MASTER off the OmniOS
# `postgres` zone on gandalf (10.9.8.3) onto a Linux/NixOS host, using ZFS
# replication as the transport.
#
# WHY ZFS AND NOT LOGICAL REPLICATION
#
# The obvious answer -- point a new logical subscriber at the master and
# promote it -- does not work here. Single-slot logical decoding on this
# publisher is single-threaded and CPU-bound at roughly the rate the master
# generates WAL, so a fresh 2.2 TB subscription takes days (galadriel's last
# rebuild took four), and a second slot would double decode load on an already
# saturated walsender, starving the existing replica. Logical replication also
# does not carry sequences or unpublished tables, so it is not a complete
# master migration in the first place.
#
# ZFS send is a physical copy, so it is exact, resumable, and incremental: you
# send a base while the master stays up, top it up as often as you like, and
# the only downtime is one final incremental taken after a clean shutdown.
#
# THE ONE THING A PHYSICAL COPY GETS WRONG: COLLATION
#
# This cluster is `en_US.UTF-8` with datlocprovider='c' -- the platform libc.
# Every text btree is therefore ordered by *illumos* strcoll, and it is about
# to land on *glibc*. Measured on this database's real data: 13% of
# `sample_locations.path` values (5222 of 40000) sort differently between the
# two. Those indexes are corrupt-by-definition on arrival -- range scans miss
# rows and unique constraints stop excluding duplicates.
#
# Measured on the same data, pure-hex columns (sha256, parent_sha256) sort
# identically under illumos libc, glibc, and C. That is what `HEX_COLS` below
# encodes, and it cuts the rebuild from 714 GB across 59 indexes to 384 GB
# across 48. `amcheck` re-proves this per index on the target -- run the
# `amcheck` subcommand before you open the new master to traffic, and treat it,
# not this script's heuristic, as the authority.
#
# NOTE: this affects `pg_basebackup`, streaming replication, a tar pipe and
# rsync in exactly the same way. It is a property of copying bytes across
# libcs, not of ZFS.
#
# WHERE THIS RUNS
#
# On gandalf, in the GLOBAL zone, as a user who can pfexec. It pushes to the
# target over ssh. Running it from a third host would force the stream through
# two network hops.
#
# ORDER OF OPERATIONS
#
#   ./migrate-to-linux.sh preflight     # verify both ends, change nothing
#   ./migrate-to-linux.sh pilot         # prove a stream receives, seconds
#   ./migrate-to-linux.sh base          # full send, master stays up (hours)
#   ./migrate-to-linux.sh sync          # incremental, repeat freely (minutes)
#   ./migrate-to-linux.sh status        # how far behind is the target?
#   ./migrate-to-linux.sh cutover       # THE ONLY DOWNTIME. stops the master.
#   ./migrate-to-linux.sh amcheck       # prove which indexes actually broke
#   ./migrate-to-linux.sh reindex       # rebuild them (resumable)
#
# `sync` is safe to run from cron between `base` and `cutover`. Intermediate
# snapshots do NOT need to be crash-consistent -- they are overwritten by the
# final one -- which is why the pgdata/pgwal split that has bitten zrepl here
# before is harmless for everything except the cutover snapshot, and that one
# is taken with Postgres already cleanly shut down.
#
# MEASURED ON THIS PAIR (2026-08-30), for sizing:
#
#   pgdata          1.73 TiB on disk (2224 GB logical, lz4 1.27x)
#   churn           ~35 GB of incremental stream per 15 min (~40 MB/s)
#   ssh aes128-gcm  497 MB/s   <- default cipher managed only 255 MB/s
#   ssh chacha20    277 MB/s
#   end-to-end      94-288 MB/s, measured over four 40s samples
#
# Read those last two lines together. The SSH cipher is worth ~2x and is the
# single best knob here -- do not drop SSH_CIPHER without re-measuring. But the
# end-to-end rate swung 3x across identical back-to-back runs, because the
# source pool is serving a live write-heavy master at the same time. That
# variance dominates everything else, mbuffer included: a send-side mbuffer
# measured *slower* than none (235 vs 288 MB/s) on one pair of runs, which is
# noise, not a result. mbuffer is left enabled because its real value is on the
# RECEIVE side -- zfs recv stops reading during each txg commit -- and that
# cannot be measured until the target exists. It costs nothing if it does not
# help.
#
# The number that actually matters for planning: churn is ~40 MB/s and the
# floor of the measured transfer range is ~94 MB/s. That is only ~2.4x of
# headroom at the bad end, so incrementals converge, but not by a huge margin.
# Run `base` during a quiet window and watch `status`: if the pending delta is
# not shrinking between syncs, the pool is too busy and you should stop and
# reschedule rather than push on.
#
# Base send duration is therefore genuinely uncertain: 1.73 TiB at 94 MB/s is
# ~5.4 h, at 288 MB/s ~1.8 h. Budget overnight.
#
# ENV (defaults in brackets):
#   DST_HOST            REQUIRED. ssh destination, e.g. root@10.9.8.7
#   DST_SUDO            [sudo]  set empty when connecting as root
#   DST_POOL            [rpool]
#   DST_PGDATA_DS       [$DST_POOL/pgdata]
#   DST_WAL_DS          [$DST_POOL/pgwal]
#   DST_PGDATA_MNT      [/var/lib/postgresql/18]   NixOS dataDir for pg 18
#   DST_WAL_MNT         [/var/lib/postgresql/wal]
#   DST_PG_USER         [postgres]
#   SSH_CIPHER          [aes128-gcm@openssh.com]
#   USE_MBUFFER         [auto]  auto|yes|no
#   MBUFFER_SIZE        [1G]
#   SNAP_PREFIX         [hoppermig]  deliberately NOT `zrepl_`, so zrepl's
#                       pruner will never destroy our incremental base
#   HEX_COLS            [sha256,parent_sha256]  proven collation-stable here
#   REINDEX_JOBS        [4]
#   DRY_RUN             [] set to 1 to print commands instead of running them

set -eu

DST_HOST="${DST_HOST:-}"
DST_SUDO="${DST_SUDO-sudo}"
DST_POOL="${DST_POOL:-rpool}"
DST_PGDATA_DS="${DST_PGDATA_DS:-$DST_POOL/pgdata}"
DST_WAL_DS="${DST_WAL_DS:-$DST_POOL/pgwal}"
DST_PGDATA_MNT="${DST_PGDATA_MNT:-/var/lib/postgresql/18}"
DST_WAL_MNT="${DST_WAL_MNT:-/var/lib/postgresql/wal}"
DST_PG_USER="${DST_PG_USER:-postgres}"

SRC_PGDATA_DS="${SRC_PGDATA_DS:-rpool/zones/postgres/pgdata}"
SRC_WAL_DS="${SRC_WAL_DS:-ssd/pgwal}"
SRC_ZONE="${SRC_ZONE:-postgres}"
SRC_SMF="${SRC_SMF:-pkgsrc/postgresql}"
SRC_PGDATA_IN_ZONE="${SRC_PGDATA_IN_ZONE:-/var/pgsql/data}"
SRC_DB="${SRC_DB:-hopper}"

SSH_CIPHER="${SSH_CIPHER:-aes128-gcm@openssh.com}"
USE_MBUFFER="${USE_MBUFFER:-auto}"
MBUFFER_SIZE="${MBUFFER_SIZE:-1G}"
SNAP_PREFIX="${SNAP_PREFIX:-hoppermig}"
HEX_COLS="${HEX_COLS:-sha256,parent_sha256}"
REINDEX_JOBS="${REINDEX_JOBS:-4}"
DRY_RUN="${DRY_RUN:-}"

STATE_DIR="${STATE_DIR:-/var/tmp/hopper-migrate}"

die() { printf 'migrate: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

run() {
	# Every caller passes one already-composed command string, so eval it as a
	# string: the dry-run print and the executed command are then the same text.
	if [ -n "$DRY_RUN" ]; then printf '  [dry-run] %s\n' "$*"; else eval "$*"; fi
}

# pfexec only when we are not already root; keeps this usable in both cases.
if [ "$(id -u)" -eq 0 ]; then PRIV=""; else PRIV="pfexec"; fi

# ServerAlive* matters on a multi-hour send: without it a silently dropped
# link leaves both ends blocked forever instead of failing so `sync` can
# resume from the receive_resume_token.
SSH="ssh -c $SSH_CIPHER -o Compression=no -o ConnectTimeout=15 -o ServerAliveInterval=60 -o ServerAliveCountMax=10"

need_dst() { [ -n "$DST_HOST" ] || die "DST_HOST is required (e.g. DST_HOST=root@10.9.8.7)"; }

dst() { $SSH "$DST_HOST" "$DST_SUDO $*"; }

# Run a shell command on the target as the postgres user. Works whether we
# log in as root (DST_SUDO empty) or via sudo.
dst_pgcmd() { $SSH "$DST_HOST" "$DST_SUDO su -s /bin/sh -c '$*' $DST_PG_USER"; }

# Feed SQL on stdin to psql on the target as the postgres user. Passing SQL
# through stdin rather than -c avoids a third level of shell quoting.
dst_psql() { $SSH "$DST_HOST" "$DST_SUDO su -s /bin/sh -c 'psql -d $SRC_DB -v ON_ERROR_STOP=1 $*' $DST_PG_USER"; }

# --- transport ------------------------------------------------------------
#
# mbuffer earns its place on BOTH ends, for different reasons. On the send
# side zfs send stalls while it walks metadata; on the receive side zfs recv
# stops reading entirely during each txg commit (every ~5s). Without a buffer
# either stall propagates through the whole pipeline and idles the link. The
# buffer is not about raw speed, it is about keeping the link busy through
# those stalls.
mbuf_local() {
	case "$USE_MBUFFER" in
	no) cat_passthrough ;;
	*) if command -v mbuffer >/dev/null 2>&1; then
		printf 'mbuffer -q -s 128k -m %s' "$MBUFFER_SIZE"
	   else printf 'cat'; fi ;;
	esac
}
cat_passthrough() { printf 'cat'; }

mbuf_remote() {
	case "$USE_MBUFFER" in
	no) printf 'cat' ;;
	*) if $SSH "$DST_HOST" 'command -v mbuffer' >/dev/null 2>&1; then
		printf 'mbuffer -q -s 128k -m %s' "$MBUFFER_SIZE"
	   else printf 'cat'; fi ;;
	esac
}

RECV_PROPS_PGDATA="${RECV_PROPS_PGDATA:--o recordsize=8K -o logbias=throughput -o primarycache=metadata}"
RECV_PROPS_WAL="${RECV_PROPS_WAL:--o recordsize=128K -o logbias=latency -o primarycache=all}"

snapname() { printf '%s_%s' "$SNAP_PREFIX" "$(date -u +%Y%m%dT%H%M%SZ)"; }

# Latest snapshot of $1 carrying our prefix (the only ones we may use as an
# incremental base -- zrepl's own snapshots can be pruned mid-migration).
last_snap() {
	$PRIV zfs list -t snapshot -H -o name -s creation -r "$1" 2>/dev/null \
		| grep "@${SNAP_PREFIX}_" | tail -1 || true
}

# Latest snapshot the TARGET actually holds, so we resume from truth rather
# than from what the source thinks it sent.
last_snap_dst() {
	dst "zfs list -t snapshot -H -o name -s creation -r $1" 2>/dev/null \
		| grep "@${SNAP_PREFIX}_" | tail -1 || true
}

resume_token() {
	dst "zfs get -H -o value receive_resume_token $1" 2>/dev/null || printf -
}

# send_one <src_ds> <dst_ds> <snap> [base_snap]
send_one() {
	so_src="$1"; so_dst="$2"; so_snap="$3"; so_base="${4:-}"; so_props="${5:-}"
	so_lb="$(mbuf_local)"; so_rb="$(mbuf_remote)"

	so_tok="$(resume_token "$so_dst")"
	if [ -n "$so_tok" ] && [ "$so_tok" != "-" ]; then
		say "resuming interrupted receive of $so_dst"
		run "$PRIV zfs send -Lec -t '$so_tok' | $so_lb | $SSH '$DST_HOST' \"$DST_SUDO sh -c '$so_rb | zfs recv -s -u $so_dst'\""
		return
	fi

	if [ -n "$so_base" ]; then
		say "incremental $so_base -> @$so_snap"
		so_sendargs="-Lec -i '$so_base' '$so_src@$so_snap'"
		so_recvargs="-s -u -F $so_dst"
	else
		say "full send $so_src@$so_snap -> $DST_HOST:$so_dst"
		so_sendargs="-Lec '$so_src@$so_snap'"
		# Properties are set here rather than sent with -p: the source's
		# mountpoints are illumos zone paths and its primarycache=metadata is
		# tuning for OmniOS ARC vs a 64 GB shared_buffers. recordsize=8K must
		# match Postgres' block size or every 8 KB write becomes a 128 KB
		# read-modify-write.
		so_recvargs="-s -u -o mountpoint=none -o canmount=noauto -o atime=off ${so_props:-$RECV_PROPS_PGDATA} $so_dst"
	fi
	run "$PRIV zfs send $so_sendargs | $so_lb | $SSH '$DST_HOST' \"$DST_SUDO sh -c '$so_rb | zfs recv $so_recvargs'\""
}

check_src_space() {
	cs_free=$($PRIV zfs list -Hp -o available "$SRC_PGDATA_DS" 2>/dev/null || echo 0)
	cs_gb=$((cs_free / 1073741824))
	printf '  rpool free: %s GiB\n' "$cs_gb"
	if [ "$cs_gb" -lt 300 ]; then
		warn "rpool free is under 300 GiB. Held migration snapshots pin freed"
		warn "blocks at roughly 40 GB/h. Either cut over soon or abort with"
		warn "'cleanup' -- do not let this migration run for days."
	fi
}

cmd_preflight() {
	need_dst
	say "source"
	$PRIV zfs list -o name,used,refer,recordsize,compression "$SRC_PGDATA_DS" "$SRC_WAL_DS"
	printf '  zone %s: ' "$SRC_ZONE"; zoneadm -z "$SRC_ZONE" list -p 2>/dev/null | cut -d: -f3 || echo "?"
	printf '  postgres: '; $PRIV zlogin "$SRC_ZONE" "postgres --version" 2>/dev/null || echo "?"
	printf '  cluster state: '
	$PRIV zlogin "$SRC_ZONE" "pg_controldata $SRC_PGDATA_IN_ZONE" 2>/dev/null \
		| awk -F: '/cluster state/{print $2}' || echo "?"
	printf '  uid/gid in zone: '; $PRIV zlogin "$SRC_ZONE" "id postgres" 2>/dev/null || echo "?"

	say "target"
	dst "zfs --version 2>/dev/null | head -1" || die "no zfs on $DST_HOST -- the target must be a ZFS host"
	dst "zpool list $DST_POOL" || die "pool $DST_POOL missing on $DST_HOST"
	printf '  postgres: '; dst_pgcmd "postgres --version" 2>/dev/null || echo "NOT FOUND"
	printf '  mbuffer: '; ($SSH "$DST_HOST" 'command -v mbuffer' 2>/dev/null) || echo "MISSING (will fall back to cat)"

	# A restored cluster whose datcollate cannot be resolved will not start.
	printf '  en_US.UTF-8 locale: '
	if dst "locale -a" 2>/dev/null | grep -i en_US | grep -qi utf; then echo "present"
	else warn "MISSING -- add i18n.supportedLocales = [ \"en_US.UTF-8/UTF-8\" ]; the cluster will NOT start without it"; fi

	# shared_preload_libraries=pg_stat_statements means a missing .so is not a
	# degraded query plan, it is a postmaster that refuses to start.
	# On NixOS pg_config lives in the package's `dev` output and is not on
	# PATH, so fall back to deriving pkglibdir from the postgres binary.
	pf_libdir=$(dst_pgcmd "pg_config --pkglibdir" 2>/dev/null || true)
	if [ -z "$pf_libdir" ]; then
		pf_pgbin=$(dst "readlink -f /run/current-system/sw/bin/postgres" 2>/dev/null || true)
		[ -n "$pf_pgbin" ] && pf_libdir="$(dirname "$(dirname "$pf_pgbin")")/lib"
	fi
	printf '  extension libs (%s):\n' "${pf_libdir:-unknown}"
	for pf_ext in pg_stat_statements pg_trgm amcheck; do
		printf '    %s: ' "$pf_ext"
		if [ -n "$pf_libdir" ] && dst "test -e $pf_libdir/$pf_ext.so" 2>/dev/null; then echo ok
		else echo "MISSING -- install the postgresql contrib/extension outputs"; fi
	done

	# shared_buffers is copied verbatim from the old master; the target must be
	# able to map it.
	pf_sb=$($PRIV zlogin "$SRC_ZONE" "psql -U postgres -tAc 'show shared_buffers'" 2>/dev/null || echo "?")
	pf_ram=$(dst "awk '/MemTotal/{print \$2}' /proc/meminfo" 2>/dev/null || echo 0)
	printf '  shared_buffers on source: %s ; target RAM: %s GiB\n' "$pf_sb" "$((pf_ram / 1048576))"
	[ "$pf_ram" -gt 0 ] && [ "$((pf_ram / 1048576))" -lt 96 ] && \
		warn "target RAM looks small for an 80 GiB shared_buffers; lower it in the NixOS config"

	# Clock skew is not cosmetic here: this fleet has already had a publisher
	# running 150.7 s behind, which silently corrupted every replication-lag
	# reading. On the new master it also means wrong created_at/analyzed_at on
	# every row hopper writes.
	say "clock skew"
	pf_t0=$(date -u +%s)
	pf_t1=$(dst "date -u +%s" 2>/dev/null || echo 0)
	pf_skew=$((pf_t1 - pf_t0)); [ "$pf_skew" -lt 0 ] && pf_skew=$((-pf_skew))
	printf '  target vs here: %ss\n' "$pf_skew"
	if [ "$pf_t1" -eq 0 ]; then warn "could not read the target clock"
	elif [ "$pf_skew" -gt 2 ]; then
		warn "target clock is ${pf_skew}s off. Enable chrony BEFORE cutover:"
		warn "  services.chrony.enable = true;"
	fi

	say "capacity"
	src_used=$($PRIV zfs list -Hp -o used "$SRC_PGDATA_DS")
	dst_avail=$(dst "zfs list -Hp -o available $DST_POOL")
	printf '  pgdata used   : %s GiB\n' "$((src_used / 1073741824))"
	printf '  target free   : %s GiB\n' "$((dst_avail / 1073741824))"
	[ "$dst_avail" -gt "$src_used" ] || warn "target has less free space than pgdata uses"
	printf '  NOTE: reindex needs transient headroom on top of that.\n'

	say "locale (the reason indexes must be rebuilt)"
	$PRIV zlogin "$SRC_ZONE" "psql -U postgres -tAc \"select datname||' '||datcollate||' provider='||datlocprovider from pg_database where datname='$SRC_DB'\"" 2>/dev/null || true
	printf '  target must be able to resolve that locale, or the cluster will\n'
	printf '  not start. On NixOS: i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];\n'
}

# Prove an illumos-generated stream is receivable on the target BEFORE
# committing hours to the base send. Costs a few seconds and a few KB.
cmd_pilot() {
	need_dst
	pl_src="${SRC_PILOT_DS:-rpool/${SNAP_PREFIX}_pilot}"
	pl_dst="$DST_POOL/${SNAP_PREFIX}_pilot"
	say "creating pilot dataset $pl_src"
	$PRIV zfs destroy -r "$pl_src" 2>/dev/null || true
	dst "zfs destroy -r $pl_dst" 2>/dev/null || true
	$PRIV zfs create -o mountpoint=/"$pl_src" "$pl_src"
	# Random, incompressible, so lz4 + `zfs send -c` are actually exercised.
	$PRIV dd if=/dev/urandom of="/$pl_src/probe.bin" bs=1M count=32 2>/dev/null
	pl_sum=$($PRIV digest -a sha256 "/$pl_src/probe.bin" 2>/dev/null || $PRIV sha256sum "/$pl_src/probe.bin" | awk '{print $1}')
	printf '  source sha256: %s\n' "$pl_sum"
	$PRIV zfs snapshot "$pl_src@pilot"
	say "sending pilot"
	send_one "$pl_src" "$pl_dst" "pilot"
	dst "zfs set mountpoint=/$pl_dst $pl_dst"
	dst "zfs set canmount=on $pl_dst"
	dst "zfs mount $pl_dst" 2>/dev/null || true
	pl_rsum=$(dst "sha256sum /$pl_dst/probe.bin" | awk '{print $1}')
	printf '  target sha256: %s\n' "$pl_rsum"
	say "cleaning up pilot datasets"
	$PRIV zfs destroy -r "$pl_src" 2>/dev/null || true
	dst "zfs destroy -r $pl_dst" 2>/dev/null || true
	[ "$pl_sum" = "$pl_rsum" ] || die "PILOT FAILED: checksums differ. Do not start the base send."
	say "PILOT OK -- illumos streams receive correctly on this target"
}

cmd_base() {
	need_dst
	base_s="$(snapname)"
	# pgdata ONLY. ssd/pgwal is deliberately NOT snapshotted here: a held
	# snapshot on that dataset pins recycled WAL segments, which is exactly
	# what filled the 928 GB `ssd` pool and PANICked this master on
	# 2026-08-29. WAL is only needed at cutover, and by then Postgres is
	# cleanly shut down, so it ships as a single full send at the end.
	say "snapshotting $SRC_PGDATA_DS as @$base_s"
	run "$PRIV zfs snapshot '$SRC_PGDATA_DS@$base_s'"
	# Hold it: this is the incremental base for everything that follows and
	# must survive any pruner, ours or zrepl's.
	run "$PRIV zfs hold $SNAP_PREFIX '$SRC_PGDATA_DS@$base_s'"
	dst "zfs list $DST_PGDATA_DS" >/dev/null 2>&1 && die "$DST_PGDATA_DS already exists on target; use 'sync', or destroy it first"
	send_one "$SRC_PGDATA_DS" "$DST_PGDATA_DS" "$base_s"
	say "base complete. Run 'sync' periodically until cutover."
	check_src_space
}

cmd_sync() {
	need_dst
	sy_base_pg="$(last_snap_dst "$DST_PGDATA_DS")"
	[ -n "$sy_base_pg" ] || die "target holds no $SNAP_PREFIX snapshot -- run 'base' first"
	sy_base_pg="${sy_base_pg##*@}"
	sy_new="$(snapname)"
	say "snapshotting @$sy_new (incremental base @$sy_base_pg)"
	run "$PRIV zfs snapshot '$SRC_PGDATA_DS@$sy_new'"
	run "$PRIV zfs hold $SNAP_PREFIX '$SRC_PGDATA_DS@$sy_new'"
	send_one "$SRC_PGDATA_DS" "$DST_PGDATA_DS" "$sy_new" "$SRC_PGDATA_DS@$sy_base_pg"
	# The target now has the new snapshot, so the previous base is dead weight
	# pinning freed blocks on the source. Release and destroy it, or a long
	# migration slowly eats rpool.
	run "$PRIV zfs release $SNAP_PREFIX '$SRC_PGDATA_DS@$sy_base_pg' 2>/dev/null || true"
	run "$PRIV zfs destroy '$SRC_PGDATA_DS@$sy_base_pg' 2>/dev/null || true"
	say "sync complete"
	check_src_space
}

cmd_status() {
	need_dst
	st_dst="$(last_snap_dst "$DST_PGDATA_DS")"
	st_src="$(last_snap "$SRC_PGDATA_DS")"
	printf '  source latest : %s\n' "${st_src:-none}"
	printf '  target latest : %s\n' "${st_dst:-none}"
	if [ -n "$st_dst" ]; then
		printf '  pending stream since target snapshot: '
		# Destroy any stale probe first, or a leftover one silently makes
		# the reported delta wrong.
		$PRIV zfs destroy "$SRC_PGDATA_DS@${SNAP_PREFIX}probe" 2>/dev/null || true
		$PRIV zfs snapshot "$SRC_PGDATA_DS@${SNAP_PREFIX}probe" 2>/dev/null || true
		$PRIV zfs send -nvPLec -i "$SRC_PGDATA_DS@${st_dst##*@}" "$SRC_PGDATA_DS@${SNAP_PREFIX}probe" 2>&1 \
			| awk '/^size/{printf "%.1f GiB\n", $2/1073741824}' || echo "?"
		$PRIV zfs destroy "$SRC_PGDATA_DS@${SNAP_PREFIX}probe" 2>/dev/null || true
	fi
}

cmd_cutover() {
	need_dst
	co_base="$(last_snap_dst "$DST_PGDATA_DS")"
	[ -n "$co_base" ] || die "target holds no $SNAP_PREFIX snapshot -- run 'base' and 'sync' first"
	co_base="${co_base##*@}"

	# A stop-method timeout is a SIGKILL, which means an UNCLEAN shutdown,
	# which means the gate below refuses to send and the master is left
	# needing crash recovery. Measured here: stop/timeout_seconds=1860, and a
	# 64 GB end-of-recovery checkpoint on this box has taken 27.7 min.
	co_stopto=$($PRIV zlogin "$SRC_ZONE" "svccfg -s $SRC_SMF listprop stop/timeout_seconds" </dev/null 2>/dev/null | awk '{print $3}')
	printf '  SMF stop/timeout_seconds: %s\n' "${co_stopto:-unknown}"
	if [ -n "${co_stopto:-}" ] && [ "$co_stopto" -lt 3600 ] 2>/dev/null; then
		warn "stop timeout is ${co_stopto}s. If the shutdown checkpoint runs long,"
		warn "SMF will SIGKILL postgres and you get an unclean shutdown."
		warn "Raise it first:  svccfg -s $SRC_SMF setprop stop/timeout_seconds = count: 7200"
		warn "                 svcadm refresh $SRC_SMF"
	fi

	warn "This STOPS the hopper master. It stays stopped."
	# CUTOVER_CONFIRM=YES skips the prompt. This exists because the
	# confirmation CANNOT safely be piped in: zlogin(1) reads stdin, so an
	# `echo YES |` is swallowed by the zlogin calls that run before the prompt
	# and `read` then sees EOF. Every zlogin below is redirected from
	# /dev/null for the same reason.
	if [ "${CUTOVER_CONFIRM:-}" = "YES" ]; then
		say "CUTOVER_CONFIRM=YES -- proceeding without prompting"
	else
		printf 'Type YES to continue: '
		read -r co_ans
		[ "$co_ans" = "YES" ] || die "aborted"
	fi

	if [ -n "${PRE_STOP_CMD:-}" ]; then
		say "running PRE_STOP_CMD (quiesce writers)"
		run "$PRE_STOP_CMD"
	else
		warn "PRE_STOP_CMD unset -- stop the hopper API and workers yourself, or"
		warn "clients will take errors instead of a clean drain."
	fi

	# Drain dirty buffers BEFORE asking SMF to stop. Without this the entire
	# 80 GB shared_buffers dirty set is flushed inside the shutdown checkpoint,
	# on the stop method's clock. Two checkpoints: the first does the bulk, the
	# second mops up what the first missed.
	say "pre-draining with CHECKPOINT (keeps the shutdown checkpoint short)"
	run "$PRIV zlogin '$SRC_ZONE' \"psql -U postgres -d $SRC_DB -c 'CHECKPOINT'\" </dev/null"
	run "$PRIV zlogin '$SRC_ZONE' \"psql -U postgres -d $SRC_DB -c 'CHECKPOINT'\""

	say "stopping postgres in zone $SRC_ZONE"
	run "$PRIV zlogin '$SRC_ZONE' 'svcadm disable -s $SRC_SMF' </dev/null"

	# THE critical gate. A cleanly shut down cluster needs no WAL replay, which
	# is the whole reason the pgdata/pgwal split is safe here -- the two
	# datasets cannot be snapshotted atomically, so they must not need to be
	# mutually consistent.
	say "verifying clean shutdown"
	co_state=$($PRIV zlogin "$SRC_ZONE" "pg_controldata $SRC_PGDATA_IN_ZONE" </dev/null | awk -F: '/cluster state/{gsub(/^ +/,"",$2); print $2}')
	printf '  cluster state: %s\n' "$co_state"
	[ "$co_state" = "shut down" ] || die "cluster state is '$co_state', expected 'shut down' -- NOT sending. Investigate before retrying."

	co_final="${SNAP_PREFIX}_final_$(date -u +%Y%m%dT%H%M%SZ)"
	say "final snapshots @$co_final (consistent: postgres is down)"
	run "$PRIV zfs snapshot '$SRC_PGDATA_DS@$co_final'"
	run "$PRIV zfs snapshot '$SRC_WAL_DS@$co_final'"

	send_one "$SRC_PGDATA_DS" "$DST_PGDATA_DS" "$co_final" "$SRC_PGDATA_DS@$co_base"

	# WAL ships once, here, as a full send. It is small (a few GB to a few tens
	# of GB) and this avoids holding a snapshot on the `ssd` pool for the whole
	# migration. See the comment in cmd_base.
	if dst "zfs list $DST_WAL_DS" >/dev/null 2>&1; then
		warn "$DST_WAL_DS already exists on the target (previous cutover attempt?)."
		warn "Destroy it there and re-run: zfs destroy -r $DST_WAL_DS"
		die "refusing to overwrite it automatically"
	fi
	say "sending WAL dataset ($(($($PRIV zfs list -Hp -o refer "$SRC_WAL_DS") / 1073741824)) GiB)"
	send_one "$SRC_WAL_DS" "$DST_WAL_DS" "$co_final" "" "$RECV_PROPS_WAL"

	cmd_finish
	say "CUTOVER DATA COMPLETE."
	printf '\nNext, in order:\n'
	printf '  1. %s amcheck    # find which indexes the libc change broke\n' "$0"
	printf '  2. %s reindex    # rebuild them -- this is the long pole\n' "$0"
	printf '  3. start postgres on %s and smoke-test\n' "$DST_HOST"
	printf '  4. repoint galadriel'"'"'s subscription conninfo at the new master\n'
	printf '     (the replication slot came across in the physical copy, so it\n'
	printf '      resumes rather than rebuilding)\n\n'
	warn "Do NOT re-enable $SRC_SMF on gandalf. Two masters sharing one"
	warn "timeline and system identifier is a split brain you cannot merge."
}

# Target-side fixups. Idempotent, so it is safe to re-run.
cmd_finish() {
	need_dst
	say "mounting and fixing up target"
	run "dst 'zfs set mountpoint=$DST_PGDATA_MNT $DST_PGDATA_DS'"
	run "dst 'zfs set mountpoint=$DST_WAL_MNT $DST_WAL_DS'"
	run "dst 'zfs set canmount=on $DST_PGDATA_DS'"
	run "dst 'zfs set canmount=on $DST_WAL_DS'"
	run "dst 'zfs mount $DST_PGDATA_DS 2>/dev/null || true'"
	run "dst 'zfs mount $DST_WAL_DS 2>/dev/null || true'"

	# The source uid is 907 (illumos zone); NixOS' postgres is typically 71.
	# ZFS ships numeric ids, so without this the cluster refuses to start.
	say "chown to $DST_PG_USER and tighten mode"
	run "dst 'chown -R $DST_PG_USER:$DST_PG_USER $DST_PGDATA_MNT $DST_WAL_MNT'"
	run "dst 'chmod 0700 $DST_PGDATA_MNT'"

	# pgdata/pg_wal arrives as a symlink to the illumos path /var/pgsql/wal/pg_wal.
	say "repointing pg_wal symlink at $DST_WAL_MNT/pg_wal"
	run "dst 'ln -sfn $DST_WAL_MNT/pg_wal $DST_PGDATA_MNT/pg_wal'"
	run "dst 'chown -h $DST_PG_USER:$DST_PG_USER $DST_PGDATA_MNT/pg_wal'"

	# postgresql.auto.conf (ALTER SYSTEM) rides along in the data directory and
	# OVERRIDES whatever NixOS generates. Left alone it can silently reimpose
	# illumos-specific or stale values on the new master.
	say "checking postgresql.auto.conf (it overrides the NixOS-generated config)"
	dst "test -s $DST_PGDATA_MNT/postgresql.auto.conf" 2>/dev/null && {
		dst "grep -v '^#' $DST_PGDATA_MNT/postgresql.auto.conf | grep ." || true
		dst "cp -n $DST_PGDATA_MNT/postgresql.auto.conf $DST_PGDATA_MNT/postgresql.auto.conf.premigrate" || true
		warn "review the settings above; a backup is at postgresql.auto.conf.premigrate"
	}

	say "target pg_controldata"
	dst_pgcmd "pg_controldata $DST_PGDATA_MNT" 2>/dev/null | head -6 || \
		warn "could not run pg_controldata on the target; check the postgres package is installed"
}

# Emit the REINDEX plan. Run against the SOURCE while it is still up (default)
# or against the target. Deliberately conservative: any index carrying a
# collatable attribute is included unless every such attribute is in HEX_COLS.
cmd_reindex_sql() {
	rs_hex=$(printf "%s" "$HEX_COLS" | sed "s/,/','/g")
	cat <<SQL_EOF
WITH ix AS (
  SELECT i.indexrelid, c.relname AS idx, n.nspname AS sch,
         pg_relation_size(i.indexrelid) AS sz,
         array_agg(DISTINCT a.attname::text)
           FILTER (WHERE t.typcollation <> 0) AS textcols
  FROM pg_index i
  JOIN pg_class c ON c.oid = i.indexrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_am am ON am.oid = c.relam
  JOIN pg_attribute a ON a.attrelid = i.indexrelid AND a.attnum > 0
  JOIN pg_type t ON t.oid = a.atttypid
  WHERE n.nspname NOT IN ('pg_catalog','information_schema')
  GROUP BY i.indexrelid, c.relname, n.nspname
)
SELECT format('REINDEX (VERBOSE) INDEX %I.%I;  -- %s', sch, idx, pg_size_pretty(sz))
FROM ix
WHERE textcols IS NOT NULL
  AND NOT (textcols <@ ARRAY['$rs_hex'])
ORDER BY sz DESC;
SQL_EOF
}

cmd_reindex() {
	need_dst
	mkdir -p "$STATE_DIR"
	rx_plan="$STATE_DIR/reindex.sql"
	rx_done="$STATE_DIR/reindex.done"
	touch "$rx_done"
	if [ ! -s "$rx_plan" ]; then
		say "generating reindex plan from the target"
		cmd_reindex_sql | dst_psql -tA > "$rx_plan"
	fi
	say "$(grep -c . "$rx_plan" || true) indexes in plan; $(grep -c . "$rx_done" || true) already done"

	# Catalog text indexes (pg_replication_origin.roname, pg_parameter_acl,
	# pg_seclabel...) are collation-affected too, and cheap.
	say "REINDEX SYSTEM first (small, but genuinely affected)"
	printf 'REINDEX SYSTEM %s;\n' "$SRC_DB" | dst_psql -q

	# Read from the file, NOT through a pipe: a `while` on the right of a pipe
	# runs in a subshell, so a failure there could not stop this script and the
	# run would report success having silently skipped the rest.
	while IFS= read -r rx_stmt; do
		[ -n "$rx_stmt" ] || continue
		rx_name=$(printf '%s' "$rx_stmt" | sed 's/^ *REINDEX (VERBOSE) INDEX //; s/;.*//; s/ *$//')
		if grep -qxF "$rx_name" "$rx_done"; then
			say "skip $rx_name (already done)"
			continue
		fi
		say "reindex $rx_name"
		if [ -n "$DRY_RUN" ]; then printf '  [dry-run] %s\n' "$rx_stmt"; continue; fi
		if printf '%s\n' "$rx_stmt" | dst_psql -q; then
			printf '%s\n' "$rx_name" >> "$rx_done"
		else
			die "reindex failed on $rx_name (rerun to resume; finished work is in $rx_done)"
		fi
	done < "$rx_plan"
	say "reindex complete -- now re-run 'amcheck' to confirm nothing is left broken"
}

# The authority. bt_index_check validates btree ordering against the CURRENT
# collation, so it reports exactly the indexes the libc change invalidated --
# no heuristic, no guessing about which columns are hex.
cmd_amcheck() {
	need_dst
	say "running bt_index_check across all btrees on the target"
	printf 'CREATE EXTENSION IF NOT EXISTS amcheck;
' | dst_psql -q
	dst_psql -tA <<'AM_EOF'
DO $$
DECLARE r record; bad int := 0; tot int := 0;
BEGIN
  FOR r IN
    SELECT c.oid::regclass AS idx
    FROM pg_class c JOIN pg_am am ON am.oid=c.relam
    JOIN pg_index i ON i.indexrelid=c.oid
    WHERE am.amname='btree' AND c.relpersistence='p' AND i.indisvalid
    ORDER BY pg_relation_size(c.oid) DESC
  LOOP
    tot := tot + 1;
    BEGIN
      PERFORM bt_index_check(index => r.idx);
    EXCEPTION WHEN others THEN
      bad := bad + 1;
      RAISE NOTICE 'BROKEN % : %', r.idx, SQLERRM;
    END;
  END LOOP;
  RAISE NOTICE 'checked % indexes, % broken', tot, bad;
END $$;
AM_EOF
	say "every index reported BROKEN above must be reindexed before opening to traffic"
}

# Non-default settings from the old master, as a starting point for
# services.postgresql.settings. Not a drop-in: paths and anything illumos- or
# zone-specific need judgement.
cmd_nixos_settings() {
	say "non-default settings on the current master"
	$PRIV zlogin "$SRC_ZONE" "psql -U postgres -tAF'|' -c \"
	  SELECT name, current_setting(name), '' FROM pg_settings
	  WHERE source NOT IN ('default','override','client')
	    AND name NOT LIKE 'lc_%' ORDER BY name\"" 2>/dev/null \
	| awk -F'|' '
	     BEGIN{ print "  services.postgresql.settings = {" }
	     {
	       u=$3; v=$2; if (u!="") v=v u;
	       key=$1;
	       # A bare dotted key is a NESTED ATTRSET in Nix, not a GUC name.
	       if (key ~ /\./) key="\"" key "\"";
	       if ($1=="dynamic_shared_memory_type")
	         printf "    # %s = \"%s\";  # illumos value, use \"posix\" on Linux\n", key, v;
	       else if ($1 ~ /^(log_directory|log_filename|data_directory|hba_file|ident_file|config_file|unix_socket_directories|stats_temp_directory)$/)
	         printf "    # %s = \"%s\";  # zone-specific path, review\n", key, v;
	       else
	         printf "    %s = \"%s\";\n", key, v;
	     }
	     END{ print "  };" }'
	printf '\n  Commented-out lines are deliberate: illumos or zone-specific,\n'
	printf '  and wrong on the target as-is.\n'
	printf '\n  Also required on the target:\n'
	printf '    i18n.supportedLocales = [ "en_US.UTF-8/UTF-8" ];\n'
	printf '    services.postgresql.package = pkgs.postgresql_18;\n'
	printf '    services.postgresql.dataDir = "%s";\n' "$DST_PGDATA_MNT"
	printf '    boot.supportedFilesystems = [ "zfs" ]; networking.hostId = "...";\n'
	printf '\n  And make sure NixOS does not initdb over the restored dataDir:\n'
	printf '  leave ensureDatabases/ensureUsers/initialScript unset on first boot.\n'
}

cmd_cleanup() {
	say "releasing holds and destroying $SNAP_PREFIX snapshots on the SOURCE"
	for cl_ds in "$SRC_PGDATA_DS" "$SRC_WAL_DS"; do
		$PRIV zfs list -t snapshot -H -o name -r "$cl_ds" 2>/dev/null \
			| grep "@${SNAP_PREFIX}" | while IFS= read -r cl_s; do
			run "$PRIV zfs release $SNAP_PREFIX '$cl_s' 2>/dev/null || true"
			run "$PRIV zfs destroy '$cl_s'"
		done
	done
}

usage() {
	sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//; $d'
	exit 1
}

case "${1:-}" in
preflight)      cmd_preflight ;;
pilot)          cmd_pilot ;;
base)           cmd_base ;;
sync)           cmd_sync ;;
status)         cmd_status ;;
cutover)        cmd_cutover ;;
finish)         cmd_finish ;;
reindex-sql)    cmd_reindex_sql ;;
reindex)        cmd_reindex ;;
amcheck)        cmd_amcheck ;;
nixos-settings) cmd_nixos_settings ;;
cleanup)        cmd_cleanup ;;
*)              usage ;;
esac
