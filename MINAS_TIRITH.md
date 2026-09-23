# minas-tirith — hopper PostgreSQL master

Build log and rationale for `minas-tirith` (10.9.8.4), the NixOS host that
replaces the OmniOS `postgres` zone on gandalf (10.9.8.3) as the hopper
PostgreSQL master.

**Status as of 2026-08-31: MIGRATION COMPLETE. minas-tirith (10.9.8.4) is the
hopper PostgreSQL master.** gandalf's `pkgsrc/postgresql` is `disabled` and must
stay that way. Cutover was lossless: both clusters reported
`Database cluster state: shut down` at the identical checkpoint
`40FB/A580D338`, system identifier 7637507770445611061, and the drain freed 25
idle backends with **0 transactions rolled back**.

Post-cutover, in order:
1. `amcheck`: 146 indexes checked, **30 BROKEN** (~362 GB), 51 min. Every failure
   an ordering-invariant violation -- the libc collation change, exactly as
   predicted. Hex-only indexes (143 GB + 132 GB) **passed**, confirming the
   pre-migration hex analysis and avoiding 275 GB of needless work.
2. `REINDEX`: 2 parallel streams. The 311 GB constraint took **42:02**; the
   other 29 finished alongside it. 0 errors, 0 invalid indexes. The rebuilt
   constraint came back at **221 GB** -- 90 GB of bloat dropped.
3. Re-`amcheck` of those 30: **0 still broken**, 17:39.
4. PostgreSQL enabled on boot (migration guards removed, `RequiresMountsFor`
   kept permanently).
5. galadriel's subscription repointed to `host=10.9.8.4` and re-enabled --
   it had auto-disabled via `disable_on_error` when the publisher vanished.
   It resumed from the cutover LSN rather than rebuilding.

Total downtime cutover -> verified-correct: ~2.5 h, at the optimistic end of
the 2.5-5 h estimate.

Migration tooling: `scripts/master/migrate-to-linux.sh`.

---

## 1. Hardware (measured, not assumed)

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X3D2, 16C/32T, 192 MiB L3 across 2 CCDs, 1 NUMA node |
| RAM | 249 GiB usable, **no swap** |
| OS | NixOS 26.05 (Yarara), kernel 6.18.48, ZFS 2.4.4 |
| `nvme0n1` | INTEL SSDPED1D280GA (Optane P4800X) 260.8 GiB, PCIe **Gen3** (8 GT/s), 512B physical |
| `nvme1n1` | WD_BLACK SN850X 4 TB, Gen4 — p1 `/boot`, p2 `/` (ext4, 384 G), p3 3.3 T free |
| `nvme2n1` / `nvme3n1` | KIOXIA KCD8XRUG7T68 7.68 TB each, Gen4, **4096B physical** |

The Kioxia pair reporting `physical_block_size=4096` behind a 512e front is why
`ashift=12` is mandatory — and it cannot be changed after pool creation.

## 2. Design decisions

### Mirror, not RAIDZ
RAIDZ turns every 8 K random read into a full-stripe read. `sample_locations`
has 714 M rows; the access pattern is random. Striped mirrors only.

### The Optane is split: 16 GiB SLOG + 244.8 GiB L2ARC
Considered and rejected:

- **SLOG alone** — a SLOG only ever holds a few seconds of in-flight sync
  writes (`zfs_txg_timeout` × a few txgs; ~225 MB at hopper's ~15 MB/s WAL).
  Dedicating 280 GB to it wastes 99% of the device.
- **`special` vdev** — at `recordsize=8K` a 2–4 TB dataset carries ~35–64 GB of
  L1 indirect metadata, which *fits in 249 GiB of RAM*, so ARC already serves it
  faster than Optane could. A single unmirrored `special` vdev is also
  **fatal to the whole pool** if it dies.

Splitting gets both jobs. Honest ranking of the two halves:

- **SLOG: predictable.** Commit latency is a serial per-transaction cost and
  Optane's ~10 µs QD1 latency is unbeatable there. This is what makes
  `synchronous_commit=on` affordable — gandalf runs it `off`.
- **L2ARC: speculative.** The Kioxia mirror actually has *more* aggregate
  random-read IOPS than the Optane (~1 M each, reads served from both, Gen4)
  and more bandwidth (Optane is Gen3-limited to ~3.2 GB/s). Optane wins only on
  per-operation latency. `l2arc_noprefetch=1` (default) keeps sequential scans
  out of it, which is what makes it worth trying.

If `arcstat -f time,l2hits,l2miss,l2hit%,l2size 10` shows single-digit
`l2hit%` after a week under real load, `zpool remove tank <cache-dev>` and take
the space back. Removal is instant and safe.

### `scratch` pool on the unmirrored SN850X partition
Sort spill is disposable, so unmirrored and `sync=disabled` are both fine, and
it moves temp I/O off the mirror. This matters most during the migration's
384 GB reindex, which sorts 714 M rows.

### recordsize 8K, not 16K
8 K matches the PostgreSQL block size, so no read-modify-write. 16 K would
halve metadata and compress better, but hopper is write-heavy (~40 MB/s of
block churn) and would pay RMW on scattered single-page writes. gandalf has run
8 K with a 1.27× lz4 ratio.

## 3. Commands executed

Partition the Optane (`sgdisk`/`parted` are not installed; `sfdisk` is):

```sh
sudo sfdisk /dev/nvme0n1 <<EOF
label: gpt
size=16G, name=slog
name=l2arc
EOF
```

Create the pools:

```sh
sudo zpool create -f -o ashift=12 -o autotrim=on \
  -O compression=lz4 -O atime=off -O xattr=sa -O acltype=posixacl \
  -O canmount=off -O mountpoint=none \
  tank mirror \
    /dev/disk/by-id/nvme-KIOXIA_KCD8XRUG7T68_53U0A00VTM9J \
    /dev/disk/by-id/nvme-KIOXIA_KCD8XRUG7T68_Y4C0A0GFTM9J

sudo zpool add tank log   /dev/disk/by-id/nvme-INTEL_SSDPED1D280GA_PHMB747200PK280CGN-part1
sudo zpool add tank cache /dev/disk/by-id/nvme-INTEL_SSDPED1D280GA_PHMB747200PK280CGN-part2

sudo zpool create -f -o ashift=12 -o autotrim=on \
  -O compression=lz4 -O atime=off -O sync=disabled -O recordsize=128K \
  -O mountpoint=/scratch \
  scratch /dev/disk/by-id/nvme-WD_BLACK_SN850X_HS_4000GB_25377E800565-part3

sudo zfs create scratch/pgtemp
sudo chown postgres:postgres /scratch/pgtemp && sudo chmod 700 /scratch/pgtemp
```

**`tank/pgdata` and `tank/pgwal` are deliberately NOT created here** —
`zfs recv` creates them during the migration and applies per-dataset properties
(pgdata: `recordsize=8K, logbias=throughput`; pgwal: `recordsize=128K,
logbias=latency`, which is what routes WAL fsyncs through the SLOG).

Clear the mountpoint of the cluster NixOS had already initdb'd there
(stock and empty — only `postgres`/`template0`/`template1`, ~40 MB):

```sh
sudo systemctl stop postgresql postgresql.target
sudo mv /var/lib/postgresql/18 /var/lib/postgresql/18.orphan-initdb-20260830
```

Generate a migration key on gandalf (its `t` user had no keypair):

```sh
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -C "t@gandalf hopper-migration"
```

Scope the subnet to /24 (it was /8, so the host treated all of 10.0.0.0/8 as
link-local). This is **stateful** config -- it lives in
`/etc/NetworkManager/system-connections/10G.nmconnection`, not in
`configuration.nix`:

```sh
sudo nmcli con mod "10G" ipv4.addresses 10.9.8.4/24
# `nmcli dev reapply` CANNOT change addressing and `con up` alone was a no-op;
# a full down/up is required. Run detached so an SSH blip cannot half-apply it,
# and use an absolute path -- systemd-run's PATH does not include nmcli.
NMCLI=$(readlink -f $(command -v nmcli))
sudo systemd-run --collect --unit=netfix2 --on-active=2 \
  /bin/sh -c "$NMCLI con down 10G; $NMCLI con up 10G"
```

Result: `inet 10.9.8.4/24 brd 10.9.8.255`, link route `10.9.8.0/24`, default
via 10.9.8.1 intact. Verified reachable from galadriel and gandalf, with DNS
and internet working.

Apply ZFS module parameters at runtime (`boot.extraModprobeConfig` otherwise
waits for a reboot):

```sh
for kv in zfs_arc_max=137438953472 zfs_arc_min=68719476736 \
          l2arc_write_max=33554432 l2arc_write_boost=67108864 \
          l2arc_mfuonly=1 zfs_vdev_async_read_max_active=16 \
          zfs_vdev_sync_read_max_active=32; do
  echo "${kv#*=}" | sudo tee /sys/module/zfs/parameters/"${kv%%=*}"
done
```

## 4. Configuration changes

### New: `/etc/nixos/hopper-db.nix`

Holds only *tuning*; `configuration.nix` continues to own *what is enabled*.
Contents and the reasoning for each block are in the file's own comments.
Summary:

| Setting | Why |
|---|---|
| `security.sudo.wheelNeedsPassword = false` | The migration script drives everything over SSH. **Declared here because a manual `/etc/sudoers` edit does not survive `nixos-rebuild switch`** — see §6. |
| `users.users.t.openssh.authorizedKeys.keys` | gandalf pushes the ZFS stream over SSH. Declared, not dropped in `~/.ssh`, so it survives rebuilds and is auditable. **Remove after migration.** |
| `zfs_arc_max=128 GiB`, `zfs_arc_min=64 GiB` | Caps ARC so it cannot fight a 64 GiB `shared_buffers` for the same RAM — the failure that broke gandalf. |
| `l2arc_mfuonly=1` | 9.5 TB of gandalf's 13.6 TB lifetime reads were one-pass sequential scans. MFU-only stops them flushing the Optane. |
| `l2arc_write_max=32 MB/s` | Deliberately modest: the SLOG shares the same physical Optane, and commit latency beats cache warm-up speed. |
| `hugepages=33500` | 33500 × 2 MiB backs a 64 GiB `shared_buffers`. galadriel ran `huge_pages=try` with `nr_hugepages=0` and silently got none for months. |
| `vm.swappiness=1` | A distro default of 150 once pushed 46 GB of galadriel's PostgreSQL into swap. |
| `cpuFreqGovernor = "performance"` | Consistent latency over power saving. |
| `boot.zfs.extraPools = [ "tank" "scratch" ]` | **Without this the pools do not come back after a reboot.** NixOS only generates `zfs-import-<pool>.service` for pools referenced in `fileSystems` or listed here; ours are neither, since ZFS mounts them from their own `mountpoint` property. |
| `networking.firewall.extraCommands` | Scopes 5432 to `10.9.8.0/24`. Uses `iptables -I` (not `-A`) because the `nixos-fw` chain **ends** in `-j nixos-fw-log-refuse`, so an appended rule would sit after the refuse and never match. |
| `systemd.targets.postgresql.wantedBy = mkForce []` | Stops PostgreSQL starting — and initdb'ing into the mountpoint — before the ZFS dataset is mounted and restored. See §6. |

### Changed: `/etc/nixos/configuration.nix`

Backup at `/etc/nixos/configuration.nix.bak-pre-hopper-20260830`.

```diff
       ./hardware-configuration.nix
+      ./hopper-db.nix
     ];
-  systemd.services.postgresql.wantedBy = lib.mkForce [ ];
-  systemd.services.postgresql.unitConfig.RequiresMountsFor = [ "/var/lib/postgresql/18" ];
-  networking.firewall.allowedTCPPorts = [ 22 5432 ];
+  networking.firewall.allowedTCPPorts = [ 22 ];
```

Those two lines moved into `hopper-db.nix` (and were superseded — see §6).

## 4b. PostgreSQL configuration (staged before data lands)

`services.postgresql.settings` and `.authentication` are now in `hopper-db.nix`.
Three findings drove the shape of it:

**NixOS points `hba_file` into the Nix store.** The `pg_hba.conf` restored from
gandalf is therefore **ignored entirely**. Without porting the rules, nothing
would connect after cutover -- including galadriel's logical replication. They
are ported via `services.postgresql.authentication` with `lib.mkAfter` (which,
in practice, emits them *before* the NixOS defaults; harmless here since ours
are `host` rules for 10.0.0.0/8 and the defaults cover `local` + loopback).
Kept at 10.0.0.0/8 to match gandalf exactly -- the firewall is the tighter
boundary at 10.9.8.0/24.

**`initdb` is safe on a restored cluster.** The pre-start script only runs
`rm -f *.conf` and `initdb` when `PG_VERSION` is *absent*, so a restored
dataDir is left alone. `postgresql.conf` is unconditionally symlinked to the
store version, so the NixOS config wins over gandalf's -- as intended.
`postgresql.auto.conf` still overrides both; `finish` backs it up.

**`huge_pages = on` needed 34000 pages, not 33500.** Measured by starting a
real postmaster: the shared segment is 70,418,169,856 bytes =
**33,578 huge pages**, because WAL buffers, lock tables and per-worker shared
state sit alongside `shared_buffers`. At 33500 it failed with
`could not map anonymous shared memory`. Verified at 34000:
`huge_pages_status=on`, `shared_memory_size_in_huge_pages=33578`,
`io_method=io_uring`. **`on` rather than `try` is deliberate** -- a shortfall
must fail loudly, not silently fall back to 4 K pages the way galadriel did.

ZFS tunables added after review: `zfs_dirty_data_max` 4 GiB -> **16 GiB** (the
default is a hard 4 GiB cap regardless of RAM, and ZFS begins throttling
writes at 60% of it -- far too small for a master churning ~40 MB/s behind
64 GiB of shared_buffers), and `zfs_vdev_async_write_max_active` 10 -> 16.

## 5. Verification

`migrate-to-linux.sh preflight` and `pilot`, run from gandalf:

```
DST_HOST=t@10.9.8.4 DST_POOL=tank /tmp/mig.sh preflight
DST_HOST=t@10.9.8.4 DST_POOL=tank /tmp/mig.sh pilot
```

- ZFS 2.4.4 on target; `tank` 6.98 T vs 2465 GiB of pgdata — fits.
- `pg_stat_statements.so`, `pg_trgm.so`, `amcheck.so` all present.
- `en_US.UTF-8` resolves; a throwaway `initdb` produced
  `datcollate=en_US.UTF-8, datlocprovider=c, UTF8` — identical to gandalf.
- **`io_method=io_uring` verified working**; `pg_settings.enumvals` is
  `{sync,worker,io_uring}`. nixpkgs does build with liburing, despite
  `pg_config --configure` not being inspectable (that binary lives in the
  package's `dev` output and is not on `PATH`).
- Clock skew gandalf↔minas-tirith: **0 s** (chrony).
- **`pilot`: SHA-256 matched end to end** — illumos ZFS streams receive
  correctly here, through mbuffer on both ends and the `aes128-gcm` cipher.

## 6. Problems hit

**`nixos-rebuild switch` reverted passwordless sudo.** It had been enabled by
hand; NixOS regenerates `/etc/sudoers` from the config on every switch, so the
change was silently lost mid-setup and locked out every remaining step. Now
declared in `hopper-db.nix`. *Lesson: on NixOS, make the config change before
the rebuild, never after.*

**`wantedBy = mkForce []` on `postgresql.service` does not stop PostgreSQL.**
The real chain is `multi-user.target → postgresql.target → (Requires)
postgresql.service`, so the target dragged the service up on the next rebuild
and `postgresql-setup.service` initdb'd a fresh stock cluster straight into
`/var/lib/postgresql/18` — the mountpoint the restore needs. Fixed by cutting
the chain at `systemd.targets.postgresql.wantedBy`. Verified: PostgreSQL stays
`inactive` and the mountpoint stays clean across a rebuild.

**The ZFS pools did not auto-import after the first reboot.** `zfs-import.target`
was enabled and looked healthy, but no `zfs-import-tank.service` existed at all
and `cachefile` was unset on both pools -- NixOS never generated import units
because neither pool appears in `fileSystems` (ZFS mounts them itself) and
`boot.zfs.extraPools` was unset. Fixed with `boot.zfs.extraPools`. Verified not
by assumption but by exporting both pools and restarting the generated units;
the resulting chain is `zfs-import-{tank,scratch}.service` (`Before=` and
`RequiredBy=`) -> `zfs-import.target` -> `zfs-mount.service` (`After=`).
*This is the single best argument for rebooting before starting the base send:
a multi-hour transfer into pools that vanish on the next boot is worse than
useless.*

**Two bugs found in `migrate-to-linux.sh` by running it here:**
- `nixos-settings` concatenated `pg_settings.setting || unit`, but `setting` is
  a *count* of `unit`s — `shared_buffers` (8388608 × 8kB) rendered as the
  nonsense `"83886088kB"` instead of `64GB`. Now uses `current_setting(name)`.
- The locale check used GNU `grep`'s `\?`, but that grep runs on **illumos**,
  where BRE has no `\?` — so it always reported the locale missing.

## 7. Outstanding

1. **One more reboot to confirm.** The first reboot (2026-08-30) validated huge
   pages (33500), `zfs_arc_max`, the /24 address, the scoped firewall rule and
   PostgreSQL staying `inactive` -- but exposed that the pools did not import.
   That is now fixed and tested by export/re-import, though a clean boot is the
   only complete proof.
2. `/var/lib/postgresql/18.orphan-initdb-20260830` (~40 MB) can be deleted.
3. PostgreSQL `settings` are not yet written -- generate with
   `migrate-to-linux.sh nixos-settings`, then layer the target-specific tuning
   (`io_method=io_uring`, `wal_init_zero=off`, `wal_recycle=off`,
   `synchronous_commit=on`, `full_page_writes=off`, `temp_tablespaces=pgtemp`).
   Note gandalf's real `shared_buffers` is **64GB**.
4. Create the temp tablespace after the restore:
   `CREATE TABLESPACE pgtemp LOCATION '/scratch/pgtemp';`
5. After cutover + reindex: remove the `mkForce` guards so PostgreSQL starts on
   boot, and remove gandalf's authorized key from `hopper-db.nix`.
6. The NM profile is the one piece of **stateful** configuration here. Consider
   moving it to `networking.networkmanager.ensureProfiles` for reproducibility.

### Post-reboot checks

```sh
cat /proc/sys/vm/nr_hugepages                 # expect 33500
zpool status tank scratch                     # both ONLINE, imported
systemctl is-active postgresql                # expect: inactive
ip -4 addr show enp12s0 | grep inet           # expect 10.9.8.4/24
sudo iptables -S nixos-fw | grep 5432         # expect -s 10.9.8.0/24
grep -E '^c_max' /proc/spl/kstat/zfs/arcstats # expect 137438953472
```

## 7b. Open decisions (speed vs. risk) -- your call

| | |
|---|---|
| **`mitigations=off`** | **APPROVED and applied 2026-08-30** (pending reboot). A *security* tradeoff, not a reliability one: dedicated DB host, private LAN, no untrusted code. Revisit if this host ever runs anything else. Before/after measured -- see below. |
| **Swap** | **APPROVED and applied 2026-08-30**: 32 GiB swapfile at `/var/lib/swapfile`, `swappiness=1`, live now. A backstop, *not* a memory tier -- any sustained usage is a bug to investigate. See below. |
| **`vm.min_free_kbytes`** | **Applied 2026-08-30**: 66 MiB -> 2 GiB. Live now, no reboot needed. |
| **Memory is NOT ECC** | `dmidecode`: `Error Correction Type: None`. ZFS checksums protect data at rest but cannot catch corruption that happens in RAM before the checksum is computed. Nothing to do on this platform -- stated so it is a known, accepted risk rather than a surprise. |

### Why swap, and why it is on ext4

`shared_buffers` sits on huge pages and therefore **cannot be swapped at all**,
so the failure that hurt galadriel (46 GB of PostgreSQL paged out at
`swappiness=150`) is structurally impossible here. Swap only ever covers
backend `work_mem`, idle connections, and acting as a pressure valve.

The real reason to have it: ARC cannot always give memory back fast enough
under a burst, and an OOM-killed *backend* makes the postmaster restart the
entire cluster -- crash recovery on 2-4 TB. Note `PG_OOM_ADJUST_*` is not set,
so every backend inherits `OOMScoreAdjust=-900`; with nothing else meaningful
running on this box the OOM killer would still pick PostgreSQL, since -900 is
not immunity (only -1000 is).

**`vm.min_free_kbytes` matters more than the swap does.** It was 66 MiB against
249 GiB of RAM. Raising it to 2 GiB gives the kernel reclaim headroom so
allocation bursts cannot outrun reclaim -- that is the actual OOM mechanism
swap is being asked to backstop.

**The swapfile is deliberately on ext4 (`/`), not on ZFS.** Swap on a ZFS file
or zvol can deadlock: ZFS must allocate memory to write pages out, and swapping
happens precisely when memory is exhausted. `scratch` would have been the
obvious-looking place and is the wrong one.

`vm.overcommit_memory` is deliberately left at 0. The classic PostgreSQL advice
of `2` is wrong on ZFS -- ARC is not counted in the overcommit calculation, so
strict mode produces spurious allocation failures.

### Mitigations before/after

Measured with `/tmp/bench.sh` (kept in this repo's history): a throwaway
cluster on `scratch`, `shared_buffers=8GB`, `fsync=off`, dataset small enough
to sit entirely in shared_buffers, then
`pgbench -S -M prepared -c 32 -j 32 -T 20` three times. Deliberately
CPU/syscall-bound, because that is what CPU mitigations actually cost.
The same parameters must be used on both sides of the reboot.

| | run 1 | run 2 | run 3 | mean |
|---|---|---|---|---|
| mitigations **ON** (before) | 2,620,961 | 2,576,446 | 2,583,115 | **2,593,507 tps** |
| mitigations **off** (after) | 2,707,475 | 2,741,365 | 2,675,835 | **2,708,225 tps** |

**+4.4%.** The two sets do not overlap (before max 2,620,961 < after min
2,675,835), so this is a real effect rather than run-to-run noise. Treat it as
an *upper* bound for the production workload: this benchmark is deliberately
CPU/syscall-bound with the whole dataset in shared_buffers, which is where
mitigations cost the most. Hopper's real query mix is far more I/O-bound and
will see less.

After the change all four report `Vulnerable`:
`vmscape`, `spec_store_bypass`, `spectre_v1`, `spec_rstack_overflow`.

Active mitigations before the change: `vmscape` (IBPB on VMEXIT),
`spec_store_bypass`, `spectre_v1`, `spec_rstack_overflow`.

## 7c. Settle by benchmark, once data is on the box

1. **`primarycache=all` + L2ARC vs `primarycache=metadata` + larger
   `shared_buffers`.** The single biggest open bet. Set at receive time via
   `RECV_PROPS_PGDATA`, so it is cheap to re-test.
2. **L2ARC's worth.** `arcstat -f time,l2hits,l2miss,l2hit%,l2size 10`; if
   `l2hit%` is single digits, `zpool remove tank <cache>` and reclaim it.
3. **`jit`** is `off` (the NixOS default). prism runs analytical queries that
   may benefit; needs `services.postgresql.enableJIT = true`.
4. **lz4 vs zstd-1** compression on pgdata.
5. **`io_uring` vs `worker`** for `io_method`.
6. **`zfs_dirty_data_max`** 16 GiB -- may want more.
7. **`shared_buffers` 64 GiB** -- inherited from gandalf, not derived from this
   box.

## 7d. Not yet done, needed before this is a production master

- **zrepl is installed but not configured.** This host will hold the only live
  copy of a 2-4 TB database. See [[zrepl-backup-topology]] concerns.
- **ZED is active but only logs.** No notification path wired to the fleet's
  host-mon -> Alertmanager -> ntfy chain, so a degraded mirror would be silent.

## 8. Rollback

Nothing here is destructive to gandalf. To undo the host entirely:

```sh
sudo zpool destroy tank
sudo zpool destroy scratch
sudo sfdisk --delete /dev/nvme0n1
sudo rm /etc/nixos/hopper-db.nix
sudo cp /etc/nixos/configuration.nix.bak-pre-hopper-20260830 /etc/nixos/configuration.nix
sudo nixos-rebuild switch
```

NixOS keeps the previous generations, so `nixos-rebuild switch --rollback` (or
the boot menu) reverts the configuration alone.
