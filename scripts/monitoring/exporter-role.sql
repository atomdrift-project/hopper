-- Least-privilege monitoring role for the Postgres metrics exporter
-- (Grafana Alloy's embedded postgres_exporter). Lives on the PUBLISHER
-- (hopper-db) and is the role Alloy connects as.
--
-- Why a separate role: the app role `hopper` is not superuser and not a member
-- of pg_monitor (verified 2026-06-27), so the per-peer lag columns of
-- pg_stat_replication / the *_stats views read back NULL for it. pg_monitor
-- unlocks those. Slot retained-WAL bytes are readable without it, but we want
-- the full picture and we do not want to widen the app role.
--
-- Run as a superuser on the publisher:
--   EXPORTER_PASSWORD=... psql -h hopper-db -U postgres -d hopper \
--     -v pw="$EXPORTER_PASSWORD" -f exporter-role.sql

\set ON_ERROR_STOP on

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hopper_exporter') THEN
    CREATE ROLE hopper_exporter LOGIN;
  END IF;
END
$$;

ALTER ROLE hopper_exporter WITH PASSWORD :'pw';
ALTER ROLE hopper_exporter CONNECTION LIMIT 5;   -- cap blast radius

-- pg_monitor is a predefined role (pg_read_all_stats + pg_read_all_settings +
-- pg_stat_scan_tables); membership is all the exporter needs. No table grants.
GRANT pg_monitor TO hopper_exporter;
GRANT CONNECT ON DATABASE hopper TO hopper_exporter;
