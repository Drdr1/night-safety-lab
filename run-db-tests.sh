#!/usr/bin/env bash
# Applies the Supabase shim + all migrations to a fresh database and runs the SQL tests.
# Usage: PGHOST=... PGPORT=... PGUSER=postgres ./run-db-tests.sh
set -euo pipefail
DB=${TEST_DB:-night_safety_test}
psql -v ON_ERROR_STOP=1 -q -d postgres -c "drop database if exists $DB" -c "create database $DB"
for f in supabase/tests/00_supabase_shim.sql supabase/migrations/*.sql; do
  psql -v ON_ERROR_STOP=1 -q -d "$DB" -f "$f" 2>&1 | grep -v 'already exists, skipping' || true
done
psql -v ON_ERROR_STOP=1 -q -t -d "$DB" -f supabase/tests/10_security_and_flows.sql 2>&1 | sed -e 's/^psql:[^ ]* //' -e '/^ *$/d' -e '/^SET$/d;/^RESET$/d;/^DO$/d'
