#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
MIGRATIONS_DIR="${ROOT_DIR}/migrations"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL env is required" >&2
  exit 2
fi

echo "Applying migrations from ${MIGRATIONS_DIR} to ${DATABASE_URL}"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz DEFAULT now())" || true

for f in $(ls "${MIGRATIONS_DIR}" | sort); do
  ver=$(echo "$f" | sed -E 's/^([0-9]+).*/\1/')
  if [ -z "$ver" ]; then
    echo "Skipping non-versioned file $f"
    continue
  fi
  already=$(psql "$DATABASE_URL" -tAc "SELECT 1 FROM schema_migrations WHERE version=${ver} LIMIT 1") || true
  if [ "$already" = "1" ]; then
    echo "Skipping $f (version ${ver} already applied)"
    continue
  fi
  echo "Applying $f (version ${ver})"
  if ! psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "${MIGRATIONS_DIR}/${f}" ; then
    echo "Failed to apply ${f}" >&2
    exit 1
  fi
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "INSERT INTO schema_migrations(version) VALUES(${ver}) ON CONFLICT DO NOTHING"
  echo "Applied ${f}"
done

echo "Migrations complete"
