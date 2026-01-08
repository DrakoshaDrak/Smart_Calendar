#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/CalendarServer/build"
CTEST_DIR="$BUILD_DIR"

WITH_HTTP=0
WITH_DB=0
WITH_IT=0
for arg in "$@"; do
  case "$arg" in
    --with-http) WITH_HTTP=1 ;;
    --with-db) WITH_DB=1 ;;
    --with-it) WITH_IT=1 ;;
    --help|-h) echo "Usage: $0 [--with-http] [--with-db] [--with-it]"; exit 0 ;;
    *) echo "Unknown arg: $arg"; exit 2 ;;
  esac
done

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

function heading { echo -e "\n===== $1 ====="; }
function ok { echo -e "${GREEN}OK${RESET} - $1"; }
function fail { echo -e "${RED}FAIL${RESET} - $1"; }
function skip { echo -e "${YELLOW}SKIP${RESET} - $1"; }

if [ "$(pwd)" != "$ROOT_DIR" ]; then
  echo "Please run this script from the repository root: $ROOT_DIR"
  exit 2
fi

mkdir -p "$BUILD_DIR"

echo "Configuring with CMake (Release)..."
cmake -S "$ROOT_DIR/CalendarServer" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release

echo "Building tests... (this may build the project)"
cmake --build "$BUILD_DIR" -j 2

TOTAL_RUN=0
TOTAL_SKIP=0

function count_matches {
  local run_regex="$1"; shift
  local exclude_regex="${1-}"; shift || true
  local out
  if [ -n "$exclude_regex" ]; then
    out=$(ctest -N -R "$run_regex" -E "$exclude_regex" --test-dir "$CTEST_DIR" 2>/dev/null || true)
  else
    out=$(ctest -N -R "$run_regex" --test-dir "$CTEST_DIR" 2>/dev/null || true)
  fi
  printf "%s" "$out" | grep -c "Test #" || true
}

function run_group {
  local title="$1"; shift
  local run_regex="$1"; shift
  local exclude_regex="${1-}"; shift || true
  local should_run="${1-1}"; shift || true

  heading "$title"

  local count
  if [ -n "$exclude_regex" ]; then
    count=$(count_matches "$run_regex" "$exclude_regex")
  else
    count=$(count_matches "$run_regex")
  fi

  if [ "$should_run" -ne 1 ]; then
    skip "$title (disabled by flags)"
    TOTAL_SKIP=$((TOTAL_SKIP + count))
    return 0
  fi

  if [ "$count" -eq 0 ]; then
    skip "$title (no matching tests)"
    return 0
  fi

  local exclude_arg=( )
  if [ -n "$exclude_regex" ]; then
    exclude_arg=( -E "$exclude_regex" )
  fi

  echo "Running: ctest -V -R '$run_regex' ${exclude_arg[*]} --test-dir '$CTEST_DIR'"
  set +e
  if [ -n "$exclude_regex" ]; then
    ctest -V -R "$run_regex" -E "$exclude_regex" --test-dir "$CTEST_DIR"
  else
    ctest -V -R "$run_regex" --test-dir "$CTEST_DIR"
  fi
  local rc=$?
  set -e
  if [ $rc -eq 0 ]; then
    ok "$title"
    TOTAL_RUN=$((TOTAL_RUN + count))
  else
    fail "$title"
    echo "ctest failed with exit code $rc"
    exit $rc
  fi
}

UNIT_RUN_REGEX="_unit$|dbpool_unit_|json_|auth_unit|cache_keys_unit|config_unit|router_unit|metrics_unit|logging_unit|redis_client_unit"
UNIT_EXCLUDE_REGEX="^(overrides_unit$|exdates_unit$)"
run_group "UNIT TESTS" "$UNIT_RUN_REGEX" "$UNIT_EXCLUDE_REGEX" 1

DB_RUN_REGEX="^(db_smoke$|recurrence_unit$|overrides_unit$|exdates_unit$)"
if [ $WITH_DB -eq 1 ]; then
  run_group "DB / LOGIC SMOKE" "$DB_RUN_REGEX" "" 1
else
  run_group "DB / LOGIC SMOKE" "$DB_RUN_REGEX" "" 0
fi

heading "HTTP TESTS"
HTTP_RUN_REGEX="^(http_smoke$|rbac_http_smoke$|members_remove_http_smoke$)"
if [ $WITH_HTTP -eq 1 ]; then
  run_group "HTTP SMOKE" "$HTTP_RUN_REGEX" "" 1
else
  run_group "HTTP SMOKE" "$HTTP_RUN_REGEX" "" 0
fi

heading "INTEGRATION SCENARIOS"
IT_RUN_REGEX="^scenario_"
function wait_http_ready() {
  local base_url="${BASE_URL:-http://127.0.0.1:8080}"
  base_url="${base_url%/}"
  local url="$base_url/health"
  local timeout_ms=10000
  local interval_ms=250
  local elapsed=0

  if command -v curl >/dev/null 2>&1; then
    while [ $elapsed -lt $timeout_ms ]; do
      http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true)
      if [ "$http_code" != "" ] && [ "${http_code:0:1}" = "2" ]; then
        return 0
      fi
      sleep 0.25
      elapsed=$((elapsed + interval_ms))
    done
    echo "Timed out waiting for HTTP server at $url (timeout ${timeout_ms}ms)" >&2
    return 2
  elif command -v wget >/dev/null 2>&1; then
    while [ $elapsed -lt $timeout_ms ]; do
      if wget -q -T 2 -O /dev/null "$url" 2>/dev/null; then
        return 0
      fi
      sleep 0.25
      elapsed=$((elapsed + interval_ms))
    done
    echo "Timed out waiting for HTTP server at $url (timeout ${timeout_ms}ms)" >&2
    return 2
  else
    echo "Neither curl nor wget is available for readiness check; please install one." >&2
    return 2
  fi
}

if [ $WITH_IT -eq 1 ]; then
  echo "Checking HTTP server readiness for integration scenarios..."
  if ! wait_http_ready; then
    echo "HTTP server did not become ready within timeout; aborting integration scenarios." >&2
    exit 2
  fi
  run_group "INTEGRATION SCENARIOS" "$IT_RUN_REGEX" "" 1
else
  run_group "INTEGRATION SCENARIOS" "$IT_RUN_REGEX" "" 0
fi

heading "SUMMARY"
echo "Tests run: $TOTAL_RUN"
echo "Tests skipped: $TOTAL_SKIP"
if [ $TOTAL_RUN -eq 0 ]; then
  echo "No tests were executed. Use --with-http/--with-db/--with-it to enable optional groups." 
fi

exit 0
