#!/usr/bin/env bash
set -eu

BASE_URL=${BASE_URL:-http://127.0.0.1:8080}
REDIS_CLI=${REDIS_CLI:-redis-cli}
REDIS_PASS=${REDIS_PASS:-}
if [ -n "$REDIS_PASS" ]; then
	REDIS_CLI_CMD="$REDIS_CLI -a $REDIS_PASS"
else
	REDIS_CLI_CMD="$REDIS_CLI"
fi

echo_stderr() { echo "$@" >&2; }

email="test+ci@example.com"
password="password123"

echo_stderr "registering user (ignore errors if exists)..."
curl -s -X POST -H "Content-Type: application/json" -d "{\"email\":\"$email\",\"password\":\"$password\"}" "$BASE_URL/auth/register" >/dev/null || true

echo_stderr "logging in..."
login=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"email\":\"$email\",\"password\":\"$password\"}" "$BASE_URL/auth/login")
if command -v jq >/dev/null 2>&1; then
	token=$(echo "$login" | jq -r '.token // empty')
else
	token=$(echo "$login" | sed -n 's/.*"token":"\([^\"]*\)".*/\1/p')
fi
if [ -z "$token" ]; then echo_stderr "login failed: $login"; exit 1; fi

echo_stderr "creating calendar (idempotent name)..."
cal=$(curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d '{"title":"CI Calendar"}' "$BASE_URL/calendars")
if command -v jq >/dev/null 2>&1; then
	calid=$(echo "$cal" | jq -r '.id // empty')
else
	calid=$(echo "$cal" | sed -n 's/.*"id":"\([^\"]*\)".*/\1/p')
fi
if [ -z "$calid" ]; then
	echo_stderr "create calendar returned no id, falling back to listing calendars"
	list=$(curl -s -H "Authorization: Bearer $token" "$BASE_URL/calendars")
	if command -v jq >/dev/null 2>&1; then
		calid=$(echo "$list" | jq -r '.items[] | select(.title=="CI Calendar") | .id' | head -n1)
	else
		calid=$(echo "$list" | sed -n 's/.*"id":"\([^\"]*\)","title":"CI Calendar".*/\1/p')
	fi
	if [ -z "$calid" ]; then echo_stderr "could not determine calendar id, output: $cal"; exit 1; fi
fi

from="2026-01-01T00:00:00Z"
to="2026-02-01T00:00:00Z"
echo_stderr "first GET (expect miss)"

res1=$(curl -s -i -H "Authorization: Bearer $token" "$BASE_URL/calendars/$calid/events?from=$from&to=$to")
xcache_key=$(echo "$res1" | sed -n 's/X-Cache-Key: \(.*\)/\1/p' | tr -d '\r')
xcache_hdr=$(echo "$res1" | sed -n 's/X-Cache: \(.*\)/\1/p' | tr -d '\r')

if [ -z "$xcache_key" ]; then echo_stderr "no X-Cache-Key found in response headers"; exit 1; fi

echo_stderr "checking redis key: $xcache_key"
ttl=$($REDIS_CLI_CMD TTL "$xcache_key" 2>/dev/null || echo -1)
getval=$($REDIS_CLI_CMD GET "$xcache_key" 2>/dev/null || true)

echo "STEP1_TTL=$ttl"
if [ "$ttl" -le 0 ]; then echo_stderr "bad TTL: $ttl"; exit 1; fi

echo_stderr "second GET (expect hit)"
res2=$(curl -s -i -H "Authorization: Bearer $token" "$BASE_URL/calendars/$calid/events?from=$from&to=$to")
xcache2=$(echo "$res2" | sed -n 's/X-Cache: \(.*\)/\1/p' | tr -d '\r')
echo "STEP2_XCACHE=$xcache2"

echo_stderr "creating event in Jan 2026 to trigger invalidate"
event_body='{"title":"CI Event","start_ts":"2026-01-15T10:00:00Z","end_ts":"2026-01-15T11:00:00Z"}'
ev=$(curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d "$event_body" "$BASE_URL/calendars/$calid/events")
echo_stderr "event create: $ev"

echo_stderr "waiting for invalidate (up to 300ms)"
STEP3_VAL="not_nil"
start_ms=$(date +%s%3N)
end_ms=$((start_ms + 300))
while true; do
	now=$(date +%s%3N)
	if [ "$now" -gt "$end_ms" ]; then break; fi
	v=$($REDIS_CLI_CMD GET "$xcache_key" 2>/dev/null || true)
	if [ -z "$v" ]; then STEP3_VAL="nil"; break; fi
	sleep 0.05
done

echo "STEP3_AFTER_WRITE_REDIS_GET=$STEP3_VAL"

echo_stderr "final GET to repopulate"
res3=$(curl -s -i -H "Authorization: Bearer $token" "$BASE_URL/calendars/$calid/events?from=$from&to=$to")
get_after=$($REDIS_CLI_CMD GET "$xcache_key" 2>/dev/null || true)
echo_stderr "redis now has: ${get_after:+present}${get_after:+' (len:'$(echo -n "$get_after" | wc -c)')'}"

exit 0