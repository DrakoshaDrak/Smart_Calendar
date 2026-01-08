#!/usr/bin/env bash
set -euo pipefail
BASE_URL=${BASE_URL:-http://127.0.0.1:8080}
CURL="curl -sS --show-error"

post() {
  local url=$1; local data=$2; local token=${3:-}
  if [ -n "$token" ]; then
    curl -sS -w "\n%{http_code}" -H "Content-Type: application/json" -H "Authorization: Bearer $token" -d "$data" "$BASE_URL$url"
  else
    curl -sS -w "\n%{http_code}" -H "Content-Type: application/json" -d "$data" "$BASE_URL$url"
  fi
}

extract_id() {
  local body=$1
  echo "$body" | sed -n 's/.*"id"\s*:\s*"\([^"]*\)".*/\1/p'
}

echo "BASE_URL=$BASE_URL"

OWNER_EMAIL=owner@example.com
OWNER_PW=passw0rd
B_EMAIL=b@example.com
B_PW=passw0rd
C_EMAIL=c@example.com
C_PW=passw0rd

echo "1) register owner (idempotent)"
res=$(post /auth/register "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PW\"}") || true
echo "$res"

echo "2) login owner"
login_res=$(post /auth/login "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$OWNER_PW\"}")
echo "$login_res"
owner_token=$(echo "$login_res" | sed -n '1p' | sed -n 's/.*"token"\s*:\s*"\([^"]*\)".*/\1/p')
if [ -z "$owner_token" ]; then
  echo "failed to get owner token; full response:"; echo "$login_res"; exit 1
fi

echo "3) register B and C"
post /auth/register "{\"email\":\"$B_EMAIL\",\"password\":\"$B_PW\"}" || true
post /auth/register "{\"email\":\"$C_EMAIL\",\"password\":\"$C_PW\"}" || true

echo "4) owner creates calendar"
cal_res=$(post /calendars "{\"title\":\"RBAC Test\"}" "$owner_token")
echo "$cal_res"
calid=$(extract_id "$(echo "$cal_res" | sed -n '1p')")
if [ -z "$calid" ]; then echo "failed to get calendar id"; exit 1; fi

echo "5) owner shares B as moderator (role=1)"
share_res=$(post /calendars/$calid/share "{\"email\":\"$B_EMAIL\",\"role\":1}" "$owner_token")
echo "$share_res"

echo "6) login B"
login_b=$(post /auth/login "{\"email\":\"$B_EMAIL\",\"password\":\"$B_PW\"}")
echo "$login_b"
b_token=$(echo "$login_b" | sed -n '1p' | sed -n 's/.*"token"\s*:\s*"\([^"]*\)".*/\1/p')
if [ -z "$b_token" ]; then echo "failed to get b token"; exit 1; fi

echo "7) B attempts to add C as moderator (should be 403)"
res_b_promote=$(post /calendars/$calid/share "{\"email\":\"$C_EMAIL\",\"role\":1}" "$b_token" )
echo "$res_b_promote"

echo "8) B adds C as reader (role=0)"
res_b_add_reader=$(post /calendars/$calid/share "{\"email\":\"$C_EMAIL\",\"role\":0}" "$b_token")
echo "$res_b_add_reader"

echo "9) B attempts to promote existing C to moderator (should be 403)"
res_b_promote2=$(post /calendars/$calid/share "{\"email\":\"$C_EMAIL\",\"role\":1}" "$b_token")
echo "$res_b_promote2"

echo "10) owner promotes C to moderator"
res_owner_promote=$(post /calendars/$calid/share "{\"email\":\"$C_EMAIL\",\"role\":1}" "$owner_token")
echo "$res_owner_promote"

echo "Done."
