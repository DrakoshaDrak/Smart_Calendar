#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
BUILD_DIR="${ROOT_DIR}/build"
if [ "$#" -ge 1 ]; then
  PORT_ARG="$1"
else
  PORT_ARG=8080
fi
export PORT=${PORT_ARG}
"${BUILD_DIR}/calendar_server"
