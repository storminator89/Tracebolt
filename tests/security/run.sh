#!/usr/bin/env bash
# Run focused boundary regressions against an owned disposable local manager.
set -euo pipefail

cd "$(dirname "$0")/../.."
manager="${TRACEBOLT_MANAGER:-./bin/manager}"
if [[ ! -x "$manager" ]]; then
  printf 'Build the manager first: make build\n' >&2
  exit 1
fi

state=$(mktemp -d "${TMPDIR:-/tmp}/tracebolt-boundary.XXXXXXXX")
pid=''
managed_pid=''
cleanup() {
  if [[ -n "$managed_pid" ]]; then
    kill "$managed_pid" 2>/dev/null || true
    wait "$managed_pid" 2>/dev/null || true
  fi
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf -- "$state"
}
trap cleanup EXIT

# The server does not accept port zero; reserve a free loopback port, then
# verify our own process is alive before issuing any mutating test requests.
port=$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)
mkdir -p "$state/web/.git"
marker="Tracebolt boundary fixture ${state##*/}"
printf '%s\n' "$marker" > "$state/web/index.html"
printf 'synthetic dotfile trap\n' > "$state/web/.env"
printf 'synthetic hidden directory trap\n' > "$state/web/.git/config"
printf 'synthetic outside-root trap\n' > "$state/outside.txt"
ln -s "$state/outside.txt" "$state/web/escape.txt"

"$manager" --port "$port" --db "$state/state.db" --web "$state/web" > "$state/manager.log" 2>&1 &
pid=$!
ready=false
for attempt in {1..100}; do
  if ! kill -0 "$pid" 2>/dev/null; then
    printf 'Disposable manager failed to start.\n' >&2
    cat "$state/manager.log" >&2
    exit 1
  fi
  response=$(curl --silent --fail --connect-timeout 1 --max-time 2 "http://127.0.0.1:$port/" || true)
  if [[ "$response" == "$marker" ]]; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]] || ! kill -0 "$pid" 2>/dev/null; then
  printf 'Disposable manager did not become ready.\n' >&2
  exit 1
fi

python3 tests/security/run_boundary.py --base-url "http://127.0.0.1:$port" --allow-mutations
python3 tests/security/run_ai_boundary.py --base-url "http://127.0.0.1:$port" --allow-mutations

managed_port=$(python3 - <<'PORT'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PORT
)
"$manager" --managed-preview --port "$managed_port" --db "$state/managed.db" --web "$state/web" > "$state/managed.log" 2>&1 &
managed_pid=$!
managed_ready=false
for attempt in {1..100}; do
  if ! kill -0 "$managed_pid" 2>/dev/null; then
    printf 'Managed test process failed; runtime details withheld.\n' >&2
    exit 1
  fi
  response=$(curl --silent --fail --connect-timeout 1 --max-time 2 "http://127.0.0.1:$managed_port/" || true)
  if [[ "$response" == "$marker" ]]; then managed_ready=true; break; fi
  sleep 0.1
done
[[ "$managed_ready" == true ]] && kill -0 "$managed_pid" 2>/dev/null || exit 1
go build -buildvcs=false -trimpath -o "$state/dev-agent" ./cmd/dev-agent
if ! python3 tests/security/run_telemetry_boundary.py --base-url "http://127.0.0.1:$managed_port" --disabled-url "http://127.0.0.1:$port" --agent ./bin/agent --dev-agent "$state/dev-agent" > "$state/telemetry-tests.log" 2>&1; then
  printf 'FAIL: seven managed API boundary groups; runtime details withheld.\n' >&2
  exit 1
fi
printf 'PASS: seven managed API boundary groups; no runtime samples printed.\n'
kill "$managed_pid"
wait "$managed_pid"
managed_pid=''

kill "$pid"
wait "$pid"
pid=''
python3 - "$state/state.db" <<'PY'
import os
import sqlite3
import stat
import sys

path = sys.argv[1]
with sqlite3.connect(path) as database:
    result = database.execute('PRAGMA integrity_check').fetchone()[0]
assert result == 'ok', result
assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, 'database must remain private (0600)'
print('Disposable database integrity and file mode: PASS')
PY
