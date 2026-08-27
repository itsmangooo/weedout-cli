#!/usr/bin/env bash
#
# Tests for scripts/vet-dependencies.sh, against a mock scan API.
#
# The case worth proving is the one the check exists for: a dependency with a
# known CVE arrives, and the pull request goes red. A vetting step that only
# ever passes is indistinguishable from no vetting step, and it is the failure
# mode nobody notices, because green is what everyone expects to see.
#
# The other half is the gap between "found something" and "could not run". A
# check that reports those the same way trains people to relax it.
#
#   scripts/test/vet_test.sh      uses whatever `weedout` is on PATH
#
# Requires: python3 and a weedout binary.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$ROOT/scripts/vet-dependencies.sh"
PORT="${PORT:-8788}"

pass=0
fail=0

ok()  { echo "  ok    $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $*"; fail=$((fail + 1)); }

check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}

contains() {
  # contains <description> <needle> <file>
  if grep -qF "$2" "$3"; then ok "$1"; else bad "$1: '$2' not in $3"; fi
}

command -v weedout >/dev/null 2>&1 || { echo "no weedout binary on PATH"; exit 2; }

# The first interpreter that actually runs. On Windows, `command -v python3`
# finds the Microsoft Store shim, which exists on PATH and does nothing.
PYTHON=""
for candidate in python3 python py; do
  if "$candidate" -c "print(1)" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done
[ -n "$PYTHON" ] || { echo "python3 is required"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null' EXIT

start_mock() {
  # start_mock <fixture.json>
  [ -n "${MOCK_PID:-}" ] && { kill "$MOCK_PID" 2>/dev/null; wait "$MOCK_PID" 2>/dev/null; }
  "$PYTHON" "$ROOT/action/test/mock_api.py" "$PORT" "$1" &
  MOCK_PID=$!
  for _ in $(seq 1 40); do
    if "$PYTHON" -c "
import socket, sys
s = socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1', $PORT)) == 0 else 1)
" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "the mock API never came up"
  exit 2
}

run_vet() {
  # run_vet <extra env assignments...> -- captures stdout+stderr, returns status
  SUMMARY_FILE="$WORK/summary.md" \
  WEEDOUT_URL="http://127.0.0.1:$PORT" \
    "$@" bash "$SCRIPT" > "$WORK/out.txt" 2>&1
  echo $?
}

echo
echo "vet-dependencies.sh"
echo

# ---------------------------------------------------------------------------
# The case this check exists for
# ---------------------------------------------------------------------------

cat > "$WORK/vulnerable.json" <<'EOF'
{
  "project": "weedout-cli",
  "dependencies_scanned": 3,
  "actionable": 1,
  "suppressed": 0,
  "counts": {"critical": 1},
  "findings": [
    {
      "package": "github.com/example/broken",
      "version": "1.0.0",
      "cve": "CVE-2026-0001",
      "severity": "critical",
      "exploited": false,
      "fixed_version": "1.0.1"
    }
  ]
}
EOF

start_mock "$WORK/vulnerable.json"
status=$(run_vet env WEEDOUT_API_KEY=wo_test)
check "a dependency with a critical CVE fails the check" 1 "$status"
contains "the summary says it was blocked" "Blocked" "$WORK/summary.md"
contains "and says why that matters here" "would" "$WORK/summary.md"

# Exploitation fails at any threshold, which is the whole premise of the
# product applied to its own supply chain.
cat > "$WORK/exploited.json" <<'EOF'
{
  "project": "weedout-cli",
  "dependencies_scanned": 3,
  "actionable": 1,
  "suppressed": 0,
  "counts": {"high": 1},
  "findings": [
    {
      "package": "github.com/example/broken",
      "version": "1.0.0",
      "cve": "CVE-2026-0002",
      "severity": "high",
      "exploited": true,
      "fixed_version": "1.0.1"
    }
  ]
}
EOF

start_mock "$WORK/exploited.json"
status=$(run_vet env WEEDOUT_API_KEY=wo_test)
check "a high finding under active exploitation fails too" 1 "$status"

# ---------------------------------------------------------------------------
# And the case where it should not fire
# ---------------------------------------------------------------------------

cat > "$WORK/clean.json" <<'EOF'
{
  "project": "weedout-cli",
  "dependencies_scanned": 0,
  "actionable": 0,
  "suppressed": 0,
  "counts": {},
  "findings": []
}
EOF

start_mock "$WORK/clean.json"
status=$(run_vet env WEEDOUT_API_KEY=wo_test)
check "a clean scan passes" 0 "$status"
contains "and says so" "nothing at critical" "$WORK/summary.md"

# A high-severity finding that is not exploited passes at the default
# threshold. Failing on it would make the check something people turn off.
cat > "$WORK/high.json" <<'EOF'
{
  "project": "weedout-cli",
  "dependencies_scanned": 3,
  "actionable": 1,
  "suppressed": 0,
  "counts": {"high": 1},
  "findings": [
    {
      "package": "github.com/example/noisy",
      "version": "1.0.0",
      "cve": "CVE-2026-0003",
      "severity": "high",
      "exploited": false,
      "fixed_version": "1.0.1"
    }
  ]
}
EOF

start_mock "$WORK/high.json"
status=$(run_vet env WEEDOUT_API_KEY=wo_test)
check "an unexploited high passes at the default threshold" 0 "$status"

status=$(run_vet env WEEDOUT_API_KEY=wo_test WEEDOUT_FAIL_ON=high)
check "and fails when the threshold is lowered to high" 1 "$status"

# ---------------------------------------------------------------------------
# Did not run, which is not the same as found nothing
# ---------------------------------------------------------------------------

start_mock "$WORK/clean.json"
status=$(run_vet env WEEDOUT_API_KEY=)
check "no key is exit 2, not a pass" 2 "$status"
contains "and says nothing was vetted" "not vetted" "$WORK/summary.md"

status=$(run_vet env WEEDOUT_API_KEY=wo_bad_key)
check "a rejected key is exit 2, not a pass" 2 "$status"
contains "and refuses to read as clean" "not a clean result" "$WORK/summary.md"

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
