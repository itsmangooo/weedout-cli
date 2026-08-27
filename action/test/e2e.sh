#!/usr/bin/env bash
#
# End-to-end test for the action's own scripts.
#
# Runs the real CLI binary against a mock scan API and drives scan.sh, then
# checks the things a broken action would get wrong silently: the exit code,
# the step outputs, and what the summary actually says.
#
# What this does not cover is GitHub itself -- the composite runner, the
# `uses:` resolution, the real PR comment API. Those are covered by
# .github/workflows/action.yml, which runs the action against this repository.
#
#   ./test/e2e.sh            uses whatever `weedout` is on PATH
#
# Requires: jq, python3, and a weedout binary.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"   # the action/ directory
PORT="${PORT:-8787}"

pass=0
fail=0

ok()   { echo "  ok    $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }

check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}

contains() {
  # contains <description> <needle> <file>
  if grep -qF "$2" "$3"; then ok "$1"; else bad "$1: '$2' not in $3"; fi
}

missing() {
  if grep -qF "$2" "$3"; then bad "$1: '$2' should not be in $3"; else ok "$1"; fi
}

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }
command -v weedout >/dev/null 2>&1 || { echo "no weedout binary on PATH"; exit 2; }

# The first interpreter that actually runs. On Windows, `command -v python3`
# finds the Microsoft Store shim, which exists on PATH and does nothing.
PYTHON=""
for candidate in python3 python py; do
  if "$candidate" -c "print(1)" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
done
[ -n "$PYTHON" ] || { echo "no working python3 on PATH"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"; [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null' EXIT

# A project for the CLI to find. The mock does not read it; it has to exist
# because refusing to scan a directory with no manifest is the CLI's job and
# this test is not about that path.
mkdir -p "$work/project"
echo '{"dependencies":{"lodash":"4.17.15"}}' > "$work/project/package.json"

start_server() {
  [ -n "${server_pid:-}" ] && { kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; }
  "$PYTHON" "$HERE/mock_api.py" "$PORT" "$1" &
  server_pid=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null "http://127.0.0.1:${PORT}/api/v1/scan" 2>/dev/null; then return; fi
    sleep 0.1
  done
}

run_action() {
  # run_action <fail-on>  -> sets $code, and writes $outputs / $summary
  outputs="$work/outputs.txt"
  summary="$work/summary.md"
  : > "$outputs"
  : > "$summary"

  GITHUB_OUTPUT="$outputs" \
  GITHUB_STEP_SUMMARY="$summary" \
  RUNNER_TEMP="$work" \
  WEEDOUT_API_KEY="wo_test_key" \
  WEEDOUT_FAIL_ON="$1" \
  WEEDOUT_PATH="$work/project" \
  WEEDOUT_API_URL="http://127.0.0.1:${PORT}" \
    bash "$ROOT/scan.sh" > "$work/scan.log" 2>&1
  code=$?

  RESULT_JSON="$work/weedout-result.json" WEEDOUT_FAIL_ON="$1" \
  GITHUB_STEP_SUMMARY="$summary" RUNNER_TEMP="$work" \
    bash "$ROOT/summary.sh" 2>/dev/null || true
}

output_value() { grep "^$1=" "$outputs" | head -n1 | cut -d= -f2-; }

# ---------------------------------------------------------------------------
echo
echo "A vulnerable project at the default threshold"
# ---------------------------------------------------------------------------
start_server "$HERE/fixtures/vulnerable.json"
run_action critical

check "fails the build"            1     "$code"
check "critical-count output"      2     "$(output_value critical-count)"
check "high-count output"          5     "$(output_value high-count)"
check "exploited-count output"     1     "$(output_value exploited-count)"
check "blocking-count output"      2     "$(output_value blocking-count)"
check "filtered-count output"      47    "$(output_value filtered-count)"
check "findings-url output"        "https://weedout.dev/targets/42" "$(output_value findings-url)"

contains "summary says the build failed"  "Build failed"                "$summary"
contains "summary names the exploited one" "systeminformation@5.0.0"    "$summary"
contains "summary carries the fix version" '`5.3.1`'                    "$summary"
contains "summary shows what was filtered" "47"                         "$summary"
missing  "high finding is not listed at the critical threshold" "lodash@4.17.15" "$summary"

# ---------------------------------------------------------------------------
echo
echo "The same project with fail-on: high"
# ---------------------------------------------------------------------------
run_action high

check "still fails"                1     "$code"
check "blocking count rises"       3     "$(output_value blocking-count)"
contains "the high finding is now listed" "lodash@4.17.15"              "$summary"
contains "and says there is no fix"       "no fix yet"                  "$summary"

# ---------------------------------------------------------------------------
echo
echo "A clean project"
# ---------------------------------------------------------------------------
start_server "$HERE/fixtures/clean.json"
run_action critical

check "passes"                     0     "$code"
check "blocking-count is zero"     0     "$(output_value blocking-count)"
contains "summary says so"         "Nothing to act on"                  "$summary"

# ---------------------------------------------------------------------------
echo
echo "A project whose only findings are below the line"
# ---------------------------------------------------------------------------
start_server "$HERE/fixtures/below_the_line.json"
run_action critical

check "does not fail the build"    0     "$code"
contains "but does not claim it is clean" "below the" "$summary"

# ---------------------------------------------------------------------------
echo
echo "A rejected API key"
#
# The one that matters most: a scan that could not run must never look like a
# scan that found nothing. Exit 2, and no summary claiming anything.
# ---------------------------------------------------------------------------
start_server "$HERE/fixtures/clean.json"
outputs="$work/outputs.txt"; : > "$outputs"
summary="$work/summary.md";  : > "$summary"
# Removed so a stale file from an earlier case cannot make this one look like
# it produced a result.
rm -f "$work/weedout-result.json"

GITHUB_OUTPUT="$outputs" GITHUB_STEP_SUMMARY="$summary" RUNNER_TEMP="$work" \
WEEDOUT_API_KEY="wo_bad_key" WEEDOUT_FAIL_ON="critical" WEEDOUT_PATH="$work/project" \
WEEDOUT_API_URL="http://127.0.0.1:${PORT}" \
  bash "$ROOT/scan.sh" > "$work/rejected.log" 2>&1
code=$?

check "exits 2, not 0 and not 1"   2     "$code"
contains "says nothing was checked" "not a clean result"                "$work/rejected.log"
missing "no clean-result claim"    "Nothing to act on"                  "$summary"
check "publishes no counts"        ""    "$(output_value blocking-count)"

# ---------------------------------------------------------------------------
echo
echo "No API key at all"
# ---------------------------------------------------------------------------
GITHUB_OUTPUT="$work/outputs.txt" RUNNER_TEMP="$work" \
WEEDOUT_API_KEY="" WEEDOUT_FAIL_ON="critical" WEEDOUT_PATH="$work/project" \
WEEDOUT_API_URL="http://127.0.0.1:${PORT}" \
  bash "$ROOT/scan.sh" > "$work/nokey.log" 2>&1
code=$?

check "also exits 2"               2     "$code"
contains "and names the missing input" "api-key" "$work/nokey.log"

# ---------------------------------------------------------------------------
echo
echo "An invalid fail-on value"
# ---------------------------------------------------------------------------
GITHUB_OUTPUT="$work/outputs.txt" RUNNER_TEMP="$work" \
WEEDOUT_API_KEY="wo_test_key" WEEDOUT_FAIL_ON="medium" WEEDOUT_PATH="$work/project" \
WEEDOUT_API_URL="http://127.0.0.1:${PORT}" \
  bash "$ROOT/scan.sh" > "$work/badflag.log" 2>&1
code=$?

check "refused before scanning"    2     "$code"
contains "and says what is allowed" 'must be' "$work/badflag.log"

# ---------------------------------------------------------------------------
echo
if [ "$fail" -gt 0 ]; then
  echo "$pass passed, $fail FAILED"
  exit 1
fi
echo "$pass passed"
