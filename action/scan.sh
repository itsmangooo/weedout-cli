#!/usr/bin/env bash
#
# Run the scan once, save the JSON, publish the counts as step outputs, and
# exit with the CLI's own code.
#
# Once, not twice: a second run for the human-readable output would double the
# API calls, double the wait, and could disagree with the first if a scan
# landed in between.

set -uo pipefail

# Exit 2, never 1. A misconfigured action did not find a vulnerability, and a
# pipeline that cannot tell those apart eventually treats an expired key as a
# security finding -- then somebody "fixes" it by deleting the step.
die() {
  echo "::error title=Weedout::$*"
  exit 2
}

command -v jq >/dev/null 2>&1 || die "jq is required and is not on PATH."

# Not bash's ${VAR:?...}: that exits 1, which in this action's contract means
# "vulnerabilities found".
[ -n "${WEEDOUT_API_KEY:-}" ] || die "The api-key input is required. Pass it from a secret."

# Secrets passed through ${{ secrets.* }} are masked already. A key typed
# straight into the workflow file is not, and it would otherwise be echoed by
# any step that dumps its environment.
echo "::add-mask::${WEEDOUT_API_KEY}"

result="${RUNNER_TEMP:-/tmp}/weedout-result.json"
scan_path="${WEEDOUT_PATH:-.}"
fail_on="${WEEDOUT_FAIL_ON:-critical}"

case "$fail_on" in
  critical|high) ;;
  *) die "fail-on must be \"critical\" or \"high\", not \"${fail_on}\"." ;;
esac

echo "Scanning ${scan_path} (failing on ${fail_on} and above)"

set +e
weedout scan "$scan_path" \
  --ci \
  --fail-on "$fail_on" \
  --json \
  --url "${WEEDOUT_API_URL:-https://weedout.dev}" \
  > "$result"
code=$?
set -e

# Exit 2 means the scan did not run: a rejected key, an unreachable service, no
# lockfile. There is no JSON to read and nothing to summarise, and calling that
# "no vulnerabilities" is the worst wrong answer this action could give.
if [ $code -eq 2 ] || [ ! -s "$result" ]; then
  echo "::error title=Weedout::The scan did not run, so nothing was checked. This is not a clean result."
  # The CLI wrote its complaint to stderr, which is already in the log above.
  exit 2
fi

if ! jq empty "$result" 2>/dev/null; then
  echo "::error title=Weedout::The CLI produced output that was not JSON."
  head -c 2000 "$result"
  exit 2
fi

emit() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }

emit "critical-count"   "$(jq -r '.counts.critical // 0'  "$result")"
emit "high-count"       "$(jq -r '.counts.high // 0'      "$result")"
emit "exploited-count"  "$(jq -r '.counts.exploited // 0' "$result")"
emit "blocking-count"   "$(jq -r '.blocking // 0'         "$result")"
emit "filtered-count"   "$(jq -r '.suppressed // 0'       "$result")"
emit "findings-url"     "$(jq -r '.dashboard_url // ""'   "$result")"
emit "result-json"      "$result"

# A readable line in the log itself, so somebody scrolling the raw output sees
# the answer without opening the summary tab.
jq -r '
  "\(.project // "project"): \(.dependencies_scanned) dependencies scanned, " +
  "\(.suppressed) filtered out as noise, \(.blocking) blocking."
' "$result"

exit $code
