#!/usr/bin/env bash
#
# Scan this repository's own dependencies with Weedout, and fail if any of them
# is critical or being exploited.
#
# Dogfooding, and not for the marketing value. A security tool that does not run
# against itself is a tool whose authors have never used it under the conditions
# their users do — with a real key, in a real pipeline, where a false positive
# is somebody's Friday afternoon.
#
# It also closes a specific gap. weedout.dev tells visitors this CLI has no
# dependencies, and `go.mod` is read live to keep that page honest. The page
# would happily start showing a table the day somebody adds one, and nobody
# would notice. Two checks cover the two halves:
#
#   - `go test .` at the repository root fails if a dependency appears at all.
#     No secret, so it runs on forks and on every pull request.
#   - this script scans whatever is there against the real service. A secret,
#     so it runs where one is available and skips where it is not.
#
# Usage:
#
#   scripts/vet-dependencies.sh
#
# Environment:
#
#   WEEDOUT_API_KEY   required; a scan-scoped key for the CLI's own project
#   WEEDOUT_URL       optional; defaults to the hosted service
#   WEEDOUT_FAIL_ON   optional; critical (default) or high
#   SUMMARY_FILE      optional; a file to append a human summary to
#
# Exit codes match the CLI's, deliberately:
#
#   0  ran, nothing blocking
#   1  ran, found something blocking
#   2  did not run
#
# The gap between 1 and 2 is the one that matters. A pipeline treating every
# non-zero exit as "vulnerabilities found" will eventually treat an expired key
# as a security finding, and somebody will fix that by deleting the step.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL_ON="${WEEDOUT_FAIL_ON:-critical}"
SUMMARY="${SUMMARY_FILE:-${GITHUB_STEP_SUMMARY:-/dev/null}}"

say() {
  echo "$*"
  echo "$*" >> "$SUMMARY"
}

if [ -z "${WEEDOUT_API_KEY:-}" ]; then
  # Exit 2, not 0. "No key" is "did not run", and a check that reports success
  # when it did not run is worse than no check: it is a green tick that means
  # nothing, on the one step whose whole job is to go red.
  say "No WEEDOUT_API_KEY, so dependencies were not vetted."
  exit 2
fi

if ! command -v weedout >/dev/null 2>&1; then
  say "No weedout binary on PATH, so dependencies were not vetted."
  exit 2
fi

# go.mod, because that is what the ecosystem's advisories are written against
# and what `weedout scan` detects here. If a go.sum exists it is covered by the
# same scan: the versions in it are the ones go.mod resolves to.
if [ ! -f "$ROOT/go.mod" ]; then
  say "No go.mod at $ROOT, so there was nothing to vet."
  exit 2
fi

echo "Vetting this repository's dependencies (failing at $FAIL_ON or confirmed exploitation)."

weedout scan "$ROOT" --ci --fail-on "$FAIL_ON"
status=$?

case "$status" in
  0)
    say "Dependencies vetted: nothing at $FAIL_ON or being exploited."
    ;;
  1)
    say "**Blocked.** A dependency of the CLI itself is at $FAIL_ON severity or is being exploited."
    say ""
    say "This is the tool refusing to ship a version of itself that it would"
    say "have told a user to fix. Upgrade the dependency, or drop it."
    ;;
  *)
    # Whatever went wrong, it is not a finding. Saying so keeps somebody from
    # "fixing" an expired key by relaxing the threshold.
    say "The scan could not run, so nothing was vetted. This is not a clean result."
    ;;
esac

exit "$status"
