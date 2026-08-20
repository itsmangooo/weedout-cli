#!/usr/bin/env bash
#
# Write the scan summary into the Actions run UI.
#
# $GITHUB_STEP_SUMMARY is what makes this visible without expanding a log, and
# it is the difference between a red tick and a red tick that tells you which
# package to upgrade.

set -euo pipefail

"$(dirname "$0")/render.sh" >> "$GITHUB_STEP_SUMMARY"
