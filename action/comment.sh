#!/usr/bin/env bash
#
# Post the same summary as a pull request comment, or update the one already
# there.
#
# Updating rather than appending: a scan runs on every push to the branch, and
# a bot that leaves a fresh comment each time buries the review conversation it
# was supposed to inform. The marker below is how the existing comment is
# found -- an HTML comment, so it is invisible in the rendered body.

set -euo pipefail

MARKER="<!-- weedout-action-summary -->"

if [ -z "${GH_TOKEN:-}" ] || [ -z "${PR_NUMBER:-}" ]; then
  echo "No token or pull request number; skipping the comment."
  exit 0
fi

body_file="${RUNNER_TEMP:-/tmp}/weedout-comment.md"
{
  echo "$MARKER"
  "$(dirname "$0")/render.sh"
} > "$body_file"

# Failing to comment must not fail the build. The gate is the scan; this is a
# convenience, and a repository with pull-requests:read is a configuration
# choice rather than an error.
set +e

existing=$(gh api "repos/${GH_REPO}/issues/${PR_NUMBER}/comments" --paginate \
  --jq "map(select(.body | startswith(\"${MARKER}\"))) | .[0].id // empty" 2>/dev/null)

if [ -n "$existing" ]; then
  gh api --method PATCH "repos/${GH_REPO}/issues/comments/${existing}" \
    -F body=@"$body_file" --silent
  status=$?
  [ $status -eq 0 ] && echo "Updated pull request comment ${existing}."
else
  gh api --method POST "repos/${GH_REPO}/issues/${PR_NUMBER}/comments" \
    -F body=@"$body_file" --silent
  status=$?
  [ $status -eq 0 ] && echo "Posted a pull request comment."
fi

if [ $status -ne 0 ]; then
  echo "::warning title=Weedout::Could not post the pull request comment. The scan itself is unaffected; grant pull-requests:write to enable it."
fi
exit 0
