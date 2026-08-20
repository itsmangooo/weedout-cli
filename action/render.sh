#!/usr/bin/env bash
#
# Render the scan result as Markdown, on stdout.
#
# One renderer, used by both the step summary and the pull request comment.
# Two copies would drift, and the failure mode is a reviewer and a maintainer
# reading different numbers for the same scan and each believing theirs.

set -euo pipefail

result="${RESULT_JSON:?RESULT_JSON is required}"
fail_on="${WEEDOUT_FAIL_ON:-critical}"

q() { jq -r "$1" "$result"; }

project=$(q '.project // "This project"')
scanned=$(q '.dependencies_scanned // 0')
filtered=$(q '.suppressed // 0')
blocking=$(q '.blocking // 0')
failing=$(q '.failing // false')
url=$(q '.dashboard_url // ""')

exploited=$(q '.counts.exploited // 0')
critical=$(q '.counts.critical // 0')
high=$(q '.counts.high // 0')
medium=$(q '.counts.medium // 0')
low=$(q '.counts.low // 0')

echo "## Weedout security scan"
echo

# The verdict first, in one sentence. Somebody opening this after a red tick
# wants to know what broke before they want a table.
if [ "$failing" = "true" ]; then
  echo "**Build failed.** ${blocking} finding(s) at ${fail_on} severity or above, or confirmed exploited in the wild."
elif [ "$blocking" -gt 0 ]; then
  echo "**${blocking} finding(s)** at ${fail_on} severity or above. Not gating this build."
elif [ "$((exploited + critical + high + medium + low))" -gt 0 ]; then
  echo "**Nothing blocking.** Some findings are open below the \`${fail_on}\` line."
else
  echo "**Nothing to act on.** No advisory cleared the bar for this project."
fi

echo
echo "\`${project}\` — ${scanned} dependencies scanned."
echo

# The filtered count is the one this product is actually proud of, so it gets a
# line of its own rather than a cell in a table.
if [ "$filtered" -gt 0 ]; then
  echo "**${filtered}** advisories matched these dependencies and were deliberately not reported — dev-only, transitive and unexploited, or below the bar. They are all on the dashboard with the reason attached."
  echo
fi

echo "| Exploited | Critical | High | Medium | Low |"
echo "| --: | --: | --: | --: | --: |"
echo "| ${exploited} | ${critical} | ${high} | ${medium} | ${low} |"
echo

# Only the findings that could have gated this build, and only if there are any.
rows=$(jq -r --arg failOn "$fail_on" '
  [ .findings[]?
    | select(.exploited == true
             or .severity == "critical"
             or ($failOn == "high" and .severity == "high"))
  ]
' "$result")

count=$(echo "$rows" | jq 'length')

if [ "$count" -gt 0 ]; then
  echo "### What is blocking"
  echo
  echo "| Package | Severity | CVE | Fix |"
  echo "| --- | --- | --- | --- |"
  echo "$rows" | jq -r '
    .[] |
    "| `\(.package)@\(.version)` " +
    "| \(if .exploited then "**exploited in the wild**" else .severity end) " +
    "| \(.cve // "—") " +
    "| \(if .fixed_in != "" and .fixed_in != null then "`\(.fixed_in)`" else "no fix yet" end) |"
  '
  echo
fi

# Warnings are things like a stale advisory mirror. A result served from stale
# data is still a result, but saying so is the difference between a scanner you
# can trust and one you cannot.
warnings=$(jq -r '.warnings[]?' "$result")
if [ -n "$warnings" ]; then
  echo "> [!WARNING]"
  echo "$warnings" | while IFS= read -r line; do echo "> ${line}"; done
  echo
fi

if [ -n "$url" ]; then
  echo "[Full findings on the dashboard](${url})"
fi
