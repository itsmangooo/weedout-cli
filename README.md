# weedout-cli

Scan your dependencies for the CVEs that actually matter, from your terminal or
your pipeline.

[Weedout](https://weedout.dev) watches dependency manifests and reports two
kinds of vulnerability: the ones attackers are actively exploiting right now,
and the ones that are severe and reachable in the code you actually ship.
Everything else is recorded, counted, and left alone.

## Install

```bash
pip install weedout-cli
```

No dependencies. This installs into the same environment as the project you are
building, so it deliberately brings nothing with it that could conflict with
what that project needs.

## Use

```bash
export WEEDOUT_API_KEY=wo_...
weedout scan
```

`weedout scan` finds a manifest in the current directory, checks it, and prints
what came back:

```
demo-app  /home/you/demo-app/package-lock.json
412 dependencies scanned · 33 filtered out as noise

  1 exploited  ·  1 critical

  ! systeminformation@5.0.0  CVE-2021-21315  → 5.3.1
  • minimist@1.2.5           CVE-2021-44906  → 1.2.6

  https://weedout.dev/targets/12
```

`!` is on CISA's exploited list; `•` cleared the bar on severity alone. The
"filtered out as noise" count is the number of real advisories that matched your
versions and were deliberately *not* shown — browsable on the dashboard with the
reason attached for each.

Create an API key in **Settings** on your dashboard. Keys belong to a single
project, so one leaked from a build log can only push results for the
repository that build was for.

### In CI

```bash
weedout scan --ci
```

`--ci` fails the command when something critical or actively exploited is
found. Without it, findings are reported and the command still succeeds —
adding a security tool should not be the thing that breaks your build first.

**GitHub Actions:**

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - uses: itsmangooo/weedout/.github@v1
        with:
          api-key: ${{ secrets.WEEDOUT_API_KEY }}

  deploy:
    needs: security-scan       # this is what makes it a gate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying"
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan ran. Nothing blocking. |
| `1` | The scan ran and found something critical or actively exploited (`--ci` only). |
| `2` | The scan did **not** run — bad key, unreachable service, no manifest found. |

`2` is separate from `1` on purpose. A pipeline that treats every non-zero exit
as "vulnerabilities found" will eventually treat an expired API key as a
security finding, and somebody will fix it by deleting the step. `2` means you
learned nothing, which is a different problem with a different fix.

## What gets scanned

| File | Ecosystem |
|---|---|
| `package-lock.json` | npm |
| `package.json` | npm |
| `requirements.txt` | PyPI |
| `go.mod` | Go |

A lockfile wins when both are present. `package-lock.json` records the version
that is actually installed; `package.json` records a range, and scanning a
range means assuming the lowest version it permits. Weedout labels that
assumption on every finding it affects rather than presenting a guess as a
fact — but running `weedout scan` after your install step removes the guess
entirely.

`node_modules` is never searched, and the walk goes two directories deep. A
repository root is where a manifest lives; wandering through a monorepo would
mean reporting on an arbitrary sub-package.

## Configuration

The API key is resolved in this order:

1. `--api-key`
2. `WEEDOUT_API_KEY`
3. `api_key` in a `.weedout` file, searched from the current directory upward

The environment beating the file is deliberate. CI injects secrets as
environment variables, and a `.weedout` that got committed must never quietly
override the key your pipeline was configured with.

`weedout init` writes a `.weedout` for local use. **Add it to `.gitignore`** —
it holds a credential.

```
weedout scan [PATH] [--ci] [--api-key KEY] [--url URL] [--timeout N] [-v]
weedout init [PATH] [--api-key KEY] [--url URL] [--force]
```

`--url` and `WEEDOUT_URL` point the CLI at a self-hosted instance.

Symbols degrade to ASCII (`->`, `*`, `-`) when the terminal's encoding cannot
represent them, so a default Windows console shows a plain report rather than
crashing mid-print.

## Links

- [Documentation](https://weedout.dev/docs)
- [Scanning your project](https://weedout.dev/docs/scanning-your-project)
- [Gate your pipeline](https://weedout.dev/docs/gate-your-pipeline)
- [Source](https://github.com/itsmangooo/weedout)
