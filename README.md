# weedout

Scan your dependencies for the CVEs that actually matter.

One binary. No runtime, no interpreter, and no third-party packages — the whole
thing is the Go standard library.

```
$ weedout scan
acme-storefront  package-lock.json
312 dependencies scanned · 47 filtered out as noise

  1 exploited  ·  2 critical  ·  5 high

  ! systeminformation@5.0.0  CVE-2021-21315  → 5.3.1
  • minimist@1.2.0  CVE-2021-44906  → 1.2.6

  https://weedout.dev/targets/42
```

The second number is the one worth reading. Most advisories that match your
lockfile do not deserve to interrupt anyone, and this tells you how many it
decided not to.

## Install

```sh
curl -sSL https://weedout.dev/install.sh | sh
```

It works out your platform, downloads the matching binary from the latest
GitHub release, verifies the published checksum, and puts it somewhere on your
PATH. It is short, and you should [read it](install.sh) before piping anything
into a shell.

With Go:

```sh
go install github.com/itsmangooo/weedout-cli@latest
```

Or download a binary directly from
[releases](https://github.com/itsmangooo/weedout-cli/releases). Builds are
published for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and
windows/amd64.

## Use

```sh
weedout init          # save your API key to .weedout
weedout scan          # scan this project
weedout scan --ci     # and fail the build on anything critical or exploited
```

Everything the dashboard shows is also here, so the web interface is optional:

```sh
weedout status        # counts, the severity breakdown, when it was last checked
weedout findings      # what is open, with the fix and how it got into the tree
weedout history       # recent scans, and how the count has moved
weedout supply-chain  # signals about the packages themselves
weedout rules         # what is being reported, and what is not
```

Add `--json` to any of them to get the same data as a machine-readable object.

### What it scans

It looks for the file that says what is *actually installed*, preferring a
lockfile over the manifest it was resolved from:

| File                | Ecosystem | Notes                                  |
| ------------------- | --------- | -------------------------------------- |
| `package-lock.json` | npm       | preferred over `package.json`          |
| `package.json`      | npm       | versions are inferred from the ranges  |
| `requirements.txt`  | PyPI      |                                        |
| `go.mod`            | Go        |                                        |

`yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock` and `go.sum` are
not supported yet. If one is present and nothing else is, the CLI says so by
name and tells you which file to point at instead — rather than uploading
something the API cannot read and leaving you with a parse error.

### Exit codes

| Code | Meaning                                                    |
| ---- | ---------------------------------------------------------- |
| `0`  | ran, nothing blocking                                      |
| `1`  | ran, found something critical or exploited (`--ci` only)   |
| `2`  | did not run — bad key, unreachable service, or no manifest  |

The gap between `1` and `2` is the point. A pipeline that treats every non-zero
exit as "vulnerabilities found" will eventually treat an expired API key as a
security finding, and somebody will fix that by deleting the step. A scan that
could not run is never reported as a clean scan, and never as a failing one.

Without `--ci`, findings are printed but the command still exits `0`. Adding
this tool to a pipeline should never be the thing that breaks the build first.

### In CI

On GitHub, use the action — see [As a GitHub Action](#as-a-github-action).
Anywhere else, it is two lines:

```yaml
- name: Check dependencies
  run: |
    curl -sSL https://weedout.dev/install.sh | sh
    weedout scan --ci
  env:
    WEEDOUT_API_KEY: ${{ secrets.WEEDOUT_API_KEY }}
```

## Keeping it current

```sh
weedout update           # check, confirm, install
weedout update --check   # report only, install nothing
weedout update --yes     # no confirmation, for a scripted upgrade
```

Updates come from this repository's GitHub Releases. What the updater will and
will not do is worth stating plainly, because a tool that downloads a file and
puts it where the operating system will run it is structurally a supply-chain
risk, and this one is a security scanner:

- **Nothing is installed without a matching SHA-256.** The digest comes from
  the `checksums.txt` published with the release. If it cannot be fetched, or
  does not match, the update fails and the binary on disk is left alone. There
  is no path that skips this.
- **HTTPS only, on every hop.** Redirects are followed, because release assets
  are served from a CDN, but a redirect to plain HTTP or to a host outside
  GitHub ends the attempt.
- **Nothing is executed.** The new binary is verified, put in place, and left
  for you to run.
- **Never automatic.** There is no background updater. A dim one-line notice
  appears at most once a day when a newer release exists; installing is
  something you ask for.
- **Never in CI.** The notice is suppressed in pipelines and with `--json` or
  `--quiet`, and `weedout update` will not install without `--yes` when there
  is nobody there to confirm. Pin a version in a pipeline: a build whose
  scanner changes underneath it is no longer reproducible.
- **A build you compiled yourself is never replaced.** `weedout version`
  reporting `dev` means the updater leaves it alone.

The replacement is a rename rather than a write over the running file, so an
interrupted update leaves either the old binary or the new one and never half
of either. On Windows the previous binary cannot be deleted while it is
running, so it is renamed to `weedout.exe.old` and cleared on the next run.

To turn the daily notice off:

```
update_checks = false
```

in the settings file described below.

## Interactive mode

```sh
weedout --interactive          # turn the menu on for this installation
weedout --interactive off      # turn it off
weedout --interactive status   # report without changing anything
```

With it on, running `weedout` with no command gives an arrow-key menu of the
commands that are safe to run with no arguments. Up and down to move, Enter to
choose, `q` to cancel; `j`/`k` and the number keys work too. Where a terminal
cannot be put into raw mode — a pipe, a serial console, a platform without an
implementation — it degrades to a typed-number prompt rather than failing.

It is **off by default and never appears in CI**, or when either input or
output is not a terminal. A binary that waits for a keypress in a pipeline is a
hung build, and that is a worse failure than a menu nobody sees.

`weedout rules ignore` is deliberately not on the menu. It changes what the
project will report from then on, and that should be typed out with its reason
rather than reachable by pressing Enter twice.

### Where the setting is stored

Beside the executable, in `weedout.settings`, so a copy of the tool carries its
own preferences and two copies on one machine do not fight over them.

That directory is often read-only once installed — `/usr/local/bin`, Program
Files, a container image layer. When it is, the file falls back to your user
config directory, and the command tells you which one it used rather than
silently forgetting the setting.

It is the same flat `key = value` format as `.weedout`:

```
interactive = true
update_checks = true
```

`weedout init` writes a `.weedout` file holding your key. **Add it to
`.gitignore`** — the command says so too. In CI, skip it and set
`WEEDOUT_API_KEY` instead: the environment always beats the file, so a key
committed by accident can never quietly override the one your pipeline was
configured with.

## Configuration

Resolved highest-first:

1. `--api-key` on the command line
2. `WEEDOUT_API_KEY` in the environment
3. `api_key` in a `.weedout` file, searched from the working directory upward

`--url` / `WEEDOUT_URL` points the CLI at a self-hosted instance.

### Key scopes

A key is issued for one project and with one of three scopes. Pick the
narrowest that does the job:

| Scope | Can | Use it for |
|---|---|---|
| **Push scans** | `weedout scan` | CI. This is the default. |
| **Read findings** | `status`, `findings`, `history`, `supply-chain` | Dashboards, your terminal. |
| **Full access** | all of the above, plus `rules` | A key you keep on your own machine. |

The split matters because a key in a pipeline is readable by anyone who can
read a build log. If that key could also add an ignore rule, whoever took it
could switch off the alert for the vulnerability they were about to use. So the
CI key cannot read your findings and cannot change your rules, and asking it to
gets a clear refusal rather than a silent failure.

Existing keys are push-only, which is what they already were — nothing widened
when scopes arrived.

### Changing what gets reported

```sh
weedout rules                                            # what is in force
weedout rules ignore CVE-2021-23337 --reason "not reachable from our code"
weedout rules unignore CVE-2021-23337
```

The reason is required. A rule with no reason is indistinguishable from a
mistake when somebody reads it back in six months.

An ignored advisory that later turns up on CISA's known-exploited list is
reported anyway, and `weedout rules` marks it so you can see the rule stopped
applying.

For anything you want reviewed like code, prefer a `.weedout.yml` committed to
the repo: it travels with the branch and goes through pull request. `weedout
rules` lists what that file says separately from the rules stored on the
server, so the two are never confused.

## Dependencies

None. `go.mod` has no `require` block, and
[weedout.dev/cli](https://weedout.dev/cli) reads that file directly rather than
listing packages by hand.

Every dependency in a security tool is another thing you have to trust, and a
CI runner is the last place that benefits from a dependency tree. The HTTP call
is `net/http`, the parsing is `encoding/json`, the upload is `mime/multipart`,
the arguments are `flag`, the update's integrity check is `crypto/sha256`, and
the coloured output is about thirty lines of ANSI escapes.

The arrow-key menu is the one place this costs something. Reading a keypress
means putting the terminal into raw mode, which the standard library exposes
only as raw syscalls — `golang.org/x/term` is the package everyone reaches for,
and it would have been this module's only dependency. It is roughly eighty
lines of `syscall` behind build tags instead, in `internal/ui/raw_*.go`. A tool
whose whole pitch is that it takes your dependency tree seriously should not
add a package to read an arrow key.

## Building

```sh
go test ./...
go build .
```

Go 1.22 or newer. Releases are cross-compiled by GitHub Actions on a `v*` tag
and published with checksums.

### Size

A plain `go build` produces a larger binary than a release does, because
releases strip the symbol table and DWARF debug info:

```sh
go build -trimpath -ldflags "-s -w" .
```

| Build | Size |
|---|---|
| `go build` | 9.1 MB |
| `-trimpath -ldflags "-s -w"` | 6.4 MB |
| gzipped, as the updater downloads it | 2.7 MB |

Most of what remains is the Go runtime and the TLS stack, and neither is
optional for a static binary that makes an HTTPS request. There is no
dependency tree to trim: `go.mod` has no `require` block, and every package
linked in traces back to `net/http`.

**Not UPX.** Compressing the executable would take it under 3 MB on disk, and
it is the wrong trade here: packed binaries are a well-known malware technique,
so antivirus and EDR products flag them heavily on reputation alone. A security
scanner that its user's endpoint protection quarantines is worse than a
security scanner that is 6 MB. The compression is applied to the download
instead, where it costs nothing.

## As a GitHub Action

```yaml
- uses: itsmangooo/weedout-cli@v1
  with:
    api-key: ${{ secrets.WEEDOUT_API_KEY }}
```

One step, no toolchain. The action downloads the release binary for the
runner's platform, verifies it against the published checksum, and runs it — so
the runner needs neither Go nor Python.

### What you get

A summary in the Actions run, and the same summary as a pull request comment:

> ## Weedout security scan
>
> **Build failed.** 2 finding(s) at critical severity or above, or confirmed
> exploited in the wild.
>
> `acme-storefront` — 312 dependencies scanned.
>
> **47** advisories matched these dependencies and were deliberately not
> reported — dev-only, transitive and unexploited, or below the bar.
>
> | Exploited | Critical | High | Medium | Low |
> | --: | --: | --: | --: | --: |
> | 1 | 2 | 5 | 3 | 0 |
>
> ### What is blocking
>
> | Package | Severity | CVE | Fix |
> | --- | --- | --- | --- |
> | `systeminformation@5.0.0` | **exploited in the wild** | CVE-2021-21315 | `5.3.1` |
> | `minimist@1.2.0` | critical | CVE-2021-44906 | `1.2.6` |

### Setup

1. Create a project on [weedout.dev](https://weedout.dev) and copy its API key.
   The key decides which project a scan belongs to, so there is nothing else to
   configure.
2. Add it to the repository as a secret named `WEEDOUT_API_KEY`.
3. Add the step.

```yaml
name: security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Only needed for the pull request comment. Without it the scan still
      # runs and the step summary is still written.
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: itsmangooo/weedout-cli@v1
        with:
          api-key: ${{ secrets.WEEDOUT_API_KEY }}
          fail-on: critical
```

### Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `api-key` | *required* | Your project key. Pass it from a secret, never inline. |
| `fail-on` | `critical` | The severity floor that fails the build: `critical` or `high`. Confirmed exploitation fails at either. |
| `path` | `.` | The directory to scan. |
| `version` | `latest` | Which CLI release to run, e.g. `v0.1.0`. Pin it for a reproducible scan. |
| `comment-on-pr` | `true` | Post and update a pull request comment. |
| `github-token` | `${{ github.token }}` | Token used for that comment. |
| `api-url` | `https://weedout.dev` | Only useful if you self-host. |

#### About `fail-on`

`critical` is the default because it is the setting people leave switched on.
It fails on critical severity **and** on anything CISA lists as being exploited
in the wild, whatever that advisory's score says — a vulnerability with working
public exploitation is not a medium problem because a rubric said so.

`high` raises the floor. It is a reasonable choice for a service that handles
other people's data, and a poor one for a repository of examples.

There is no `medium` or `low`. A gate that fails on everything is a gate
somebody disables, and a disabled gate reports nothing at all.

### Outputs

```yaml
- uses: itsmangooo/weedout-cli@v1
  id: weedout
  with:
    api-key: ${{ secrets.WEEDOUT_API_KEY }}

- if: steps.weedout.outputs.exploited-count != '0'
  run: |
    echo "Exploited in the wild: ${{ steps.weedout.outputs.exploited-count }}"
    echo "${{ steps.weedout.outputs.findings-url }}"
```

| Output | What it is |
| --- | --- |
| `critical-count` | Open findings at critical severity. |
| `high-count` | Open findings at high severity. |
| `exploited-count` | Findings CISA lists as exploited in the wild. |
| `blocking-count` | Findings at or above `fail-on`. |
| `filtered-count` | Advisories matched and deliberately not reported. |
| `findings-url` | This project on the dashboard. |
| `result-json` | Path to the full result, for a later step to read. |

The step fails on exit `1` and on exit `2`, and those mean different things —
see [Exit codes](#exit-codes) above. A `2` is never a clean result.

Outputs are published on failure too, so a step with `if: always()` can react
to the numbers that just failed the build.

## Licence

[MIT](LICENSE).

Permissive on purpose. This binary runs inside other people's CI, with their
credentials in the environment, and the landing page invites anyone to check
its dependency list and verify it has none. A tool making that argument should
be one you can read, audit and vendor without asking.

The hosted service it talks to is a separate repository under a different
licence.
