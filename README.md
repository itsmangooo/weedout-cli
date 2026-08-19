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

`weedout init` writes a `.weedout` file holding your key. **Add it to
`.gitignore`** — the command says so too. In CI, skip it and set
`WEEDOUT_API_KEY` instead: the environment always beats the file, so a key
committed by accident can never quietly override the one your pipeline was
configured with.

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

### In GitHub Actions

```yaml
- name: Check dependencies
  run: |
    curl -sSL https://weedout.dev/install.sh | sh
    weedout scan --ci
  env:
    WEEDOUT_API_KEY: ${{ secrets.WEEDOUT_API_KEY }}
```

## Configuration

Resolved highest-first:

1. `--api-key` on the command line
2. `WEEDOUT_API_KEY` in the environment
3. `api_key` in a `.weedout` file, searched from the working directory upward

`--url` / `WEEDOUT_URL` points the CLI at a self-hosted instance.

## Dependencies

None. `go.mod` has no `require` block, and
[weedout.dev/cli](https://weedout.dev/cli) reads that file directly rather than
listing packages by hand.

Every dependency in a security tool is another thing you have to trust, and a
CI runner is the last place that benefits from a dependency tree. The HTTP call
is `net/http`, the parsing is `encoding/json`, the upload is `mime/multipart`,
the arguments are `flag`, and the coloured output is about thirty lines of ANSI
escapes.

## Building

```sh
go test ./...
go build .
```

Go 1.22 or newer. Releases are cross-compiled by GitHub Actions on a `v*` tag
and published with checksums.

## Licence

Not yet chosen. Until one is added, the usual default applies: all rights
reserved.
