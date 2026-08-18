"""``weedout`` — scan a project's dependencies from the command line.

Two commands. ``weedout scan`` finds a lockfile, uploads it, and prints what
came back. ``weedout init`` writes a ``.weedout`` so the key does not have to be
passed every time.

Exit codes are the contract with CI, and there are three of them:

    0   the scan ran and nothing is blocking
    1   the scan ran and found something blocking (``--ci`` only)
    2   the scan did not run — bad key, unreachable service, no file

The separation between 1 and 2 is the important one. A pipeline that treats
every non-zero exit as "vulnerabilities found" will eventually treat an expired
API key as a security finding, and someone will "fix" it by removing the step.
Without ``--ci`` a finding is reported but does not fail the command, so adding
the tool to a pipeline is never the thing that breaks the build first.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from weedout_cli import __version__
from weedout_cli.client import ApiError, ScanResult, post_scan
from weedout_cli.config import (
    CONFIG_FILENAME,
    DEFAULT_BASE_URL,
    ENV_API_KEY,
    resolve,
    write_config_file,
)
from weedout_cli.detect import find_manifest, supported_filenames

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


# ---------------------------------------------------------------------------
# Output
#
# Colour is opt-out via NO_COLOR and automatically off when stdout is not a
# terminal, so a CI log does not fill with escape sequences.
#
# Glyphs get the same treatment for a less obvious reason. A Windows console
# still commonly runs a legacy code page — cp1252 on a default `cmd.exe` — and
# printing "→" to one raises UnicodeEncodeError. A security tool that crashes
# while printing its own results is worse than one that prints plain ASCII, so
# the symbol set is chosen from what the stream can actually encode.
# ---------------------------------------------------------------------------


def _use_colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


#: The two symbol sets. Keys are identical so callers never branch.
FANCY_SYMBOLS = {"arrow": "→", "sep": "·", "bullet": "•", "alert": "!"}
PLAIN_SYMBOLS = {"arrow": "->", "sep": "-", "bullet": "*", "alert": "!"}


def _supports_unicode(stream) -> bool:
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        "".join(FANCY_SYMBOLS.values()).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class Printer:
    def __init__(self, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.colour = _use_colour(self.stream)
        self.symbols = FANCY_SYMBOLS if _supports_unicode(self.stream) else PLAIN_SYMBOLS

    def symbol(self, name: str) -> str:
        return self.symbols[name]

    def _wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.colour else text

    def dim(self, text: str) -> str:
        return self._wrap(text, "2")

    def bold(self, text: str) -> str:
        return self._wrap(text, "1")

    def red(self, text: str) -> str:
        return self._wrap(text, "31")

    def yellow(self, text: str) -> str:
        return self._wrap(text, "33")

    def green(self, text: str) -> str:
        return self._wrap(text, "32")

    def line(self, text: str = "") -> None:
        try:
            print(text, file=self.stream)
        except UnicodeEncodeError:
            # Belt and braces. The symbol set above covers what this tool
            # prints; a package name containing something the console cannot
            # encode is not the tool's to fix, and must not stop the report.
            encoding = getattr(self.stream, "encoding", "ascii") or "ascii"
            print(text.encode(encoding, "replace").decode(encoding), file=self.stream)


def _report(result: ScanResult, printer: Printer, manifest: Path) -> None:
    """Print the result the way it should read in a build log.

    Counts first, then the findings worth acting on, then the link. The
    suppressed count is shown deliberately: the number the product is proud of
    is not how much it found, it is how much it decided not to interrupt anyone
    about.
    """
    printer.line()
    printer.line(f"{printer.bold(result.project or manifest.name)}  {printer.dim(str(manifest))}")
    printer.line(
        printer.dim(
            f"{result.dependencies_scanned} dependencies scanned {printer.symbol('sep')} "
            f"{result.suppressed} filtered out as noise"
        )
    )
    printer.line()

    if result.actionable == 0:
        printer.line(printer.green("  Nothing to act on."))
    else:
        parts = []
        if result.exploited:
            parts.append(printer.red(f"{result.exploited} exploited"))
        if result.critical:
            parts.append(printer.red(f"{result.critical} critical"))
        for label in ("high", "medium", "low"):
            if result.counts.get(label):
                parts.append(printer.yellow(f"{result.counts[label]} {label}"))
        printer.line("  " + f"  {printer.symbol('sep')}  ".join(parts))

    if result.findings:
        printer.line()
        for finding in result.findings:
            marker = (
                printer.red(printer.symbol("alert"))
                if finding.get("exploited")
                else printer.yellow(printer.symbol("bullet"))
            )
            fix = finding.get("fixed_in")
            fix_text = (
                printer.green(f"{printer.symbol('arrow')} {fix}")
                if fix
                else printer.dim("no fix yet")
            )
            printer.line(
                f"  {marker} {finding.get('package', '?')}@{finding.get('version', '?')}"
                f"  {printer.dim(finding.get('cve', ''))}  {fix_text}"
            )

    for warning in result.warnings:
        printer.line()
        printer.line(printer.yellow(f"  Note: {warning}"))

    if result.dashboard_url:
        printer.line()
        printer.line(printer.dim(f"  {result.dashboard_url}"))
    printer.line()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_scan(args: argparse.Namespace, printer: Printer) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        printer.line(printer.red(f"No such path: {root}"))
        return EXIT_ERROR

    if root.is_file():
        manifest = root
    else:
        found = find_manifest(root)
        if found is None:
            printer.line(printer.red(f"No manifest found in {root}."))
            printer.line(printer.dim(f"Looked for: {supported_filenames()}"))
            return EXIT_ERROR
        manifest = found[0]

    config = resolve(root, cli_key=args.api_key, cli_url=args.url)
    if not config.api_key:
        printer.line(printer.red("No API key."))
        printer.line(
            printer.dim(
                f"Set {ENV_API_KEY}, run `weedout init`, or pass --api-key. "
                "Create a key in Settings on your dashboard."
            )
        )
        return EXIT_ERROR

    if args.verbose:
        printer.line(printer.dim(f"Scanning {manifest}"))
        printer.line(printer.dim(f"Key from {config.key_source}"))
        printer.line(printer.dim(f"Endpoint {config.base_url}"))

    try:
        result = post_scan(config.base_url, config.api_key, manifest, timeout=args.timeout)
    except ApiError as exc:
        printer.line(printer.red(str(exc)))
        # Always 2. A scan that could not run is not a scan that found nothing,
        # and a pipeline must be able to tell those apart.
        return EXIT_ERROR

    _report(result, printer, manifest)

    if args.ci and result.blocking:
        printer.line(
            printer.red(
                f"Failing: {result.blocking} finding(s) at critical severity or "
                "confirmed exploitation."
            )
        )
        return EXIT_FINDINGS

    return EXIT_OK


def command_init(args: argparse.Namespace, printer: Printer) -> int:
    root = Path(args.path).resolve()
    target = root / CONFIG_FILENAME

    if target.exists() and not args.force:
        printer.line(printer.yellow(f"{target} already exists. Pass --force to overwrite."))
        return EXIT_ERROR

    api_key = args.api_key or os.environ.get(ENV_API_KEY, "")
    if not api_key:
        printer.line(printer.red("No API key to write."))
        printer.line(printer.dim(f"Pass --api-key, or set {ENV_API_KEY} and run this again."))
        return EXIT_ERROR

    try:
        write_config_file(target, api_key, args.url)
    except OSError as exc:
        printer.line(printer.red(f"Could not write {target}: {exc}"))
        return EXIT_ERROR

    printer.line(f"Wrote {target}")

    found = find_manifest(root)
    if found is not None:
        printer.line(printer.dim(f"Will scan {found[0].relative_to(root)}"))
    else:
        printer.line(
            printer.yellow(f"No manifest found here yet. Looked for: {supported_filenames()}")
        )

    printer.line()
    printer.line(printer.yellow("This file contains a credential. Add it to .gitignore."))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="weedout",
        description="Scan your dependencies for the CVEs that actually matter.",
    )
    parser.add_argument("--version", action="version", version=f"weedout {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a project's dependencies")
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="project directory, or a manifest file (default: current directory)",
    )
    scan.add_argument(
        "--ci",
        action="store_true",
        help="exit 1 if anything critical or actively exploited is found",
    )
    scan.add_argument("--api-key", default=None, help=f"overrides ${ENV_API_KEY}")
    scan.add_argument("--url", default=None, help=f"API base URL (default: {DEFAULT_BASE_URL})")
    scan.add_argument("--timeout", type=int, default=120, help="seconds to wait (default: 120)")
    scan.add_argument("-v", "--verbose", action="store_true", help="show what was chosen and why")
    scan.set_defaults(handler=command_scan)

    init = subparsers.add_parser("init", help=f"write a {CONFIG_FILENAME} config file")
    init.add_argument("path", nargs="?", default=".", help="project directory")
    init.add_argument("--api-key", default=None, help=f"defaults to ${ENV_API_KEY}")
    init.add_argument("--url", default=None, help="API base URL, if self-hosting")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(handler=command_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    printer = Printer()

    try:
        return args.handler(args, printer)
    except KeyboardInterrupt:
        printer.line()
        printer.line(printer.dim("Interrupted."))
        return EXIT_ERROR
    except Exception as exc:
        # An unhandled crash must exit 2, never 1.
        #
        # Left to propagate, Python exits 1 — which in this tool means
        # "critical vulnerabilities found". A bug in the client would then be
        # indistinguishable from a real finding: it would fail builds that are
        # fine, and, once someone stopped trusting the signal, be worked around
        # rather than reported. Traceback still goes to stderr so the bug is
        # reportable.
        import traceback

        traceback.print_exc()
        printer.line(printer.red(f"weedout failed unexpectedly: {exc}"))
        printer.line(printer.dim("This is a bug. Nothing was checked."))
        return EXIT_ERROR


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    run()
