"""Finding the file to scan.

The rule is "prefer the file that says what is actually installed". A
`package-lock.json` records resolved versions; a `package.json` records the
ranges a resolver was asked to satisfy. Scanning the range means guessing at
the floor it permits, and the guess is labelled as one in the dashboard — but a
lockfile removes the guess entirely, so when both are present the lockfile
wins.

Detection is by filename, matching what the server accepts. The server does the
parsing; duplicating that here would mean two implementations of "is this a
valid manifest" that have to agree forever, and the one in the CI runner would
be the one nobody notices has drifted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["CANDIDATES", "Candidate", "find_all_manifests", "find_manifest"]


@dataclass(frozen=True, slots=True)
class Candidate:
    """One recognised manifest filename."""

    filename: str
    ecosystem: str
    #: Lower sorts first. A lockfile outranks the manifest it was resolved from.
    rank: int
    locked: bool


#: In preference order. Kept in one list so `weedout scan` and the error
#: message that lists what it looked for can never disagree.
CANDIDATES: tuple[Candidate, ...] = (
    Candidate("package-lock.json", "npm", 0, locked=True),
    Candidate("package.json", "npm", 1, locked=False),
    Candidate("requirements.txt", "PyPI", 0, locked=False),
    Candidate("go.mod", "Go", 0, locked=False),
)

#: Directories never worth walking into. `node_modules` in particular contains
#: a `package.json` for every installed package — thousands of files, none of
#: which describes the project being built.
SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "vendor",
        "venv",
        "env",
        "dist",
        "build",
        "target",
        "site-packages",
    }
)

#: How deep the search goes below the starting directory.
#:
#: Deliberately shallow. A repository root is where a manifest lives; walking
#: an entire monorepo would make `weedout scan` pick an arbitrary sub-package
#: and report on the wrong thing, which is worse than reporting nothing.
MAX_DEPTH = 2


def _candidate_for(path: Path) -> Candidate | None:
    for candidate in CANDIDATES:
        if path.name == candidate.filename:
            return candidate
    return None


def find_all_manifests(root: Path, max_depth: int = MAX_DEPTH) -> list[tuple[Path, Candidate]]:
    """Every recognised manifest under `root`, in preference order.

    Sorted by rank, then by depth, then by path — so a lockfile at the root
    beats a lockfile in a subdirectory, and the result is stable rather than
    dependent on filesystem ordering.
    """
    root = root.resolve()
    found: list[tuple[Path, Candidate]] = []

    def walk(directory: Path, depth: int) -> None:
        try:
            entries = sorted(directory.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            if entry.is_dir():
                if depth < max_depth and entry.name not in SKIP_DIRECTORIES:
                    if not entry.name.startswith("."):
                        walk(entry, depth + 1)
                continue

            candidate = _candidate_for(entry)
            if candidate is not None:
                found.append((entry, candidate))

    walk(root, 0)

    def sort_key(item: tuple[Path, Candidate]) -> tuple[int, int, str]:
        path, candidate = item
        depth = len(path.relative_to(root).parts) - 1
        return (candidate.rank, depth, str(path))

    return sorted(found, key=sort_key)


def find_manifest(root: Path, max_depth: int = MAX_DEPTH) -> tuple[Path, Candidate] | None:
    """The single best manifest to scan, or None if there is nothing to scan."""
    matches = find_all_manifests(root, max_depth)
    return matches[0] if matches else None


def supported_filenames() -> str:
    """A human-readable list, for the "nothing found" message."""
    return ", ".join(candidate.filename for candidate in CANDIDATES)
