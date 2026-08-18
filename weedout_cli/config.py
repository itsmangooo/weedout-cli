"""Where the API key and endpoint come from.

Resolution order, highest first:

1. ``--api-key`` on the command line
2. ``WEEDOUT_API_KEY`` in the environment
3. ``api_key`` in a ``.weedout`` file, searched from the current directory upward

The environment beating the file is the important one. CI systems inject
secrets as environment variables, and a `.weedout` accidentally committed to the
repository must never quietly override the key the pipeline was configured
with — a build that authenticates as the wrong account is far worse than one
that fails to authenticate at all.

``.weedout`` is a flat ``key = value`` file rather than TOML or YAML: it holds
two settings, and depending on a parser to read them would put a dependency in
a CI runner for no benefit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CONFIG_FILENAME", "Config", "find_config_file", "read_config_file", "resolve"]

CONFIG_FILENAME = ".weedout"
DEFAULT_BASE_URL = "https://weedout.dev"

ENV_API_KEY = "WEEDOUT_API_KEY"
ENV_BASE_URL = "WEEDOUT_URL"

#: How far up the tree the search for `.weedout` goes.
#:
#: Bounded so that running the CLI in a temporary directory cannot pick up a
#: stray config from somewhere near the filesystem root.
MAX_PARENTS = 6


@dataclass(frozen=True, slots=True)
class Config:
    api_key: str | None
    base_url: str
    #: Where the key came from, so `weedout scan` can say so. A developer
    #: debugging "wrong project" needs to know which of three places won.
    key_source: str


def find_config_file(start: Path) -> Path | None:
    """The nearest `.weedout`, searching upward from `start`."""
    current = start.resolve()
    for _ in range(MAX_PARENTS + 1):
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def read_config_file(path: Path) -> dict[str, str]:
    """Parse a `.weedout` file. Unreadable or malformed lines are skipped.

    A broken config must not crash the scan — it degrades to "no key found
    there", and the caller reports that in terms the user can act on.
    """
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return values

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator:
            continue
        values[name.strip().lower()] = value.strip().strip("\"'")
    return values


def resolve(
    start: Path,
    cli_key: str | None = None,
    cli_url: str | None = None,
    env: dict[str, str] | None = None,
) -> Config:
    """Work out the key and endpoint for this invocation."""
    env = os.environ if env is None else env

    file_values: dict[str, str] = {}
    config_path = find_config_file(start)
    if config_path is not None:
        file_values = read_config_file(config_path)

    if cli_key:
        api_key, source = cli_key, "--api-key"
    elif env.get(ENV_API_KEY):
        api_key, source = env[ENV_API_KEY], ENV_API_KEY
    elif file_values.get("api_key"):
        api_key, source = file_values["api_key"], str(config_path)
    else:
        api_key, source = None, "nowhere"

    base_url = (
        cli_url
        or env.get(ENV_BASE_URL)
        or file_values.get("url")
        or file_values.get("base_url")
        or DEFAULT_BASE_URL
    )

    return Config(
        api_key=api_key.strip() if api_key else None,
        base_url=base_url.strip().rstrip("/"),
        key_source=source,
    )


def write_config_file(path: Path, api_key: str, base_url: str | None = None) -> None:
    """Write a `.weedout`, with a warning about what it now contains."""
    lines = [
        "# Weedout project configuration.",
        "#",
        "# This file holds a credential. Add it to .gitignore: a key committed",
        "# to a repository is a key anyone who can read the repository has.",
        "# In CI, prefer the WEEDOUT_API_KEY environment variable, which takes",
        "# precedence over this file.",
        "",
        f"api_key = {api_key}",
    ]
    if base_url and base_url != DEFAULT_BASE_URL:
        lines.append(f"url = {base_url}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
