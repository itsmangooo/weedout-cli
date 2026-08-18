"""weedout — the command-line client for Weedout.

Deliberately dependency-free. This gets installed into the same environment as
the project being built, so anything it brings with it is a version constraint
somebody else has to satisfy.
"""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    # Read from the installed distribution rather than repeating the number
    # here. `pyproject.toml` is the single source of truth: a release that
    # bumped one and not the other would ship a wheel whose own `--version`
    # lied about which wheel it was.
    __version__ = version("weedout-cli")
except PackageNotFoundError:  # pragma: no cover - only in an uninstalled tree
    # Running from a source checkout that was never installed, not even with
    # `pip install -e .`. Anything published has metadata, so this value should
    # never reach a user; it is deliberately obvious rather than a plausible
    # number somebody might trust.
    __version__ = "0.0.0+source"
