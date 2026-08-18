"""weedout — the command-line client for Weedout.

Deliberately dependency-free. This gets installed into the same environment as
the project being built, so anything it brings with it is a version constraint
somebody else has to satisfy.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
