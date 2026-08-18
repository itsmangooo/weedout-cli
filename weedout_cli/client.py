"""Talking to the scan API, using only the standard library.

`urllib` rather than `requests` or `httpx` on purpose. This package gets
installed into the same environment as the project being built, often by a
`pip install` in a CI step that also installs the project's own dependencies.
A client library here is a version constraint that can conflict with the
project's, to solve a problem that is one POST request wide.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

__all__ = ["ApiError", "ScanResult", "post_scan"]

USER_AGENT = "weedout-cli"

#: Generous, because the caller is a pipeline that would rather wait than
#: retry. The server does no outbound HTTP during a scan, so a slow response
#: means a large lockfile, not a stalled upstream.
DEFAULT_TIMEOUT = 120


class ApiError(Exception):
    """The API refused the request, or could not be reached.

    Carries the server's machine-readable code when there was one, so the
    caller can distinguish "your key is wrong" from "the service is down"
    without matching on prose.
    """

    def __init__(self, message: str, code: str = "", status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The parsed scan response."""

    project: str
    dependencies_scanned: int
    actionable: int
    suppressed: int
    new: int
    resolved: int
    counts: dict[str, int]
    findings: list[dict]
    warnings: list[str]
    dashboard_url: str

    @property
    def critical(self) -> int:
        return self.counts.get("critical", 0)

    @property
    def exploited(self) -> int:
        return self.counts.get("exploited", 0)

    @property
    def blocking(self) -> int:
        """What `--ci` fails on: critical severity or confirmed exploitation.

        Counted from the findings list rather than by adding two counters —
        a finding that is both critical *and* exploited is one problem, and
        summing would report it twice.
        """
        return len(
            [f for f in self.findings if f.get("severity") == "critical" or f.get("exploited")]
        )

    @classmethod
    def from_json(cls, payload: dict) -> ScanResult:
        return cls(
            project=payload.get("project", ""),
            dependencies_scanned=payload.get("dependencies_scanned", 0),
            actionable=payload.get("actionable", 0),
            suppressed=payload.get("suppressed", 0),
            new=payload.get("new", 0),
            resolved=payload.get("resolved", 0),
            counts=payload.get("counts") or {},
            findings=payload.get("findings") or [],
            warnings=payload.get("warnings") or [],
            dashboard_url=payload.get("dashboard_url", ""),
        )


def _multipart(field: str, path: Path, content: bytes) -> tuple[bytes, str]:
    """Encode one file as a multipart/form-data body.

    Hand-rolled because it is fifteen lines and the alternative is a
    dependency. The boundary is random so it cannot appear in the payload by
    coincidence.
    """
    boundary = f"----weedout{secrets.token_hex(16)}"
    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="{field}"; filename="{path.name}"\r\n'
            ).encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            content,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


def post_scan(
    base_url: str, api_key: str, path: Path, timeout: int = DEFAULT_TIMEOUT
) -> ScanResult:
    """Upload a manifest and return the scan result."""
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ApiError(f"Could not read {path}: {exc}", code="unreadable_file") from exc

    body, content_type = _multipart("manifest", path, content)

    request = urllib.request.Request(  # noqa: S310 - scheme validated below
        url=f"{base_url.rstrip('/')}/api/v1/scan",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": content_type,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    if request.type not in ("http", "https"):
        raise ApiError(f"Unsupported URL scheme: {request.type}", code="bad_url")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise _from_http_error(exc) from exc
    except urllib.error.URLError as exc:
        raise ApiError(f"Could not reach {base_url}: {exc.reason}", code="unreachable") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(
            "The server sent a response that was not JSON.", code="bad_response"
        ) from exc

    return ScanResult.from_json(payload)


def _from_http_error(exc: urllib.error.HTTPError) -> ApiError:
    """Turn an HTTP error into an ApiError, preferring the server's own words."""
    code = ""
    message = ""
    try:
        payload = json.loads(exc.read().decode("utf-8"))
        if isinstance(payload, dict):
            code = str(payload.get("error", ""))
            message = str(payload.get("message") or payload.get("error", ""))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        # A proxy or load balancer between here and the API will return HTML.
        # That is still a real error and the caller must hear about it, so the
        # fallback message below covers it rather than this becoming a crash
        # inside the error handler.
        pass

    if not message:
        message = _FALLBACK_MESSAGES.get(exc.code, f"The server returned HTTP {exc.code}.")

    return ApiError(message, code=code, status=exc.code)


_FALLBACK_MESSAGES = {
    401: "That API key was not accepted. Check WEEDOUT_API_KEY, or create a new key in Settings.",
    403: "That key is not allowed to do this.",
    404: "No scan endpoint at that URL. Check the configured address.",
    413: "That file is too large to scan.",
    429: "Too many scans for this project right now. Try again shortly.",
    503: "The scan could not be completed. Nothing was checked; this is not a clean result.",
}
