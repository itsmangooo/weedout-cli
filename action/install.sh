#!/usr/bin/env bash
#
# Download the Weedout CLI for whatever this runner is, and verify it.
#
# A pre-built binary rather than `go install` or `pip install`: the action must
# work on a runner with neither toolchain, and a scan step that first builds a
# compiler's worth of dependencies is a scan step people remove.
#
# The checksum is not optional. This downloads an executable over the network
# and then runs it against the caller's source tree; verifying it against the
# published hash is the least this can do.

set -euo pipefail

REPO="itsmangooo/weedout-cli"
VERSION="${WEEDOUT_VERSION:-latest}"

die() {
  # ::error:: renders as an annotation on the run rather than a line in a log
  # nobody expands.
  echo "::error title=Weedout::$*"
  exit 1
}

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

case "${RUNNER_OS:-}" in
  Linux)   goos="linux"  ;;
  macOS)   goos="darwin" ;;
  Windows) goos="windows" ;;
  *)       die "Unsupported runner OS: ${RUNNER_OS:-unset}" ;;
esac

case "${RUNNER_ARCH:-}" in
  X64)   goarch="amd64" ;;
  ARM64) goarch="arm64" ;;
  *)     die "Unsupported runner architecture: ${RUNNER_ARCH:-unset}" ;;
esac

ext=""
[ "$goos" = "windows" ] && ext=".exe"

asset="weedout-${goos}-${goarch}${ext}"

# ---------------------------------------------------------------------------
# Which release
# ---------------------------------------------------------------------------

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  # Tolerate both "v0.1.0" and "0.1.0"; the tags carry the v.
  case "$VERSION" in
    v*) tag="$VERSION" ;;
    *)  tag="v${VERSION}" ;;
  esac
  base="https://github.com/${REPO}/releases/download/${tag}"
fi

dest="${RUNNER_TEMP:-/tmp}/weedout"
mkdir -p "$dest"

echo "Downloading ${asset} (${VERSION})"

# --fail so a 404 is an error rather than a saved HTML page that later fails to
# execute with a message about a syntax error in an ELF header.
curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  --output "${dest}/${asset}" "${base}/${asset}" \
  || die "No Weedout CLI release for ${goos}/${goarch} at ${VERSION}. See https://github.com/${REPO}/releases"

curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  --output "${dest}/checksums.txt" "${base}/checksums.txt" \
  || die "The release has no checksums.txt, so the download cannot be verified. Refusing to run it."

# ---------------------------------------------------------------------------
# Verify
#
# sha256sum exists on Linux and in Git Bash on Windows; macOS runners have
# shasum. Compare the hash ourselves rather than using `sha256sum -c`, because
# the checksum file names every platform's asset and -c would fail on the ones
# that are not present.
# ---------------------------------------------------------------------------

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${dest}/${asset}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${dest}/${asset}" | awk '{print $1}')"
else
  die "Neither sha256sum nor shasum is available, so the download cannot be verified."
fi

expected="$(awk -v want="$asset" '$2 == want || $2 == "*"want {print $1}' "${dest}/checksums.txt" | head -n1)"

[ -n "$expected" ] || die "checksums.txt does not mention ${asset}. Refusing to run an unverified binary."

if [ "$actual" != "$expected" ]; then
  die "Checksum mismatch for ${asset}: got ${actual}, expected ${expected}. Not running it."
fi

echo "Checksum verified: ${actual}"

chmod +x "${dest}/${asset}"
mv "${dest}/${asset}" "${dest}/weedout${ext}"

# Later steps in this composite action find it here.
echo "$dest" >> "$GITHUB_PATH"

"${dest}/weedout${ext}" version
