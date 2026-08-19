#!/bin/sh
# Install the Weedout CLI.
#
#   curl -sSL https://weedout.dev/install.sh | sh
#
# POSIX sh, not bash: this runs inside CI images that ship dash or busybox ash
# and nothing else. No arrays, no [[ ]], no local -n.
#
# What it does, in order: work out your platform, ask GitHub for the latest
# release, download that binary and its published checksum, verify them, and
# move the result somewhere on your PATH.
#
# It is deliberately noisy about what it is doing. A script piped into a shell
# has every right to be distrusted, so it says which URL it fetched, which
# checksum it compared, and where it put the binary.

set -eu

REPO="itsmangooo/weedout-cli"
BINARY="weedout"

# Override to pin a version or install somewhere else:
#   VERSION=v1.2.0 INSTALL_DIR=~/bin sh install.sh
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "this script needs $1, which is not installed"
}

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

detect_platform() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="linux" ;;
        Darwin) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*)
            die "this script is for Linux and macOS.
On Windows, download weedout-windows-amd64.exe from
  https://github.com/$REPO/releases/latest
or install with Go:
  go install github.com/$REPO@latest" ;;
        *) die "unsupported operating system: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "unsupported architecture: $arch
Prebuilt binaries cover amd64 and arm64. For anything else:
  go install github.com/$REPO@latest" ;;
    esac

    printf '%s-%s' "$os" "$arch"
}

# ---------------------------------------------------------------------------
# Where to put it
#
# Preference order: an explicit INSTALL_DIR, then a directory already on PATH
# that is writable without sudo, then ~/.local/bin. Reaching for sudo
# unprompted is not this script's business.
# ---------------------------------------------------------------------------

choose_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        printf '%s' "$INSTALL_DIR"
        return
    fi
    for candidate in "$HOME/.local/bin" "/usr/local/bin" "$HOME/bin"; do
        if [ -d "$candidate" ] && [ -w "$candidate" ]; then
            printf '%s' "$candidate"
            return
        fi
    done
    printf '%s' "$HOME/.local/bin"
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

fetch() {
    # $1 url, $2 destination
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "this script needs curl or wget"
    fi
}

resolve_version() {
    if [ "$VERSION" != "latest" ]; then
        printf '%s' "$VERSION"
        return
    fi
    # The redirect from /releases/latest names the tag, which avoids parsing
    # the API's JSON with sed and avoids the unauthenticated rate limit.
    if command -v curl >/dev/null 2>&1; then
        resolved="$(curl -sSfL -o /dev/null -w '%{url_effective}' \
            "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')"
    else
        resolved="$(wget -qS --max-redirect=5 -O /dev/null \
            "https://github.com/$REPO/releases/latest" 2>&1 \
            | sed -n 's#.*/tag/##p' | tail -1 | tr -d '\r')"
    fi
    [ -n "$resolved" ] || die "could not work out the latest version.
Pick one from https://github.com/$REPO/releases and re-run with VERSION=vX.Y.Z"
    printf '%s' "$resolved"
}

verify() {
    # $1 file, $2 expected sha256. Skipped with a warning rather than failing
    # if no checksum tool is present — a missing sha256sum is a property of the
    # machine, not evidence the download is bad.
    file="$1"
    expected="$2"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | cut -d' ' -f1)"
    else
        say "  ! no sha256sum or shasum available; skipping verification"
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        die "checksum mismatch.
  expected $expected
  got      $actual
Not installing. Please report this at https://github.com/$REPO/issues"
    fi
    say "  checksum ok"
}

main() {
    need uname
    need sed

    platform="$(detect_platform)"
    version="$(resolve_version)"
    dir="$(choose_dir)"

    asset="weedout-${platform}"
    base="https://github.com/$REPO/releases/download/$version"

    say "Weedout CLI $version ($platform)"

    tmp="$(mktemp -d 2>/dev/null || mktemp -d -t weedout)"
    # Clean up on any exit, including the die paths above.
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "  downloading $base/$asset"
    fetch "$base/$asset" "$tmp/$BINARY" \
        || die "download failed. Does $version have a $platform build?
See https://github.com/$REPO/releases/tag/$version"

    # Checksums are published as one file for the whole release.
    if fetch "$base/checksums.txt" "$tmp/checksums.txt" 2>/dev/null; then
        expected="$(grep " $asset\$" "$tmp/checksums.txt" 2>/dev/null | cut -d' ' -f1 || true)"
        if [ -n "$expected" ]; then
            verify "$tmp/$BINARY" "$expected"
        else
            say "  ! no checksum listed for $asset"
        fi
    else
        say "  ! no checksums.txt in this release; skipping verification"
    fi

    chmod +x "$tmp/$BINARY"

    mkdir -p "$dir" || die "could not create $dir"
    if ! mv "$tmp/$BINARY" "$dir/$BINARY" 2>/dev/null; then
        die "could not write to $dir.
Either re-run with a writable location:
  INSTALL_DIR=\$HOME/.local/bin sh install.sh
or move it yourself:
  sudo mv $tmp/$BINARY /usr/local/bin/$BINARY"
    fi

    say "  installed to $dir/$BINARY"

    # Tell them if it will not be found, rather than letting the next command
    # fail with "weedout: not found".
    case ":$PATH:" in
        *":$dir:"*) ;;
        *)
            say ""
            say "  ! $dir is not on your PATH. Add it:"
            say "      export PATH=\"$dir:\$PATH\""
            ;;
    esac

    say ""
    say "Next:"
    say "  $BINARY init      save your API key to .weedout"
    say "  $BINARY scan      scan this project"
}

main "$@"
