# Install the Weedout CLI on Windows.
#
# Usage:
#
#   irm https://weedout.dev/install.ps1 | iex
#
# Or:
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Optional overrides:
#
#   $env:VERSION = "v1.2.0"
#   $env:INSTALL_DIR = "C:\Tools\weedout"
#   .\install.ps1
#
# What it does:
#   - detects Windows architecture
#   - resolves the latest GitHub release
#   - downloads the Windows executable
#   - downloads checksums.txt
#   - verifies SHA256
#   - installs weedout.exe
#   - tells you if the install directory is not on PATH

$ErrorActionPreference = "Stop"

$Repo = "itsmangooo/weedout-cli"
$Binary = "weedout.exe"

$Version = if ($env:VERSION) {
    $env:VERSION
} else {
    "latest"
}

$InstallDir = if ($env:INSTALL_DIR) {
    $env:INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA "Programs\weedout\bin"
}


function Say {
    param([string]$Message)

    Write-Host $Message
}


function Die {
    param([string]$Message)

    Write-Error $Message
    exit 1
}


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

function Get-Platform {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq "Core") {
        Die "this installer is for Windows only"
    }

    # PROCESSOR_ARCHITEW6432 is useful when a 32-bit PowerShell process is
    # running on 64-bit Windows.
    $arch = if ($env:PROCESSOR_ARCHITEW6432) {
        $env:PROCESSOR_ARCHITEW6432
    } else {
        $env:PROCESSOR_ARCHITECTURE
    }

    switch ($arch.ToUpperInvariant()) {
        "AMD64" {
            return "windows-amd64"
        }

        "ARM64" {
            return "windows-arm64"
        }

        default {
            Die @"
unsupported architecture: $arch

Prebuilt binaries cover amd64 and arm64.

For anything else:
  go install github.com/$Repo@latest
"@
        }
    }
}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

function Download-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    try {
        Invoke-WebRequest `
            -Uri $Url `
            -OutFile $Destination `
            -UseBasicParsing
    }
    catch {
        throw "failed to download $Url`: $($_.Exception.Message)"
    }
}


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

function Resolve-Version {
    if ($Version -ne "latest") {
        return $Version
    }

    $url = "https://github.com/$Repo/releases/latest"

    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.AllowAutoRedirect = $false
        $request.Method = "HEAD"

        $response = $request.GetResponse()

        try {
            $location = $response.Headers["Location"]
        }
        finally {
            $response.Close()
        }

        if ($location -match "/tag/([^/?#]+)$") {
            return $Matches[1]
        }

        Die @"
could not work out the latest version.

GitHub returned:
  $location

Pick one from:
  https://github.com/$Repo/releases

Then re-run with:

  `$env:VERSION = "vX.Y.Z"
  .\install.ps1
"@
    }
    catch {
        Die @"
could not work out the latest version.

$($_.Exception.Message)

Pick one from:
  https://github.com/$Repo/releases

Then re-run with:

  `$env:VERSION = "vX.Y.Z"
  .\install.ps1
"@
    }
}


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

function Verify-Checksum {
    param(
        [Parameter(Mandatory = $true)]
        [string]$File,

        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    try {
        $actual = (
            Get-FileHash `
                -Path $File `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    catch {
        Say "  ! could not calculate SHA256; skipping verification"
        return
    }

    $expectedNormalized = $Expected.ToLowerInvariant()

    if ($actual -ne $expectedNormalized) {
        Die @"
checksum mismatch.

  expected $expectedNormalized
  got      $actual

Not installing.

Please report this at:
  https://github.com/$Repo/issues
"@
    }

    Say "  checksum ok"
}


# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------

function Test-DirectoryOnPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $target = [System.IO.Path]::GetFullPath($Directory).TrimEnd("\")

    foreach ($entry in ($env:PATH -split ";")) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        try {
            $candidate = [System.IO.Path]::GetFullPath(
                [Environment]::ExpandEnvironmentVariables($entry)
            ).TrimEnd("\")

            if ($candidate -ieq $target) {
                return $true
            }
        }
        catch {
            # Ignore malformed PATH entries.
        }
    }

    return $false
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Main {
    $platform = Get-Platform
    $resolvedVersion = Resolve-Version

    $asset = "weedout-$platform.exe"
    $base = "https://github.com/$Repo/releases/download/$resolvedVersion"

    Say "Weedout CLI $resolvedVersion ($platform)"

    $tmp = Join-Path `
        ([System.IO.Path]::GetTempPath()) `
        ("weedout-" + [guid]::NewGuid().ToString("N"))

    New-Item `
        -ItemType Directory `
        -Path $tmp `
        -Force `
        | Out-Null

    try {
        $binaryPath = Join-Path $tmp $Binary
        $checksumPath = Join-Path $tmp "checksums.txt"

        $binaryUrl = "$base/$asset"
        $checksumUrl = "$base/checksums.txt"

        Say "  downloading $binaryUrl"

        try {
            Download-File `
                -Url $binaryUrl `
                -Destination $binaryPath
        }
        catch {
            Die @"
download failed.

Does $resolvedVersion have a $platform build?

See:
  https://github.com/$Repo/releases/tag/$resolvedVersion
"@
        }

        # -------------------------------------------------------------------
        # Checksum
        # -------------------------------------------------------------------

        try {
            Download-File `
                -Url $checksumUrl `
                -Destination $checksumPath

            $expected = $null

            foreach ($line in Get-Content $checksumPath) {
                # Typical format:
                #
                # SHA256  weedout-windows-amd64.exe
                #
                # Also accepts:
                #
                # SHA256 *weedout-windows-amd64.exe

                if ($line -match "^([a-fA-F0-9]{64})\s+\*?(.+)$") {
                    $hash = $Matches[1]
                    $fileName = $Matches[2].Trim()

                    if ($fileName -eq $asset) {
                        $expected = $hash
                        break
                    }
                }
            }

            if ($expected) {
                Verify-Checksum `
                    -File $binaryPath `
                    -Expected $expected
            }
            else {
                Say "  ! no checksum listed for $asset"
            }
        }
        catch {
            Say "  ! no checksums.txt in this release; skipping verification"
        }

        # -------------------------------------------------------------------
        # Install
        # -------------------------------------------------------------------

        try {
            New-Item `
                -ItemType Directory `
                -Path $InstallDir `
                -Force `
                | Out-Null
        }
        catch {
            Die "could not create $InstallDir"
        }

        $destination = Join-Path $InstallDir $Binary

        try {
            Move-Item `
                -Path $binaryPath `
                -Destination $destination `
                -Force
        }
        catch {
            Die @"
could not write to:

  $InstallDir

Either re-run with a writable location:

  `$env:INSTALL_DIR = "`$HOME\bin"
  .\install.ps1

or move weedout.exe somewhere on your PATH.
"@
        }

        Say "  installed to $destination"

        # -------------------------------------------------------------------
        # PATH
        # -------------------------------------------------------------------

        if (-not (Test-DirectoryOnPath -Directory $InstallDir)) {
            Say "  adding $InstallDir to user PATH"

            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")

            if ([string]::IsNullOrWhiteSpace($userPath)) {
                $newPath = $InstallDir
            }
            else {
                $entries = $userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $alreadyPresent = $false

                foreach ($entry in $entries) {
                    try {
                        $candidate = [System.IO.Path]::GetFullPath(
                            [Environment]::ExpandEnvironmentVariables($entry)
                        ).TrimEnd("\")

                        $target = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd("\")

                        if ($candidate -ieq $target) {
                            $alreadyPresent = $true
                            break
                        }
                    }
                    catch {
                        # Ignore malformed PATH entries.
                    }
                }

                if ($alreadyPresent) {
                    $newPath = $userPath
                }
                else {
                    $newPath = "$userPath;$InstallDir"
                }
            }

            [Environment]::SetEnvironmentVariable(
                "Path",
                $newPath,
                "User"
            )

            # Make weedout available immediately in this PowerShell session too.
            $env:Path = "$env:Path;$InstallDir"

            Say "  added to PATH"
        }

        Say ""
        Say "Next:"
        Say "  weedout init      save your API key to .weedout"
        Say "  weedout scan      scan this project"
    }
    finally {
        if (Test-Path $tmp) {
            Remove-Item `
                -Path $tmp `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
}


Main