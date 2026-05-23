#Requires -Version 5.1
<#
.SYNOPSIS
  cspm-scanner installer for Windows.

.EXAMPLE
  iwr -useb https://raw.githubusercontent.com/mohidev-tech/cspm-scanner/main/install.ps1 | iex

.PARAMETER Version
  Specific release tag (e.g. v0.2.0). Defaults to the latest release. Falls
  back to 'go install ...@latest' when no releases exist yet.

.PARAMETER InstallDir
  Directory to drop cspm.exe into. Defaults to %USERPROFILE%\.cspm\bin.
#>
[CmdletBinding()]
param(
  [string]$Version    = $env:CSPM_VERSION,
  [string]$InstallDir = (Join-Path $env:USERPROFILE ".cspm\bin")
)

$ErrorActionPreference = "Stop"
$repo = "mohidev-tech/cspm-scanner"

if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

# Detect arch
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $arch = "arm64" }

# Resolve latest version
if (-not $Version) {
  try {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
    $Version = $rel.tag_name
  } catch {
    Write-Host "==> No releases yet — using 'go install' fallback"
  }
}

if ($Version) {
  $stripped = $Version.TrimStart("v")
  $url = "https://github.com/$repo/releases/download/$Version/cspm_${stripped}_windows_${arch}.zip"
  Write-Host "==> Downloading $url"
  $tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("cspm-" + [Guid]::NewGuid()))
  try {
    $zip = Join-Path $tmp.FullName "cspm.zip"
    Invoke-WebRequest $url -OutFile $zip -UseBasicParsing
    Expand-Archive $zip -DestinationPath $tmp.FullName -Force
    Copy-Item (Join-Path $tmp.FullName "cspm.exe") (Join-Path $InstallDir "cspm.exe") -Force
  } finally {
    Remove-Item $tmp -Recurse -Force
  }
} else {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "go is required to install from source. Install Go from https://go.dev/dl/ first."
  }
  $env:GOBIN = $InstallDir
  & go install ("github.com/" + $repo + "/cmd/cspm@latest")
}

Write-Host "==> Installed: $InstallDir\cspm.exe"

# Suggest PATH update
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  Write-Host "==> Add $InstallDir to your User PATH. Run this once:"
  Write-Host "    [Environment]::SetEnvironmentVariable('Path', '$InstallDir;' + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
}

Write-Host ""
& "$InstallDir\cspm.exe" version
Write-Host ""
Write-Host "Try: cspm scan .\your\terraform"
