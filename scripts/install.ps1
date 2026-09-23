# envscanner — source installer (Windows)
#
# Usage (PowerShell):
#   iwr -useb https://raw.githubusercontent.com/Se-ve-n/envscanner/main/scripts/install.ps1 | iex
#
# Or from a local clone:
#   .\scripts\install.ps1
#
[CmdletBinding()]
param(
    [string]$Branch = "main",
    [string]$InstallDir = "$env:LOCALAPPDATA\envscanner\bin"
)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/Se-ve-n/envscanner"
$BuildDir = Join-Path $env:TEMP "envscanner-build-$([guid]::NewGuid().ToString('N'))"

function Log($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "[x] $msg" -ForegroundColor Red; exit 1 }

# --- Prereqs ---
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Die "cargo not found. Install Rust: https://rustup.rs"
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Die "git not found."
}

try {
    # --- Fetch source ---
    Log "Cloning $RepoUrl ($Branch)"
    git clone --depth 1 --branch $Branch $RepoUrl $BuildDir
    if ($LASTEXITCODE -ne 0) { Die "git clone failed" }

    # --- Build ---
    Log "Building release binary (this may take a minute)"
    Push-Location $BuildDir
    try {
        cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { Die "cargo build failed" }
    } finally {
        Pop-Location
    }

    # --- Install ---
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $BuildDir "target\release\envscanner.exe") (Join-Path $InstallDir "envscanner.exe") -Force
    Log "Installed to $InstallDir\envscanner.exe"

    # --- PATH ---
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Warn "$InstallDir is not on your user PATH."
        Warn "Adding it now (User scope)."
        $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Warn "Open a new terminal for the PATH change to take effect."
    }

    Log "Done. Run: envscanner --version"
}
finally {
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
}