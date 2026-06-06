# GitVulture installer for Windows (PowerShell 5.1+ / 7+)
# Run:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Quiet
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Venv "C:\tools\gv-venv"

param(
    [switch]$Quiet,
    [string]$Venv = "$env:USERPROFILE\.gitvulture\venv",
    [string]$BinDir = "$env:USERPROFILE\.gitvulture\bin",
    [string]$DefaultKey = "sk-emergent-07c12D71306386c4d9"
)

$ErrorActionPreference = "Stop"
function Say($m)   { Write-Host "[gitvulture] $m" -ForegroundColor Cyan }
function Ok($m)    { Write-Host "[ ok ] $m"      -ForegroundColor Green }
function Warn($m)  { Write-Host "[warn] $m"      -ForegroundColor Yellow }
function Fail($m)  { Write-Host "[fail] $m"      -ForegroundColor Red; exit 1 }

# ---------- 1. Pre-flight ----------
Say "checking prerequisites..."
try {
    $pyVersion = (& python --version) 2>&1
} catch { Fail "Python not found. Install Python 3.10+ from python.org first." }
if ($pyVersion -notmatch "Python (\d+)\.(\d+)") {
    Fail "Could not parse Python version: $pyVersion"
}
$pyMaj = [int]$Matches[1]; $pyMin = [int]$Matches[2]
if ($pyMaj -lt 3 -or ($pyMaj -eq 3 -and $pyMin -lt 10)) {
    Fail "Python 3.10+ required (found $pyVersion)"
}
Ok "$pyVersion"

# ---------- 2. venv ----------
$venvParent = Split-Path $Venv -Parent
if (-not (Test-Path $venvParent)) { New-Item -ItemType Directory -Path $venvParent | Out-Null }
if (-not (Test-Path $Venv)) {
    Say "creating venv at $Venv"
    & python -m venv $Venv
}
$pyExe = Join-Path $Venv "Scripts\python.exe"
$pipExe = Join-Path $Venv "Scripts\pip.exe"
& $pyExe -m pip install --upgrade pip setuptools wheel | Out-Null
Ok "venv ready"

# ---------- 3. Install package ----------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Say "installing gitvulture from $scriptDir"
try {
    & $pipExe install `
        --extra-index-url "https://d33sy5i8bnduwe.cloudfront.net/simple/" `
        -e $scriptDir 2>$null | Out-Null
} catch {
    & $pipExe install -e $scriptDir | Out-Null
}
Ok "gitvulture installed (editable)"

# ---------- 4. Embed EMERGENT_LLM_KEY ----------
$cfgDir = "$env:USERPROFILE\.gitvulture"
$cfgFile = Join-Path $cfgDir "config.env"
if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir | Out-Null }

if ((Test-Path $cfgFile) -and (Select-String -Path $cfgFile -Pattern "EMERGENT_LLM_KEY" -Quiet)) {
    Ok "existing config found at $cfgFile — leaving in place"
} else {
    if ($Quiet) {
        $key = $DefaultKey
    } else {
        Write-Host ""
        Write-Host "EMERGENT LLM KEY (universal key for Claude/Gemini/OpenAI)" -ForegroundColor Yellow
        Write-Host "Press ENTER to use the bundled default key, or paste your own."
        $userKey = Read-Host "key [$DefaultKey]"
        if ([string]::IsNullOrWhiteSpace($userKey)) { $key = $DefaultKey } else { $key = $userKey }
    }
    Set-Content -Path $cfgFile -Value @"
# GitVulture configuration — auto-loaded by the launcher on every run.
EMERGENT_LLM_KEY=$key
"@ -Encoding UTF8
    # Lock perms (current user only)
    icacls $cfgFile /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    Ok "wrote $cfgFile (user-only ACL)"
}

# ---------- 5. Wrapper .cmd ----------
if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir | Out-Null }
$launcher = Join-Path $BinDir "gitvulture.cmd"
$launcherContent = @"
@echo off
REM GitVulture launcher — loads config.env then invokes the venv'd CLI.
if exist "$cfgFile" (
    for /f "usebackq tokens=2 delims==" %%A in (`findstr /b /c:"EMERGENT_LLM_KEY=" "$cfgFile"`) do set "EMERGENT_LLM_KEY=%%A"
)
set "PYTHONUNBUFFERED=1"
set "PYTHONIOENCODING=utf-8"
"$pyExe" -u -m gitvulture.cli %*
"@
Set-Content -Path $launcher -Value $launcherContent -Encoding ASCII
Ok "installed launcher at $launcher"

# ---------- 6. PATH ----------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    Warn "$BinDir is NOT on your PATH"
    if (-not $Quiet) {
        $ans = Read-Host "Add to user PATH automatically? (Y/n)"
        if ($ans -ne "n") {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
            Ok "added $BinDir to PATH — open a NEW terminal to use 'gitvulture'"
        }
    } else {
        Write-Host "  add to user PATH yourself:"
        Write-Host "  setx PATH `"$userPath;$BinDir`""
    }
}

# ---------- 7. Smoke test ----------
Say "smoke test..."
$null = & $pyExe -m gitvulture.cli --help 2>$null
if ($LASTEXITCODE -eq 0) { Ok "gitvulture --help passes" } else { Fail "smoke test failed" }

# ---------- 8. Done ----------
Write-Host ""
Write-Host "gitvulture installed." -ForegroundColor Green
Write-Host "  binary:   $launcher"
Write-Host "  config:   $cfgFile"
Write-Host "  venv:     $Venv"
Write-Host ""
Write-Host "  Try:  gitvulture --help"               -ForegroundColor Cyan
Write-Host "        gitvulture --interactive"         -ForegroundColor Cyan
Write-Host "        gitvulture https://target.tld/ --insecure --i-have-permission" -ForegroundColor Cyan
