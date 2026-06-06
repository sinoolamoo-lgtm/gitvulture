@echo off
REM ======================================================================
REM GitVulture - Universal Installer for Windows 10/11
REM Double-click this file. It will install Python + Git via winget,
REM clone the repo, install dependencies, write the LLM key and create
REM a launcher. Handles 99 percent of common failures automatically.
REM ======================================================================

setlocal EnableDelayedExpansion EnableExtensions
title GitVulture Installer
color 0A

echo.
echo ============================================================
echo               G i t V u l t u r e
echo        One-Click Installer for Windows 10 / 11
echo  .git exposure exploitation framework  +  AI strict-mode
echo ============================================================
echo.

REM ---- configuration ----
set "REPO_URL=https://github.com/sinoolamoo-lgtm/gitvulture.git"
set "INSTALL_DIR=%USERPROFILE%\gitvulture"
set "LLM_ENV_FILE=%USERPROFILE%\.gitvulture\config.env"
set "EMERGENT_LLM_KEY=sk-emergent-07c12D71306386c4d9"
set "EMERGENT_INDEX=https://d33sy5i8bnduwe.cloudfront.net/simple/"
set "EXITCODE=0"

REM ---- step 1: check winget ----
echo === 1/8 Checking Windows Package Manager (winget) ===
where winget >nul 2>&1
if errorlevel 1 (
    echo [!] winget is not available on this system.
    echo     Install "App Installer" from the Microsoft Store, then re-run.
    echo     Or install manually:
    echo       Python 3.10+        https://python.org/downloads/
    echo       Git for Windows     https://git-scm.com/download/win
    set EXITCODE=1
    goto end
)
echo [OK] winget is available

REM ---- step 2: install Python if missing ----
echo.
echo === 2/8 Checking Python 3.10+ ===
where python >nul 2>&1
if errorlevel 1 (
    echo Python not found. Installing via winget...
    winget install -e --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements --scope user
    call :refresh_path
)
where python >nul 2>&1
if errorlevel 1 (
    echo [X] Python install failed.
    echo     Install manually from https://python.org/downloads/ and re-run.
    set EXITCODE=1
    goto end
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo [OK] %PYVER%

REM ---- step 3: install Git if missing ----
echo.
echo === 3/8 Checking Git ===
where git >nul 2>&1
if errorlevel 1 (
    echo Git not found. Installing via winget...
    winget install -e --id Git.Git --silent --accept-source-agreements --accept-package-agreements
    call :refresh_path
)
where git >nul 2>&1
if errorlevel 1 (
    echo [X] Git install failed.
    echo     Install manually from https://git-scm.com/download/win and re-run.
    set EXITCODE=1
    goto end
)
for /f "tokens=*" %%v in ('git --version 2^>^&1') do set "GITVER=%%v"
echo [OK] %GITVER%

REM ---- step 4: clone or update repo ----
echo.
echo === 4/8 Fetching GitVulture source ===
if exist "%INSTALL_DIR%\.git" (
    echo Pulling latest changes...
    pushd "%INSTALL_DIR%"
    git pull --ff-only
    popd
) else (
    if exist "%INSTALL_DIR%" (
        echo [!] %INSTALL_DIR% exists but is not a git repo - renaming
        ren "%INSTALL_DIR%" "gitvulture.bak.%RANDOM%"
    )
    git clone --depth 1 "%REPO_URL%" "%INSTALL_DIR%"
    if errorlevel 1 (
        echo [X] git clone failed. Check your internet connection.
        set EXITCODE=1
        goto end
    )
)
echo [OK] Source at %INSTALL_DIR%

REM ---- step 5: create venv ----
echo.
echo === 5/8 Creating Python virtualenv ===
set "VENV_DIR=%INSTALL_DIR%\.venv"
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [X] venv creation failed.
        set EXITCODE=1
        goto end
    )
)
call "%VENV_DIR%\Scripts\activate.bat"
echo [OK] venv ready

REM ---- step 6: install Python deps ----
echo.
echo === 6/8 Installing GitVulture (1-3 min) ===
python -m pip install -U pip wheel setuptools >nul 2>&1
echo Fetching emergentintegrations from Emergent's index...
pip install --extra-index-url %EMERGENT_INDEX% emergentintegrations==0.2.0
if errorlevel 1 (
    echo [X] emergentintegrations install failed.
    set EXITCODE=1
    goto end
)
pushd "%INSTALL_DIR%"
pip install --extra-index-url %EMERGENT_INDEX% -e .
if errorlevel 1 (
    echo [X] pip install -e . failed.
    popd
    set EXITCODE=1
    goto end
)
popd
echo [OK] Installed

REM ---- step 7: write LLM key + create launcher ----
echo.
echo === 7/8 Configuring LLM key and launcher ===
if not exist "%USERPROFILE%\.gitvulture\" mkdir "%USERPROFILE%\.gitvulture"
> "%LLM_ENV_FILE%" echo # GitVulture configuration - auto-loaded by the launcher on every run.
>>"%LLM_ENV_FILE%" echo EMERGENT_LLM_KEY=%EMERGENT_LLM_KEY%
icacls "%LLM_ENV_FILE%" /inheritance:r /grant:r "%USERNAME%:F" >nul 2>&1
echo [OK] LLM key saved to %LLM_ENV_FILE%

set "LAUNCHER=%USERPROFILE%\gitvulture.bat"
> "%LAUNCHER%" echo @echo off
>>"%LAUNCHER%" echo REM GitVulture launcher - loads config.env then invokes the venv'd CLI
>>"%LAUNCHER%" echo if exist "%LLM_ENV_FILE%" ^(
>>"%LAUNCHER%" echo     for /f "usebackq tokens=2 delims==" %%%%A in ^(`findstr /b /c:"EMERGENT_LLM_KEY=" "%LLM_ENV_FILE%"`^) do set "EMERGENT_LLM_KEY=%%%%A"
>>"%LAUNCHER%" echo ^)
>>"%LAUNCHER%" echo call "%VENV_DIR%\Scripts\activate.bat"
>>"%LAUNCHER%" echo gitvulture %%*
echo [OK] Launcher created at %LAUNCHER%

REM Optional: copy to a folder on PATH
set "BIN_DIR=%USERPROFILE%\AppData\Local\Microsoft\WindowsApps"
if exist "%BIN_DIR%\" (
    copy /Y "%LAUNCHER%" "%BIN_DIR%\gitvulture.bat" >nul 2>&1
    echo [OK] Also installed to %BIN_DIR%\gitvulture.bat (on your PATH)
)

REM ---- step 8: smoke test ----
echo.
echo === 8/8 Verifying installation ===
"%VENV_DIR%\Scripts\gitvulture.exe" --help >nul 2>&1
if errorlevel 1 (
    REM Fall back to module invocation if the entry point isn't registered
    "%VENV_DIR%\Scripts\python.exe" -m gitvulture.cli --help >nul 2>&1
    if errorlevel 1 (
        echo [X] Smoke test failed.
        set EXITCODE=1
        goto end
    )
)
echo [OK] gitvulture --help works

REM ---- done ----
echo.
color 0B
echo ===============================================================
echo                  INSTALLATION COMPLETE
echo ===============================================================
echo.
echo Quick tests (open a NEW CMD/PowerShell window first):
echo     gitvulture --help
echo     gitvulture --list-targets
echo     gitvulture --interactive
echo     gitvulture https://my-lab.example.com --insecure --i-have-permission
echo     gitvulture https://my-lab.example.com --ai --exploit-roadmap -vv
echo.
echo Storage layout (sqlmap-style):
echo     %%USERPROFILE%%\.gitvulture\output\HOST\TIMESTAMP\
echo.
echo Installed paths:
echo     Source        %INSTALL_DIR%
echo     Virtualenv    %VENV_DIR%
echo     LLM key       %LLM_ENV_FILE%
echo     Launcher      %LAUNCHER%
echo.
echo Reminder: use only on assets you own or are authorised to test.
echo Pass --i-have-permission and --scope HOST to make your intent explicit.
echo.

:end
echo.
pause
endlocal
exit /b %EXITCODE%

REM ---- helper: refresh PATH from registry ----
:refresh_path
for /f "tokens=2*" %%a in ('reg query HKCU\Environment /v PATH 2^>nul') do set "USER_PATH=%%b"
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "SYS_PATH=%%b"
set "PATH=%SYS_PATH%;%USER_PATH%"
goto :eof
