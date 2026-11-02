@echo off
REM SwarmShieldSE — no-admin install: copies the release binary and
REM registers a Startup entry so it runs on every login until removed.
REM Usage: install.bat [listen:target ...]   (default 9101:8081)
setlocal
set EXE=%~dp0target\release\swarmshield.exe
if not exist "%EXE%" (
  echo building release binary...
  cargo build --release --bin swarmshield || exit /b 1
)
set RULES=%*
if "%RULES%"=="" set RULES=9101:8081
set BAT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\swarmshield.bat
(
  echo @echo off
  echo title SwarmShieldSE - live protection
  echo "%EXE%" %RULES% -q
) > "%BAT%"
echo installed: %BAT%
echo   rules: %RULES%
echo   starts on next login; delete that file to uninstall.
echo.
echo For a true Windows service (runs without a terminal, boots with
echo the OS, no user login needed):
echo   1. open an ELEVATED terminal (admin)
echo   2. sc create SwarmShieldSE binPath= "%~dp0target\release\swarm_svc.exe %RULES%" start= auto
echo   3. sc start SwarmShieldSE
echo Uninstall: sc stop SwarmShieldSE ^&^& sc delete SwarmShieldSE
echo Linux:   deploy\swarmshield.service  → /etc/systemd/system/
echo macOS:   deploy\dev.swarmshield.plist → ~/Library/LaunchAgents/
endlocal
