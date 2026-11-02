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
endlocal
