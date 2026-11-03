@echo off
REM SwarmShieldSE — no-admin install: registers a Startup entry so
REM the guard runs on every login until removed.
REM Works out of the download zip: swarmshield.exe sits next to this.
setlocal
set EXE=%~dp0swarmshield.exe
if not exist "%EXE%" set EXE=%~dp0target\release\swarmshield.exe
if not exist "%EXE%" (
  echo swarmshield.exe not found next to install.bat
  exit /b 1
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
