@echo off
REM SwarmShieldSE install — the FULL wire-up, all headless except
REM the app window: engine service, DNS guard (ad-block machine-wide),
REM watcher (downloads/startup/hosts/usb), weekly scanner.
REM Pro features stay LOCKED until a signed token activates them.
setlocal

REM self-elevate — service + DNS need admin
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo requesting admin...
  powershell -Command "Start-Process '%~f0' -Verb RunAs"
  exit /b
)

set EXE_DIR=%~dp0
set RULES=9101:8081
echo installing SwarmShieldSE...

REM engine service — hidden, survives reboot, no console
sc create SwarmShieldSE binPath= "%EXE_DIR%swarmshield.exe %RULES%" start= auto >nul 2>&1
sc start SwarmShieldSE >nul 2>&1
echo   engine service running

REM DNS → the guard — machine-wide ad-block on every app
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses 127.0.0.1 }" >nul 2>&1
echo   dns -> 127.0.0.1 (ad-block live)

REM hidden background tasks — no consoles, run on every login
schtasks /create /tn "SwarmShield-DnsGuard" /tr "\"%EXE_DIR%dns_guard.exe\"" /sc onlogon /rl highest /f >nul 2>&1
schtasks /create /tn "SwarmShield-Watcher" /tr "\"%EXE_DIR%swarm_watcher.exe\"" /sc onlogon /rl highest /f >nul 2>&1
schtasks /run /tn "SwarmShield-DnsGuard" >nul 2>&1
schtasks /run /tn "SwarmShield-Watcher" >nul 2>&1
echo   guard + watcher registered (hidden, on login)

REM app shortcuts — the ONE windowed piece
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\SwarmShieldSE.lnk');$s.TargetPath='%EXE_DIR%swarm_gui.exe';$s.Save();$m=(New-Object -COM WScript.Shell).CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\SwarmShieldSE.lnk');$m.TargetPath='%EXE_DIR%swarm_gui.exe';$m.Save()" >nul 2>&1
echo   app: desktop + start menu

echo.
echo done — protection is live. everything runs headless; only the
echo app window shows. Pro features stay locked until a signed token.
start "" "%EXE_DIR%swarm_gui.exe"
