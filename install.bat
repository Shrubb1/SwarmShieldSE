@echo off
REM SwarmShieldSE install - desktop + Start Menu shortcuts, service,
REM and the background file scanner on every login.
setlocal
set RULES=9101:8081
echo installing SwarmShieldSE...
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\SwarmShieldSE.lnk');$s.TargetPath='%~dp0swarm_gui.exe';$s.Save();$m=(New-Object -COM WScript.Shell).CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\SwarmShieldSE.lnk');$m.TargetPath='%~dp0swarm_gui.exe';$m.Save()" 2>nul
echo   app:      %USERPROFILE%\Desktop\SwarmShieldSE.lnk
echo   startmenu: searchable as "SwarmShieldSE"

REM background file scanner on every login (silent, low priority)
set STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\swarm_scanner.bat
(
  echo @echo off
  echo title SwarmShieldSE - file scanner
  echo "%~dp0swarm_scanner.exe" -q
) > "%STARTUP%"
echo   scanner:  %STARTUP% (runs on login)

echo.
echo For the background service (runs without login):
echo   admin: sc create SwarmShieldSE binPath= "%~dp0swarmshield.exe %RULES%" start= auto
echo   then:  sc start SwarmShieldSE
echo.
start "" "%~dp0swarm_gui.exe"
