while ($true) {
  $ts = Get-Date -f 'yyyy-MM-dd HH:mm'
  $svc = (Get-Process swarm_svc -ErrorAction SilentlyContinue)
  $sh  = (Get-Process swarmshield -ErrorAction SilentlyContinue)
  $rss = @($svc,$sh) | ForEach-Object { $_.WorkingSet64/1MB } | Measure-Object -Sum | Select-Object -Expand Sum
  $feed = if (Test-Path 'C:\ProgramData\SwarmShieldSE\svc_feed.log') { (Get-Content 'C:\ProgramData\SwarmShieldSE\svc_feed.log' | Measure-Object -Line).Lines } else { 0 }
  "$ts rss_mb=$([math]::Round($rss,1)) svc=$(if($svc){'up'}else{'DOWN'}) shield=$(if($sh){'up'}else{'DOWN'}) feed_events=$feed" | Add-Content overnight.log
  Copy-Item 'C:\ProgramData\SwarmShieldSE\svc_feed.log' feed_snapshot.log -ErrorAction SilentlyContinue
  if (!$svc -and !$sh) { "$ts ALERT: guard processes gone" | Add-Content overnight.log }
  Start-Sleep 300
}
