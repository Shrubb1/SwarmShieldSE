$sig = @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class WD {
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
}
'@
Add-Type $sig
$p = Get-Process swarm_gui -ErrorAction SilentlyContinue
if(!$p){Write-Output 'gone';exit}
$h=$p.MainWindowHandle
Write-Output "parent=$h title='$($p.MainWindowTitle)' vis=$([WD]::IsWindowVisible($h))"
$kids=@()
$cb=[WD+EnumWindowsProc]{param($wh,$l)
  $sb=New-Object System.Text.StringBuilder 100;[WD]::GetClassName($wh,$sb,100)|Out-Null
  $script:kids+=$sb.ToString(); return $true}
[WD]::EnumChildWindows($h,$cb,[IntPtr]::Zero)|Out-Null
Write-Output "children: $($kids -join ', ')"
