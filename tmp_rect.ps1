$sig = @'
using System; using System.Runtime.InteropServices;
public class WR {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetDesktopWindow();
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  public struct RECT { public int Left,Top,Right,Bottom; }
}
'@
Add-Type $sig
$h=[System.IntPtr]4260710
$r=New-Object WR+RECT
[WR]::GetWindowRect($h,[ref]$r)|Out-Null
Write-Output "bounds: L=$($r.Left) T=$($r.Top) R=$($r.Right) B=$($r.Bottom) w=$($r.Right-$r.Left) h=$($r.Bottom-$r.Top)"
Write-Output "parent: $([WR]::GetParent($h))"
