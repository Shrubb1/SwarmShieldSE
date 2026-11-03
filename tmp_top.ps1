Add-Type '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetWindowPos(System.IntPtr h,System.IntPtr i,int x,int y,int cx,int cy,uint f);' -Name WT -Namespace UT
$h=[System.IntPtr]4260710
$TOPMOST=New-Object System.IntPtr -1
[UT.WT]::SetWindowPos($h,$TOPMOST,300,100,760,560,0x0040)|Out-Null
Write-Output 'topmost'
