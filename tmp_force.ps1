Add-Type '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h); [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetWindowPos(System.IntPtr h,System.IntPtr i,int x,int y,int cx,int cy,uint f); [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h,int n);' -Name WF -Namespace UF
$h=[System.IntPtr]2884178
$tm=[System.IntPtr](-1)
[UF.WF]::ShowWindow($h,5)|Out-Null
[UF.WF]::SetWindowPos($h,$tm,400,120,700,540,0x0040)|Out-Null
[UF.WF]::SetForegroundWindow($h)|Out-Null
Write-Output 'forced'
