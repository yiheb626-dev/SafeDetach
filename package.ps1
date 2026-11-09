param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot 'release'}
& (Join-Path $PSScriptRoot 'build.ps1') -OutputDirectory $OutputDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $OutputDirectory 'README.md') -Force
Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath (Join-Path $PSScriptRoot 'SafeDetach-win-x64.zip') -Force
$sourceItems = 'src','tests','README.md','build.ps1','test.ps1','test-recognition.ps1','test-results.ps1','test-portable.ps1','test-apple.ps1','test-scan.ps1','test-dpi.ps1','test-auto-scan.ps1','test-eject.ps1','package.ps1' | ForEach-Object { Join-Path $PSScriptRoot $_ }
Compress-Archive -Path $sourceItems -DestinationPath (Join-Path $PSScriptRoot 'SafeDetach-source.zip') -Force
Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'SafeDetach.exe'),(Join-Path $PSScriptRoot 'SafeDetach-win-x64.zip') -Algorithm SHA256
