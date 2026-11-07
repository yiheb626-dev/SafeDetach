param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not $OutputDirectory){$OutputDirectory=Join-Path $projectRoot 'release'}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = Join-Path $OutputDirectory 'SafeDetach.exe'
$sources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') -Filter '*.cs' | ForEach-Object FullName
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/win32manifest:$projectRoot\src\app.manifest" "/out:$output" $sources
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
Write-Output "Built: $output"
