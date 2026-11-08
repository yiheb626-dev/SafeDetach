param([string]$AppPath)
$ErrorActionPreference='Stop'
if(-not $AppPath){$AppPath=Join-Path $PSScriptRoot 'release-1.4.2\SafeDetach.exe'}
$app=(Resolve-Path -LiteralPath $AppPath).Path
$binary=Join-Path $PSScriptRoot 'tests\ScanPerformance.exe'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
try {
    $sources=Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName
    & $compiler /nologo /target:exe /platform:x64 /main:ScanPerformance /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$binary" $sources (Join-Path $PSScriptRoot 'tests\ScanPerformance.cs')
    if($LASTEXITCODE -ne 0){throw 'Scan test build failed'}
    & $binary $app
    if($LASTEXITCODE -ne 0){throw 'Scan tests failed'}
}finally{if(Test-Path -LiteralPath $binary){Remove-Item -LiteralPath $binary}}
