param([string]$PreviewPath)
$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'tests\ResultRows.exe'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
try {
    $sources = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName
    & $compiler /nologo /target:exe /platform:x64 /main:ResultRows /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$binary" $sources (Join-Path $PSScriptRoot 'tests\ResultRows.cs')
    if ($LASTEXITCODE -ne 0) {throw 'Result test compilation failed'}
    if ($PreviewPath) {& $binary $PreviewPath} else {& $binary}
    if ($LASTEXITCODE -ne 0) {throw 'Result tests failed'}
} finally {if(Test-Path -LiteralPath $binary){Remove-Item -LiteralPath $binary}}
