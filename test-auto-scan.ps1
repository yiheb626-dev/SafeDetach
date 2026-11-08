$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$binary=Join-Path $PSScriptRoot 'tests\AutomaticScan.exe'
try {
    $sources=Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName
    & $compiler /nologo /target:exe /platform:x64 /main:AutomaticScan /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/win32manifest:$PSScriptRoot\src\app.manifest" "/out:$binary" $sources (Join-Path $PSScriptRoot 'tests\AutomaticScan.cs')
    if($LASTEXITCODE -ne 0){throw 'Auto-scan test build failed'}
    & $binary
    if($LASTEXITCODE -ne 0){throw 'Auto-scan tests failed'}
}finally{if(Test-Path -LiteralPath $binary){Remove-Item -LiteralPath $binary}}
