$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$app = Join-Path $PSScriptRoot 'tests\SafeDetach.exe'
$runner = Join-Path $PSScriptRoot 'tests\Recognition.exe'
try {
    $sources = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter '*.cs' | ForEach-Object FullName
    & $compiler /nologo /target:winexe /platform:x64 /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/out:$app" $sources
    if ($LASTEXITCODE -ne 0) {throw 'App compilation failed'}
    & $compiler /nologo /target:exe /platform:x64 /reference:System.Management.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/reference:$app" "/out:$runner" (Join-Path $PSScriptRoot 'tests\Recognition.cs')
    if ($LASTEXITCODE -ne 0) {throw 'Test compilation failed'}
    & $runner
    if ($LASTEXITCODE -ne 0) {throw 'Recognition tests failed'}
} finally {
    foreach ($temporaryFile in @($app,$runner)) {if (Test-Path -LiteralPath $temporaryFile) {Remove-Item -LiteralPath $temporaryFile}}
}
