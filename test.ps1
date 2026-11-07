$ErrorActionPreference = 'Stop'
$testBinary = Join-Path $PSScriptRoot 'tests\Integration.exe'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
try {
    & $compiler /nologo /target:exe /platform:x64 /reference:System.Management.dll "/out:$testBinary" (Join-Path $PSScriptRoot 'tests\Integration.cs') (Join-Path $PSScriptRoot 'src\HandleScanner.cs') (Join-Path $PSScriptRoot 'src\PortableProtocol.cs') (Join-Path $PSScriptRoot 'src\ProcessActions.cs') (Join-Path $PSScriptRoot 'src\EjectWorkflow.cs') (Join-Path $PSScriptRoot 'src\Devices.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
    & $testBinary
    if ($LASTEXITCODE -ne 0) { throw 'Integration tests failed' }
} finally {
    if (Test-Path -LiteralPath $testBinary) { Remove-Item -LiteralPath $testBinary }
}

